//! Windows AppContainer backend (T-007b, FR-007, SPEC-007).
//!
//! Every mandatory control is enforced with Win32 calls in this module and
//! `ffi.rs` rather than through `sandboxrs-windows`, because that crate's only
//! safe entry points either need a broad baseline ACL on system directories or
//! run their own unsandboxed launch probe. `docs/sandbox-windows.md` records
//! which APIs of the pinned dependency were examined and rejected, with source
//! citations, for the coordinator's dependency decision.
//!
//! Guarantees this module supplies and tests (see
//! `crates/fail2commit/tests/sandbox_windows_*.rs`):
//!
//! * Grants are anchored on a fail2commit-owned stage root below the trusted
//!   per-user directory, resolved from operating-system facts rather than the
//!   process environment.
//! * Nothing is granted until a handle-based walk has rejected reparse points,
//!   multi-link files and objects whose final path leaves that stage root, and
//!   every ACL write goes through the already-inspected handle.
//! * The loopback-exemption control is read from the OS configuration without
//!   launching any process, and blocks until the fresh package SID is proven
//!   absent.
//! * Timeouts, termination and cleanup are deadline-bounded and their results
//!   are checked, so a run never reports success while package code lives and a
//!   failed ACL cleanup is recorded, logged and refused by the next operation.

mod ffi;

use crate::isolation::{JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend};
use crate::paths::TrustedPaths;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::PSID;

const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
const FILE_MODIFY: u32 = 0x0013_01BF;
const POLL_MS: u32 = 25;

/// A positive probe verdict is reused for at most this long, and only for an
/// identical environment fingerprint. Nothing is cached across processes and a
/// negative verdict is never cached (S7B-005).
const PROBE_TTL: Duration = Duration::from_secs(30);
/// Upper bound on every post-run wait once the tree has been terminated.
const CLEANUP_GRACE: Duration = Duration::from_secs(10);
/// The probe's single sandboxed launch is killed by this timeout, which is how
/// the timeout control is measured on every probe. It is deliberately generous:
/// the child writes its markers first and only then floods output and spins, and
/// a cold AppContainer profile can take a second to materialise under load.
const PROBE_TIMEOUT: Duration = Duration::from_millis(4_000);
const PROBE_OUTPUT_BYTES: u64 = 4 * 1024;
const PROBE_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const PROBE_PROCESSES: u32 = 4;
const PROBE_NOISE_LINES: u32 = 4_000;

/// First-level directory, below `TrustedPaths::cache_dir`, that holds every job
/// stage. The stager contract is documented in `docs/sandbox-windows.md`.
const STAGE_DIR: &str = "sandbox-stage";
/// State file naming ACL revocations that failed, so the next operation refuses
/// while a package SID is still named in a staged DACL (S7B-006).
const REVOKE_STATE_FILE: &str = "pending-revoke.json";
/// Prefix of the tray approval pipe (`fail2commit-approval-<SID>`).
const APPROVAL_PIPE: &str = "fail2commit-approval-";
/// Deny entries the approval pipe must carry for the two app-package groups.
/// Mirrors the SDDL documented for `crates/fail2commit-core/src/ipc/winsec.rs`
/// on the wave-1 branch; that module belongs to another worker and is not
/// imported here.
const APPROVAL_PIPE_DENY_SDDL: &str = "D:P(D;;GA;;;S-1-15-2-1)(D;;GA;;;S-1-15-2-2)";

#[derive(Default)]
pub struct AppContainer;

impl SandboxBackend for AppContainer {
    fn probe(&self) -> ProbeReport {
        probe_cached()
    }

    fn run(&self, job: &JobSpec) -> crate::Result<JobOutcome> {
        let report = self.probe();
        if !report.available {
            return Err(crate::Error::isolation_unavailable(format!(
                "AppContainer controls are unavailable: {}",
                report.detail
            )));
        }
        run_unprobed(job)
    }
}

fn mandatory_controls() -> Vec<(String, bool)> {
    [
        "appcontainer-zero-capabilities",
        "no-loopback-exemption",
        "staged-restrictive-acls",
        "explicit-stdio-handle-list",
        "approval-ipc-denied",
        "job-tree-and-resource-limits",
        "timeout-kills-job",
        "bounded-concurrent-output",
        "clean-environment",
    ]
    .into_iter()
    .map(|name| (name.to_string(), false))
    .collect()
}

fn mark(controls: &mut [(String, bool)], name: &str) {
    if let Some((_, ok)) = controls.iter_mut().find(|(n, _)| n == name) {
        *ok = true;
    }
}

fn failure_report(error: crate::Error) -> ProbeReport {
    ProbeReport {
        backend: "appcontainer",
        available: false,
        detail: error.message,
        controls: mandatory_controls(),
    }
}
struct CachedProbe {
    key: String,
    at: Instant,
    report: ProbeReport,
}

static PROBE_CACHE: Mutex<Option<CachedProbe>> = Mutex::new(None);

/// Everything a control verdict depends on. A change invalidates the entry, so
/// a caller-controlled `SystemRoot`, a moved stage root or new probe limits can
/// never reuse an older "available" answer.
fn probe_key() -> crate::Result<String> {
    let system32 = ffi::system_directory()?;
    let windows = ffi::windows_directory()?;
    let stage_root = stage_root()?;
    let env_root = std::env::var_os("SystemRoot").unwrap_or_default();
    Ok(format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        system32.display(),
        windows.display(),
        stage_root.display(),
        PathBuf::from(&env_root).display(),
        PROBE_TIMEOUT.as_millis(),
        PROBE_OUTPUT_BYTES,
        PROBE_MEMORY_BYTES,
        PROBE_PROCESSES
    ))
}

fn probe_cached() -> ProbeReport {
    let key = match probe_key() {
        Ok(key) => key,
        Err(error) => return failure_report(error),
    };
    {
        let cached = PROBE_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cached.as_ref() {
            if entry.key == key && entry.report.available && entry.at.elapsed() < PROBE_TTL {
                return entry.report.clone();
            }
        }
    }
    let report = probe_host();
    let mut cached = PROBE_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *cached = report.available.then(|| CachedProbe {
        key,
        at: Instant::now(),
        report: report.clone(),
    });
    report
}

fn probe_host() -> ProbeReport {
    let mut controls = mandatory_controls();
    let started = Instant::now();
    let result = probe_host_inner(&mut controls);
    let available = result.is_ok() && controls.iter().all(|(_, ok)| *ok);
    ProbeReport {
        backend: "appcontainer",
        available,
        detail: match result {
            Ok(()) => format!(
                "all mandatory AppContainer controls verified in one sandboxed launch \
                 ({} ms); loopback exemptions read from FirewallAPI; LPAC is not enabled or claimed",
                started.elapsed().as_millis()
            ),
            Err(error) => error.message,
        },
        controls,
    }
}
/// One sandboxed launch proves every control that needs a live container, and
/// no unsandboxed process is ever started (S7B-013). The child reports through
/// a file in its writable stage rather than through bounded stdout, so the
/// marker checks cannot race the output-budget truncation.
fn probe_host_inner(controls: &mut [(String, bool)]) -> crate::Result<()> {
    let stage_root = stage_root()?;
    let system32 = ffi::system_directory()?;
    let cmd_source = system32.join("cmd.exe");
    if !cmd_source.is_file() {
        return Err(crate::Error::isolation_unavailable(format!(
            "the operating system's System32 does not contain cmd.exe: {}",
            cmd_source.display()
        )));
    }
    let stage = tempfile::Builder::new()
        .prefix("probe-")
        .tempdir_in(&stage_root)
        .map_err(|e| {
            crate::Error::isolation_unavailable(format!(
                "create probe stage below {}: {e}",
                stage_root.display()
            ))
        })?;
    let read_only = stage.path().join("read-only");
    let work = stage.path().join("work");
    fs::create_dir_all(&read_only)?;
    fs::create_dir_all(&work)?;
    let cmd = read_only.join("probe-cmd.exe");
    fs::copy(&cmd_source, &cmd).map_err(|e| {
        crate::Error::isolation_unavailable(format!("stage trusted probe executable: {e}"))
    })?;

    let nonce = hex::encode(random_bytes_16()?);
    let user = ffi::current_user_sid()?;
    // Same DACL shape as the tray approval pipe, with a probe suffix so a live
    // tray pipe can never collide with the measurement.
    let approval_name = format!(r"\\.\pipe\{APPROVAL_PIPE}{user}-probe-{nonce}");
    let default_name = format!(r"\\.\pipe\fail2commit-probe-default-{nonce}");
    let sddl = format!("{APPROVAL_PIPE_DENY_SDDL}(A;;GA;;;SY)(A;;GA;;;{user})");
    let approval = ffi::listening_pipe(&approval_name, Some(&sddl))?;
    let default_pipe = ffi::listening_pipe(&default_name, None)?;

    let command = probe_command(&approval_name, &default_name);
    let result_file = work.join("probe-result.txt");

    let job = JobSpec {
        program: cmd,
        args: vec!["/d".into(), "/c".into(), command.into()],
        cwd: work.clone(),
        env: vec![("F2C_PROBE".into(), "yes".into())],
        read_only: vec![read_only],
        work_dir: work,
        exports: Vec::new(),
        export_to: None,
        limits: probe_limits(),
    };
    let outcome = run_unprobed(&job)?;
    if outcome.status != JobStatus::TimedOut {
        return Err(crate::Error::isolation_unavailable(format!(
            "the probe job did not end at its timeout: {:?}; stdout={:?} stderr={:?} markers={:?}",
            outcome.status,
            String::from_utf8_lossy(&outcome.stdout),
            String::from_utf8_lossy(&outcome.stderr),
            fs::read_to_string(&result_file).unwrap_or_default()
        )));
    }
    let markers = fs::read_to_string(&result_file).unwrap_or_default();
    if !outcome.truncated {
        return Err(crate::Error::isolation_unavailable(format!(
            "the probe job did not report truncated output; stdout={} stderr={} markers={markers:?}",
            outcome.stdout.len(),
            outcome.stderr.len()
        )));
    }
    if outcome.stdout.len() + outcome.stderr.len() > PROBE_OUTPUT_BYTES as usize {
        return Err(crate::Error::isolation_unavailable(format!(
            "the probe job exceeded its output budget; markers={markers:?}"
        )));
    }
    if ffi::pipe_has_client(&approval) || ffi::pipe_has_client(&default_pipe) {
        return Err(crate::Error::isolation_unavailable(
            "the sandbox child reached an approval pipe",
        ));
    }
    for expected in [
        "PATH-ABSENT",
        "ENV=yes",
        "APPROVAL-DENIED",
        "DEFAULT-DENIED",
        "READY",
    ] {
        if !markers.contains(expected) {
            return Err(crate::Error::isolation_unavailable(format!(
                "the probe child did not report {expected}; it wrote {markers:?}"
            )));
        }
    }
    // The child's LOCALAPPDATA must be based inside its own work directory,
    // never on the real user profile (S7B-008). Windows appends the container's
    // package folder to the base value.
    let expected_local_app_data = plain_path(stage.path()).join("work").join("localappdata");
    let reported_local_app_data = markers
        .lines()
        .find_map(|line| line.strip_prefix("LAD="))
        .unwrap_or_default();
    if !reported_local_app_data.starts_with(&expected_local_app_data.to_string_lossy().into_owned())
    {
        return Err(crate::Error::isolation_unavailable(format!(
            "the probe child's LOCALAPPDATA was not scoped to its work directory ({}); it wrote \
             {markers:?}",
            expected_local_app_data.display()
        )));
    }
    for refused in ["PATH-LEAK", "APPROVAL-OPEN", "DEFAULT-OPEN"] {
        if markers.contains(refused) {
            return Err(crate::Error::isolation_unavailable(format!(
                "the probe child reported {refused}"
            )));
        }
    }
    for name in [
        "appcontainer-zero-capabilities",
        "no-loopback-exemption",
        "staged-restrictive-acls",
        "explicit-stdio-handle-list",
        "approval-ipc-denied",
        "job-tree-and-resource-limits",
        "timeout-kills-job",
        "bounded-concurrent-output",
        "clean-environment",
    ] {
        mark(controls, name);
    }
    Ok(())
}

fn probe_limits() -> crate::isolation::JobLimits {
    crate::isolation::JobLimits {
        timeout: PROBE_TIMEOUT,
        memory_bytes: Some(PROBE_MEMORY_BYTES),
        max_processes: Some(PROBE_PROCESSES),
        max_output_bytes: PROBE_OUTPUT_BYTES,
    }
}

/// The probe's single command line. It is deliberately unquoted: cmd.exe
/// re-parses its command line instead of using the MSVCRT rules, so a path with
/// a space or a stray backslash-quote would corrupt it. Every name used here is
/// either relative to the granted work directory or a pipe name without spaces.
///
/// The child writes its findings into `probe-result.txt` (which it can create
/// and read: measured on the verified host) rather than into stdout, so the
/// marker checks cannot race the output budget. It then floods stdout to
/// exercise the shared budget and finally spins forever so the timeout control
/// is measured by killing it.
fn probe_command(approval_pipe: &str, default_pipe: &str) -> String {
    let mut command = String::new();
    command.push_str(
        "(if defined PATH (echo PATH-LEAK>>probe-result.txt) else (echo PATH-ABSENT>>probe-result.txt)) & ",
    );
    command.push_str("echo ENV=%F2C_PROBE%>>probe-result.txt & ");
    for (pipe, label) in [(approval_pipe, "APPROVAL"), (default_pipe, "DEFAULT")] {
        command.push_str(&format!(
            "(>{pipe} echo probe) && (echo {label}-OPEN>>probe-result.txt) || (echo {label}-DENIED>>probe-result.txt) & "
        ));
    }
    command.push_str("echo READY>>probe-result.txt & ");
    command.push_str(&format!(
        "echo LAD=%LOCALAPPDATA%>>probe-result.txt & (for /L %i in (1,1,{PROBE_NOISE_LINES}) do @echo 0123456789abcdef) & "
    ));
    command.push_str("(for /L %i in (1,0,2) do @echo off)");
    command
}
/// Run one job. Every call repeats the environment-dependent checks (stage
/// root, grant read-back, loopback list, token, job limits, handle list) so a
/// cached probe verdict is never the only evidence for a launch (S7B-005).
fn run_unprobed(job: &JobSpec) -> crate::Result<JobOutcome> {
    let stage_root = stage_root()?;
    clear_pending_revokes(&stage_root)?;
    let paths = ValidatedPaths::new(job, &stage_root)?;
    let max_processes = job.limits.max_processes.filter(|n| *n > 0).ok_or_else(|| {
        crate::Error::isolation_unavailable("a positive process limit is required")
    })?;
    let memory_bytes = job.limits.memory_bytes.filter(|n| *n > 0).ok_or_else(|| {
        crate::Error::isolation_unavailable("a positive job memory limit is required")
    })?;
    if job.limits.timeout.is_zero() {
        return Err(crate::Error::isolation_unavailable(
            "a positive job timeout is required",
        ));
    }
    let output_cap = usize::try_from(job.limits.max_output_bytes)
        .map_err(|_| crate::Error::isolation_unavailable("output limit exceeds usize"))?;

    let profile = ffi::Profile::create_fresh()?;
    verify_no_loopback_exemption(&profile.sid_string)?;
    let mut grants = StagingGrants::new(profile.sid(), &stage_root);
    for root in &paths.read_only {
        grants.grant_tree(root, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, false)?;
    }
    grants.grant_tree(&paths.work_dir, FILE_MODIFY, true)?;

    let job_object = ffi::Job::new(max_processes, memory_bytes)?;
    job_object.verify(max_processes, memory_bytes)?;
    // `CreateProcessW`, `cmd.exe` and the loader do not accept the extended
    // `\\?\` form that canonicalization returns, so execution inputs use the
    // plain DOS form. Canonical verbatim paths are still what every containment
    // comparison and every ACL call uses.
    let program = plain_path(&paths.program);
    let cwd = plain_path(&paths.cwd);
    let work_dir = plain_path(&paths.work_dir);
    let env = environment_block(&job.env, &cwd, &work_dir)?;
    let mut command_line = command_line(&program, &job.args)?;

    let stdin = OpenOptions::new()
        .read(true)
        .open("NUL")
        .map_err(|e| crate::Error::isolation_unavailable(format!("open NUL stdin: {e}")))?;
    let (stdout_read, stdout_write) = ffi::pipe()?;
    let (stderr_read, stderr_write) = ffi::pipe()?;
    let stdio = [
        stdin.as_raw_handle() as HANDLE,
        stdout_write.as_raw_handle() as HANDLE,
        stderr_write.as_raw_handle() as HANDLE,
    ];
    let mut canary = HandleCanary::create(&paths.stage)?;
    let spawned = ffi::spawn_suspended(
        &program,
        &mut command_line,
        &env,
        &cwd,
        profile.sid(),
        stdio,
    )?;
    let facts = ffi::token_facts(&spawned.process, profile.sid())
        .map_err(|error| abort_with(&spawned, error))?;
    if !facts.is_appcontainer || !facts.sid_matches || facts.capability_count != 0 {
        return Err(abort_with(
            &spawned,
            crate::Error::isolation_unavailable(
                "child token did not verify as the fresh zero-capability AppContainer",
            ),
        ));
    }
    // The reviewed dependency configuration does not request LPAC. Observing
    // LPAC would mean the launch policy changed unexpectedly.
    if facts.is_lpac {
        return Err(abort_with(
            &spawned,
            crate::Error::isolation_unavailable(
                "unexpected LPAC token; dependency configuration changed",
            ),
        ));
    }
    job_object
        .assign(&spawned.process)
        .map_err(|error| abort_with(&spawned, error))?;
    // The child exists but is still suspended, so an inherited handle is
    // observable here: after closing our own copy, an exclusive open must
    // succeed (S7B-005, S7B-012).
    canary
        .verify_after_spawn()
        .map_err(|error| abort_with(&spawned, error))?;
    spawned
        .resume()
        .map_err(|error| abort_with(&spawned, error))?;
    drop(stdout_write);
    drop(stderr_write);
    drop(stdin);

    let budget = Arc::new(Mutex::new(OutputBudget {
        remaining: output_cap,
        truncated: false,
    }));
    let (stdout_thread, stdout_rx) = drain(stdout_read, Arc::clone(&budget));
    let (stderr_thread, stderr_rx) = drain(stderr_read, Arc::clone(&budget));
    let deadline = Instant::now() + job.limits.timeout;
    let status = wait_for_tree(&job_object, deadline)?;
    let status = match status {
        Some(status) => status,
        None => JobStatus::Exited(spawned.exit_code()? as i32),
    };
    let drain_deadline = Instant::now() + CLEANUP_GRACE;
    let stdout = collect_drain(stdout_rx, drain_deadline, "stdout")?;
    let stderr = collect_drain(stderr_rx, drain_deadline, "stderr")?;
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
    let truncated = budget.lock().unwrap_or_else(|e| e.into_inner()).truncated;
    // Cleanup is part of the operation: a failed revoke is recorded, logged and
    // returned, so the next probe()/run() refuses while it is outstanding.
    grants.release()?;
    Ok(JobOutcome {
        status,
        stdout,
        stderr,
        truncated,
        exported: Vec::new(),
    })
}

/// Kill a suspended or failed root process, keeping the original error and
/// appending the kill failure when that also fails.
fn abort_with(spawned: &ffi::Spawned, error: crate::Error) -> crate::Error {
    match spawned.kill() {
        Ok(()) => error,
        Err(kill) => crate::Error::isolation_unavailable(format!(
            "{}; terminating the suspended root process also failed: {}",
            error.message, kill.message
        )),
    }
}
/// Wait for the job to stop. `Ok(Some(status))` reports a status this function
/// decided (timed out or resource-killed); `Ok(None)` means the tree emptied on
/// its own and the caller reads the root exit code. A tree that survives the
/// deadline plus the grace period is an error, never a success (S7B-004).
fn wait_for_tree(job_object: &ffi::Job, deadline: Instant) -> crate::Result<Option<JobStatus>> {
    let mut decided = None;
    while Instant::now() < deadline {
        if let Some(message) = job_object.next_message(POLL_MS) {
            if message == ffi::MSG_ACTIVE_PROCESS_LIMIT || message == ffi::MSG_JOB_MEMORY_LIMIT {
                job_object.terminate().map_err(|error| {
                    crate::Error::isolation_unavailable(format!(
                        "the sandbox hit a job limit but TerminateJobObject failed: {}",
                        error.message
                    ))
                })?;
                decided = Some(JobStatus::Killed);
                break;
            }
            if message == ffi::MSG_ACTIVE_PROCESS_ZERO {
                break;
            }
        }
        if job_object.active_processes()? == 0 {
            break;
        }
    }
    if decided.is_none() && job_object.active_processes()? != 0 {
        job_object.terminate().map_err(|error| {
            crate::Error::isolation_unavailable(format!(
                "the sandbox job outlived its deadline and TerminateJobObject failed: {}",
                error.message
            ))
        })?;
        decided = Some(JobStatus::TimedOut);
    }
    job_object.wait_empty(Instant::now() + CLEANUP_GRACE)?;
    if job_object.active_processes()? != 0 {
        return Err(crate::Error::isolation_unavailable(
            "sandbox processes are still alive after termination; refusing to report success",
        ));
    }
    Ok(decided)
}

struct ValidatedPaths {
    program: PathBuf,
    cwd: PathBuf,
    read_only: Vec<PathBuf>,
    work_dir: PathBuf,
    /// The one job stage directory below the fail2commit stage root.
    stage: PathBuf,
}

impl ValidatedPaths {
    fn new(job: &JobSpec, stage_root: &Path) -> crate::Result<Self> {
        let work_dir = canonical_dir(&job.work_dir, "work_dir")?;
        let cwd = canonical_dir(&job.cwd, "cwd")?;
        let program = canonical_file(&job.program, "program")?;
        let read_only = job
            .read_only
            .iter()
            .map(|p| canonical_existing(p, "read_only"))
            .collect::<crate::Result<Vec<_>>>()?;
        if read_only.is_empty() {
            return Err(crate::Error::isolation_unavailable(
                "at least one staged read-only root is required",
            ));
        }
        if !path_under(&cwd, &work_dir) {
            return Err(crate::Error::isolation_unavailable(
                "cwd is outside the writable work_dir",
            ));
        }
        if !read_only.iter().any(|p| path_under(&program, p)) {
            return Err(crate::Error::isolation_unavailable(
                "program is outside staged read_only roots",
            ));
        }
        if read_only
            .iter()
            .any(|p| path_under(p, &work_dir) || path_under(&work_dir, p))
        {
            return Err(crate::Error::isolation_unavailable(
                "read_only and work_dir must not overlap",
            ));
        }
        // The anchor is a fail2commit-owned directory below the trusted per-user
        // state, never `std::env::temp_dir()` or any other caller-controlled
        // value (S7B-003).
        if !path_under(&work_dir, stage_root) {
            return Err(crate::Error::isolation_unavailable(format!(
                "work_dir {} is outside the fail2commit sandbox stage root {}",
                work_dir.display(),
                stage_root.display()
            )));
        }
        let stage = first_child_under(stage_root, &work_dir).ok_or_else(|| {
            crate::Error::isolation_unavailable(format!(
                "work_dir {} must be inside a job stage below {}",
                work_dir.display(),
                stage_root.display()
            ))
        })?;
        if same_path(&stage, stage_root) {
            return Err(crate::Error::isolation_unavailable(
                "work_dir must be inside a job stage, not the stage root itself",
            ));
        }
        if !read_only.iter().all(|p| path_under(p, &stage)) {
            return Err(crate::Error::isolation_unavailable(
                "all granted paths must share one fail2commit job stage",
            ));
        }
        reject_unsafe_grant(&stage)?;
        // Nothing is granted until every staged object has been inspected
        // through its own handle: no reparse points, no multi-link files, and no
        // final path outside the stage root (S7B-001).
        walk_stage(&stage, stage_root, |_| Ok(()))?;
        Ok(Self {
            program,
            cwd,
            read_only,
            work_dir,
            stage,
        })
    }
}
fn canonical_existing(path: &Path, label: &str) -> crate::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(crate::Error::isolation_unavailable(format!(
            "{label} must be absolute"
        )));
    }
    path.canonicalize().map_err(|e| {
        crate::Error::isolation_unavailable(format!("canonicalize {label} {}: {e}", path.display()))
    })
}

fn canonical_dir(path: &Path, label: &str) -> crate::Result<PathBuf> {
    let p = canonical_existing(path, label)?;
    if !p.is_dir() {
        return Err(crate::Error::isolation_unavailable(format!(
            "{label} is not a directory"
        )));
    }
    Ok(p)
}

fn canonical_file(path: &Path, label: &str) -> crate::Result<PathBuf> {
    let p = canonical_existing(path, label)?;
    if !p.is_file() {
        return Err(crate::Error::isolation_unavailable(format!(
            "{label} is not a file"
        )));
    }
    Ok(p)
}

/// The plain DOS form of a canonical path: the extended `\\?\` prefix removed,
/// and `\\?\UNC\server` restored to `\\server`.
fn plain_path(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) => match rest.strip_prefix("UNC\\") {
            Some(unc) => PathBuf::from(format!(r"\\{unc}")),
            None => PathBuf::from(rest),
        },
        None => path.to_path_buf(),
    }
}

fn first_child_under(parent: &Path, path: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(parent).ok()?;
    let first = relative.components().next()?;
    Some(parent.join(first.as_os_str()))
}

fn component_eq(left: Component<'_>, right: Component<'_>) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .to_lowercase()
        .eq(&right.as_os_str().to_string_lossy().to_lowercase())
}

/// Component-wise, case-insensitive prefix test on canonical paths. Windows
/// paths are case-insensitive, and every path compared here has already been
/// canonicalized, so a plain `starts_with` would be either too strict or unsafe.
fn path_under(child: &Path, parent: &Path) -> bool {
    let child_count = child.components().count();
    let parent_count = parent.components().count();
    child_count >= parent_count
        && child
            .components()
            .zip(parent.components())
            .all(|(a, b)| component_eq(a, b))
}

fn same_path(left: &Path, right: &Path) -> bool {
    path_under(left, right) && path_under(right, left)
}

/// The fail2commit-owned stage root: `<trusted cache dir>/sandbox-stage`.
///
/// The cache directory comes from `TrustedPaths` (LOCALAPPDATA for a normal
/// installation), and the OS-known local app data directory is used to refuse
/// anything that is not really below it. `FAIL2COMMIT_HOME` relocates the whole
/// trusted directory set, which is the documented mechanism for disposable test
/// homes (`crate::paths`), and is honoured here for the same reason.
fn stage_root() -> crate::Result<PathBuf> {
    let paths = TrustedPaths::resolve().map_err(|error| {
        crate::Error::isolation_unavailable(format!(
            "the trusted per-user state directory is unavailable: {}",
            error.message
        ))
    })?;
    let candidate = paths.cache_dir.join(STAGE_DIR);
    crate::fsutil::ensure_private_dir(&candidate).map_err(|error| {
        crate::Error::isolation_unavailable(format!(
            "create the sandbox stage root {}: {}",
            candidate.display(),
            error.message
        ))
    })?;
    let root = candidate.canonicalize().map_err(|e| {
        crate::Error::isolation_unavailable(format!(
            "canonicalize the sandbox stage root {}: {e}",
            candidate.display()
        ))
    })?;
    reject_unsafe_anchor(&root)?;
    Ok(root)
}

/// Refuse an anchor that is a volume root, the user profile (or an ancestor of
/// it), or the local app data directory itself. Grants are only ever written
/// below the returned root, which is what makes "never on the user profile"
/// structural rather than a promise (S7B-003).
fn reject_unsafe_anchor(root: &Path) -> crate::Result<()> {
    let profile = ffi::known_user_profile()?
        .canonicalize()
        .map_err(|e| crate::Error::isolation_unavailable(format!("canonicalize profile: {e}")))?;
    let local = ffi::known_local_app_data()?.canonicalize().map_err(|e| {
        crate::Error::isolation_unavailable(format!("canonicalize LOCALAPPDATA: {e}"))
    })?;
    reject_unsafe_grant(root)?;
    if same_path(root, &local) || path_under(&local, root) {
        return Err(crate::Error::isolation_unavailable(format!(
            "the sandbox stage root {} must be below the local app data directory {}",
            root.display(),
            local.display()
        )));
    }
    let relocated = std::env::var_os("FAIL2COMMIT_HOME").is_some_and(|value| !value.is_empty());
    if !relocated && !path_under(root, &local) {
        return Err(crate::Error::isolation_unavailable(format!(
            "the sandbox stage root {} is not below the OS local app data directory {}",
            root.display(),
            local.display()
        )));
    }
    if same_path(root, &profile) {
        return Err(crate::Error::isolation_unavailable(
            "the sandbox stage root must not be the user profile",
        ));
    }
    Ok(())
}

/// Refuse to grant on the user profile, on an ancestor of it, or on a volume
/// root. Bypass-traverse makes an ancestor grant pointless and dangerous.
fn reject_unsafe_grant(path: &Path) -> crate::Result<()> {
    let profile = ffi::known_user_profile()?
        .canonicalize()
        .map_err(|e| crate::Error::isolation_unavailable(format!("canonicalize profile: {e}")))?;
    if same_path(path, &profile) || path_under(&profile, path) {
        return Err(crate::Error::isolation_unavailable(format!(
            "refusing to grant on the user profile or an ancestor of it: {}",
            path.display()
        )));
    }
    if path.parent().is_none() {
        return Err(crate::Error::isolation_unavailable(format!(
            "refusing to grant on a volume root: {}",
            path.display()
        )));
    }
    Ok(())
}
/// Walk every staged object below `root` through its own handle.
fn walk_stage(
    root: &Path,
    stage_root: &Path,
    mut visit: impl FnMut(&ffi::StagedObject) -> crate::Result<()>,
) -> crate::Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let object = ffi::StagedObject::open(&path).map_err(|error| {
            crate::Error::isolation_unavailable(format!(
                "inspect staged path {}: {}",
                path.display(),
                error.message
            ))
        })?;
        require_plain(&object, stage_root)?;
        visit(&object)?;
        if object.is_dir() {
            for entry in fs::read_dir(&path).map_err(|e| {
                crate::Error::isolation_unavailable(format!(
                    "list staged directory {}: {e}",
                    path.display()
                ))
            })? {
                pending.push(entry?.path());
            }
        }
    }
    Ok(())
}

/// Reject anything whose access would not be confined to the stage: a reparse
/// point (a followed link escapes), a file with more than one directory entry
/// (a hard link shares the file object, and therefore its DACL, with a path
/// outside the stage), and an object whose final path leaves the stage root.
fn require_plain(object: &ffi::StagedObject, stage_root: &Path) -> crate::Result<()> {
    if object.is_reparse_point() {
        return Err(crate::Error::isolation_unavailable(format!(
            "staged path is a reparse point: {}",
            object.path().display()
        )));
    }
    if !object.is_dir() && object.link_count() != 1 {
        return Err(crate::Error::isolation_unavailable(format!(
            "staged file has {} hard links, so it is shared with a path outside the stage \
             and cannot be granted: {}",
            object.link_count(),
            object.path().display()
        )));
    }
    let final_path = object.final_path()?;
    if !path_under(&final_path, stage_root) {
        return Err(crate::Error::isolation_unavailable(format!(
            "staged path resolves outside the sandbox stage root: {} -> {}",
            object.path().display(),
            final_path.display()
        )));
    }
    Ok(())
}
struct StagingGrants<'a> {
    sid: PSID,
    stage_root: &'a Path,
    granted: Vec<PathBuf>,
}

impl<'a> StagingGrants<'a> {
    fn new(sid: PSID, stage_root: &'a Path) -> Self {
        Self {
            sid,
            stage_root,
            granted: Vec::new(),
        }
    }

    /// Grant `mask` on `root` and every descendant, re-inspecting each object
    /// through the same handle that receives the ACE (S7B-001).
    fn grant_tree(&mut self, root: &Path, mask: u32, writable: bool) -> crate::Result<()> {
        let mut paths = Vec::new();
        walk_stage(root, self.stage_root, |object| {
            paths.push(object.path().to_path_buf());
            Ok(())
        })?;
        for path in paths {
            let object = ffi::StagedObject::open(&path)?;
            require_plain(&object, self.stage_root)?;
            object.grant(self.sid, mask)?;
            self.granted.push(path.clone());
            let actual = object.allowed_mask(self.sid)?;
            let forbidden = if writable {
                actual & !FILE_MODIFY
            } else {
                actual & !(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
            };
            if actual & mask != mask || forbidden != 0 {
                return Err(crate::Error::isolation_unavailable(format!(
                    "staging ACL did not read back with the requested access: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Remove every grant, reporting what failed. Failures are logged, written
    /// to the stage state file and returned, so the caller fails the operation
    /// and the next `probe()`/`run()` refuses until they are cleared (S7B-006).
    fn release(&mut self) -> crate::Result<()> {
        let granted = std::mem::take(&mut self.granted);
        let mut failures = Vec::new();
        for path in granted.iter().rev() {
            if fs::symlink_metadata(path).is_err() {
                // The staged object is already gone: no ACE can remain on it.
                continue;
            }
            let result = ffi::StagedObject::open(path)
                .and_then(|object| require_plain(&object, self.stage_root).map(|()| object))
                .and_then(|object| object.revoke(self.sid));
            if let Err(error) = result {
                failures.push((path.clone(), error.message));
            }
        }
        if failures.is_empty() {
            return Ok(());
        }
        for (path, message) in &failures {
            eprintln!(
                "fail2commit: sandbox staging ACL cleanup failed for {}: {}",
                path.display(),
                message
            );
        }
        let sid = ffi::sid_text(self.sid)?;
        record_pending_revokes(self.stage_root, &failures, &sid)?;
        Err(crate::Error::isolation_unavailable(format!(
            "{} staged ACL revocation(s) failed; recorded in {} and the next sandbox operation \
             will refuse until they are cleared",
            failures.len(),
            self.stage_root.join(REVOKE_STATE_FILE).display()
        )))
    }
}

impl Drop for StagingGrants<'_> {
    fn drop(&mut self) {
        if !self.granted.is_empty() {
            let _ = self.release();
        }
    }
}
/// A canary for the explicit stdio handle list. The parent opens a file with
/// `bInheritHandle` set, closes its own handle once the child has been created,
/// and then requires an exclusive open to succeed. If the child inherited the
/// handle, the file object is still open and the exclusive open fails, which is
/// a direct measurement rather than an inference (S7B-005, S7B-012).
struct HandleCanary {
    path: PathBuf,
    handle: Option<OwnedHandle>,
}

impl HandleCanary {
    fn create(stage: &Path) -> crate::Result<Self> {
        let path = stage.join("handle-canary.dat");
        fs::write(&path, b"fail2commit handle canary").map_err(|e| {
            crate::Error::isolation_unavailable(format!(
                "write the handle canary {}: {e}",
                path.display()
            ))
        })?;
        let handle = ffi::open_inheritable(&path)?;
        Ok(Self {
            path,
            handle: Some(handle),
        })
    }

    fn verify_after_spawn(&mut self) -> crate::Result<()> {
        self.handle.take();
        if ffi::exclusive_open_succeeds(&self.path)? {
            return Ok(());
        }
        Err(crate::Error::isolation_unavailable(
            "the sandbox child inherited a handle outside the explicit stdio handle list",
        ))
    }
}

impl Drop for HandleCanary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct PendingRevoke {
    path: String,
    sid: String,
    detail: String,
}

fn revoke_state_file(stage_root: &Path) -> PathBuf {
    stage_root.join(REVOKE_STATE_FILE)
}

fn record_pending_revokes(
    stage_root: &Path,
    failures: &[(PathBuf, String)],
    sid: &str,
) -> crate::Result<()> {
    let file = revoke_state_file(stage_root);
    crate::fsutil::with_lock(&file, || {
        let mut entries = read_pending_revokes(stage_root)?;
        for (path, detail) in failures {
            let path = path.to_string_lossy().into_owned();
            if !entries
                .iter()
                .any(|entry| entry.path == path && entry.sid == sid)
            {
                entries.push(PendingRevoke {
                    path,
                    sid: sid.to_string(),
                    detail: detail.clone(),
                });
            }
        }
        write_pending_revokes(stage_root, &entries)
    })
}

fn read_pending_revokes(stage_root: &Path) -> crate::Result<Vec<PendingRevoke>> {
    let file = revoke_state_file(stage_root);
    if !file.exists() {
        return Ok(Vec::new());
    }
    let bytes = crate::fsutil::read_bounded(&file, 256 * 1024)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&bytes).map_err(|e| {
        crate::Error::isolation_unavailable(format!(
            "the sandbox ACL cleanup state {} is unreadable: {e}",
            file.display()
        ))
    })
}

fn write_pending_revokes(stage_root: &Path, entries: &[PendingRevoke]) -> crate::Result<()> {
    let file = revoke_state_file(stage_root);
    if entries.is_empty() {
        match fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(crate::Error::internal(format!(
                "removing {} failed: {e}",
                file.display()
            ))),
        }
    } else {
        let json = serde_json::to_vec_pretty(entries)
            .map_err(|e| crate::Error::internal(format!("serialize pending revokes: {e}")))?;
        crate::fsutil::atomic_write(&file, &json)
    }
}

/// Retry outstanding revocations and refuse while any remain. Called by every
/// `probe()` and `run()` so a leaked ACE is never silently ignored (S7B-006).
fn clear_pending_revokes(stage_root: &Path) -> crate::Result<()> {
    let entries = read_pending_revokes(stage_root)?;
    if entries.is_empty() {
        return Ok(());
    }
    let file = revoke_state_file(stage_root);
    crate::fsutil::with_lock(&file, || {
        let remaining = read_pending_revokes(stage_root)?;
        let mut failed = Vec::new();
        for entry in &remaining {
            let path = PathBuf::from(&entry.path);
            if fs::symlink_metadata(&path).is_err() {
                continue;
            }
            let result = ffi::sid_from_string(&entry.sid).and_then(|sid| {
                ffi::StagedObject::open(&path)
                    .and_then(|object| require_plain(&object, stage_root).map(|()| object))
                    .and_then(|object| object.revoke(sid.as_psid()))
            });
            if let Err(error) = result {
                failed.push(PendingRevoke {
                    path: entry.path.clone(),
                    sid: entry.sid.clone(),
                    detail: error.message,
                });
            }
        }
        if failed.is_empty() {
            // Everything is cleared: drop the state file so the next operation
            // is not blocked by a stale record.
            return write_pending_revokes(stage_root, &[]);
        }
        write_pending_revokes(stage_root, &failed)?;
        Err(crate::Error::isolation_unavailable(format!(
            "{} sandbox staging ACL revocation(s) are still outstanding ({}); refusing to continue",
            failed.len(),
            file.display()
        )))
    })
}
/// Prove that the fresh package SID has no loopback exemption, using the
/// operating system's own exemption list. Nothing is launched, so no
/// environment value and no executable path can influence the verdict; any
/// uncertainty (missing export, failing call) is an error (S7B-002).
fn verify_no_loopback_exemption(sid: &str) -> crate::Result<()> {
    let exempt = ffi::loopback_exempt_sids()?;
    if exempt.iter().any(|entry| entry.eq_ignore_ascii_case(sid)) {
        return Err(crate::Error::isolation_unavailable(
            "fresh AppContainer unexpectedly has a loopback exemption",
        ));
    }
    Ok(())
}

/// Build the child environment from the job's allowlist plus the variables the
/// loader needs, all derived from OS facts.
///
/// * `SystemRoot` and `SystemDrive` come from `GetSystemWindowsDirectoryW`.
/// * `LOCALAPPDATA` is passed only when the caller points it inside the job's
///   own work directory; it is never copied from the parent environment
///   (S7B-008).
/// * Windows requires hidden per-drive current-directory entries in any
///   caller-supplied environment block.
fn environment_block(
    env: &[(OsString, OsString)],
    cwd: &Path,
    work_dir: &Path,
) -> crate::Result<Vec<u16>> {
    let mut vars: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
    for (key, value) in env {
        validate_env(key, value)?;
        let folded = key.to_string_lossy().to_uppercase();
        if vars.insert(folded, (key.clone(), value.clone())).is_some() {
            return Err(crate::Error::isolation_unavailable(
                "duplicate environment key (case-insensitive)",
            ));
        }
    }
    let system_root = required_windows_directory()?;
    let root = system_root.into_os_string();
    vars.insert("SYSTEMROOT".into(), ("SystemRoot".into(), root.clone()));
    if let Some(drive) = Path::new(&root).components().next() {
        let drive = drive.as_os_str().to_os_string();
        vars.insert("SYSTEMDRIVE".into(), ("SystemDrive".into(), drive));
    }
    vars.insert(
        "LOCALAPPDATA".into(),
        ("LOCALAPPDATA".into(), local_app_data(work_dir)),
    );
    let cwd_drive = cwd
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_uppercase());
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let root = PathBuf::from(format!(r"{drive}\"));
        if !root.is_dir() {
            continue;
        }
        let hidden_key = format!("={drive}");
        let value = if cwd_drive.as_deref() == Some(drive.as_str()) {
            cwd.as_os_str().to_os_string()
        } else {
            root.into_os_string()
        };
        vars.insert(hidden_key.clone(), (hidden_key.into(), value));
    }
    let mut block = Vec::new();
    for (_, (key, value)) in vars {
        block.extend(key.encode_wide());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    Ok(block)
}

/// The Windows directory from the OS, refusing when the process environment
/// claims a different one: an inconsistent parent environment must not decide
/// where system binaries or the child's `SystemRoot` come from (S7B-002).
fn required_windows_directory() -> crate::Result<PathBuf> {
    let os_value = ffi::windows_directory()?;
    if let Some(claimed) = std::env::var_os("SystemRoot") {
        let claimed = PathBuf::from(claimed);
        if !claimed.is_absolute() {
            return Err(crate::Error::isolation_unavailable(
                "the process SystemRoot is not absolute",
            ));
        }
        let canonical = claimed.canonicalize().map_err(|e| {
            crate::Error::isolation_unavailable(format!(
                "canonicalize the process SystemRoot {}: {e}",
                claimed.display()
            ))
        })?;
        let os_canonical = os_value.canonicalize().unwrap_or_else(|_| os_value.clone());
        if !same_path(&canonical, &os_canonical) {
            return Err(crate::Error::isolation_unavailable(format!(
                "the process SystemRoot {} disagrees with the operating system's Windows \
                 directory {}; refusing to build a sandbox environment from it",
                claimed.display(),
                os_value.display()
            )));
        }
    }
    Ok(os_value)
}

/// `LOCALAPPDATA` for the child.
///
/// An AppContainer launch needs the variable to exist — `CreateProcessW` fails
/// with Win32 error 203 without it on the verified host — but the parent's value
/// names the real user profile, which must not leak into package code (S7B-008).
/// The child therefore gets a path inside its own disposable work directory.
/// The caller's value is used only when the caller already points it inside that
/// work directory.
fn local_app_data(work_dir: &Path) -> OsString {
    if let Some(value) = std::env::var_os("LOCALAPPDATA") {
        let candidate = PathBuf::from(&value);
        if candidate.is_absolute() {
            if let (Ok(candidate), Ok(work)) = (candidate.canonicalize(), work_dir.canonicalize()) {
                if path_under(&candidate, &work) {
                    return value;
                }
            }
        }
    }
    work_dir.join("localappdata").into_os_string()
}
fn validate_env(key: &OsStr, value: &OsStr) -> crate::Result<()> {
    let key_w: Vec<u16> = key.encode_wide().collect();
    let value_w: Vec<u16> = value.encode_wide().collect();
    if key_w.is_empty()
        || key_w.contains(&0)
        || key_w.contains(&('=' as u16))
        || value_w.contains(&0)
    {
        return Err(crate::Error::isolation_unavailable(
            "invalid sandbox environment entry",
        ));
    }
    Ok(())
}

fn command_line(program: &Path, args: &[OsString]) -> crate::Result<Vec<u16>> {
    let mut all = Vec::with_capacity(args.len() + 1);
    all.push(program.as_os_str().to_os_string());
    all.extend_from_slice(args);
    let mut text = OsString::new();
    for (i, arg) in all.iter().enumerate() {
        if i != 0 {
            text.push(" ");
        }
        text.push(quote_windows_arg(arg)?);
    }
    let mut wide: Vec<u16> = text.encode_wide().collect();
    wide.push(0);
    Ok(wide)
}

fn quote_windows_arg(arg: &OsStr) -> crate::Result<OsString> {
    let units: Vec<u16> = arg.encode_wide().collect();
    if units.contains(&0) {
        return Err(crate::Error::isolation_unavailable(
            "sandbox argument contains NUL",
        ));
    }
    let needs_quotes = units.is_empty()
        || units
            .iter()
            .any(|c| *c == b' ' as u16 || *c == b'\t' as u16 || *c == b'"' as u16);
    if !needs_quotes {
        return Ok(arg.to_os_string());
    }
    let mut out = vec![b'"' as u16];
    let mut slashes = 0usize;
    for unit in units {
        if unit == b'\\' as u16 {
            slashes += 1;
        } else if unit == b'"' as u16 {
            out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2 + 1));
            out.push(unit);
            slashes = 0;
        } else {
            out.extend(std::iter::repeat_n(b'\\' as u16, slashes));
            out.push(unit);
            slashes = 0;
        }
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    out.push(b'"' as u16);
    Ok(OsString::from_wide(&out))
}

struct OutputBudget {
    remaining: usize,
    truncated: bool,
}

/// Drain one pipe on its own thread and report the result through a channel, so
/// the waiting side can bound the wait with a deadline (S7B-004).
fn drain(
    mut file: File,
    budget: Arc<Mutex<OutputBudget>>,
) -> (thread::JoinHandle<()>, Receiver<std::io::Result<Vec<u8>>>) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 8192];
        let result = loop {
            match file.read(&mut chunk) {
                Ok(0) => break Ok(kept),
                Ok(count) => {
                    let mut budget = budget.lock().unwrap_or_else(|e| e.into_inner());
                    let take = count.min(budget.remaining);
                    kept.extend_from_slice(&chunk[..take]);
                    budget.remaining -= take;
                    if take != count {
                        budget.truncated = true;
                    }
                }
                Err(error) => break Err(error),
            }
        };
        let _ = sender.send(result);
    });
    (handle, receiver)
}

/// Collect one drained stream, giving up at `deadline`. A timed-out drain is an
/// error rather than a silent success, even though the bytes are only logs.
fn collect_drain(
    receiver: Receiver<std::io::Result<Vec<u8>>>,
    deadline: Instant,
    label: &str,
) -> crate::Result<Vec<u8>> {
    let wait = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(wait) {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(e)) => Err(crate::Error::internal(format!(
            "sandbox {label} drain failed: {e}"
        ))),
        Err(RecvTimeoutError::Timeout) => Err(crate::Error::isolation_unavailable(format!(
            "the sandbox {label} drain did not finish before the cleanup deadline"
        ))),
        Err(RecvTimeoutError::Disconnected) => Err(crate::Error::internal(format!(
            "the sandbox {label} drain thread exited without a result"
        ))),
    }
}

fn random_bytes_16() -> crate::Result<[u8; 16]> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|e| crate::Error::isolation_unavailable(format!("random probe name: {e}")))?;
    Ok(nonce)
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A disposable job stage directly below the real fail2commit stage root,
    /// which is what the stager contract requires.
    fn test_stage(prefix: &str) -> tempfile::TempDir {
        let root = stage_root().expect("stage root");
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(&root)
            .expect("job stage")
    }

    fn stage_dirs(stage: &Path) -> (PathBuf, PathBuf) {
        let read_only = stage.join("read-only");
        let work = stage.join("work");
        fs::create_dir_all(&read_only).unwrap();
        fs::create_dir_all(&work).unwrap();
        (read_only, work)
    }

    fn copy_cmd(read_only: &Path) -> PathBuf {
        let program = read_only.join("cmd.exe");
        fs::copy(ffi::system_directory().unwrap().join("cmd.exe"), &program).unwrap();
        program
    }

    fn job(program: PathBuf, read_only: &Path, work: &Path) -> JobSpec {
        JobSpec {
            program,
            args: vec!["/d".into(), "/c".into(), "exit /b 0".into()],
            cwd: work.to_path_buf(),
            env: Vec::new(),
            read_only: vec![read_only.to_path_buf()],
            work_dir: work.to_path_buf(),
            exports: Vec::new(),
            export_to: None,
            limits: crate::isolation::JobLimits {
                timeout: Duration::from_secs(10),
                memory_bytes: Some(128 * 1024 * 1024),
                max_processes: Some(4),
                max_output_bytes: 16 * 1024,
            },
        }
    }

    #[test]
    fn host_probe_verifies_every_mandatory_control() {
        let report = AppContainer.probe();
        assert!(report.available, "{}: {:?}", report.detail, report.controls);
        assert!(report.controls.iter().all(|(_, verified)| *verified));
    }

    #[test]
    fn a_second_probe_reuses_a_short_lived_positive_verdict() {
        let first = Instant::now();
        let cold_report = AppContainer.probe();
        let cold = first.elapsed();
        let second = Instant::now();
        let warm_report = AppContainer.probe();
        let warm = second.elapsed();
        println!("cold probe {cold:?}, cached probe {warm:?}");
        assert!(
            cold_report.available && warm_report.available,
            "{}",
            cold_report.detail
        );
        assert!(cold < Duration::from_secs(30), "cold probe {cold:?}");
        assert!(warm < Duration::from_secs(5), "cached probe {warm:?}");
    }

    #[test]
    fn missing_mandatory_limit_fails_before_launch() {
        let stage = test_stage("no-launch-");
        let (read_only, work) = stage_dirs(stage.path());
        let program = copy_cmd(&read_only);
        let marker = work.join("must-not-exist.txt");
        let mut spec = job(program, &read_only, &work);
        spec.args = vec![
            "/d".into(),
            "/c".into(),
            format!("echo launched > \"{}\"", marker.display()).into(),
        ];
        spec.limits.max_processes = None;
        let error = run_unprobed(&spec).unwrap_err();
        assert_eq!(error.code, crate::ResultCode::IsolationUnavailable);
        assert!(
            !marker.exists(),
            "process launched despite a missing control"
        );
    }
    #[test]
    fn stale_revoke_state_blocks_the_next_operation_until_it_is_cleared() {
        let stage = tempfile::tempdir().unwrap();
        let file = revoke_state_file(stage.path());
        // A recorded failure that cannot be replayed (an unparsable SID) keeps the
        // operation refused, which is the fail-closed half of S7B-006.
        let staged = stage.path().join("staged-file.txt");
        fs::write(&staged, b"staged").unwrap();
        let record = format!(
            r#"[{{"path":{:?},"sid":"not-a-sid","detail":"test"}}]"#,
            staged.display().to_string()
        );
        fs::write(&file, record.as_bytes()).unwrap();
        let error = clear_pending_revokes(stage.path()).unwrap_err();
        assert_eq!(error.code, crate::ResultCode::IsolationUnavailable);
        assert!(
            error.message.contains("outstanding"),
            "unexpected error: {}",
            error.message
        );
        assert!(file.exists(), "the refusal must keep the record");

        // Once the stale record is gone the operation continues.
        fs::remove_file(&file).unwrap();
        clear_pending_revokes(stage.path()).unwrap();
    }

    #[test]
    fn a_recorded_revoke_failure_is_cleared_once_the_object_is_gone() {
        let stage = tempfile::tempdir().unwrap();
        let missing = stage.path().join("already-deleted.txt");
        record_pending_revokes(
            stage.path(),
            &[(missing, "simulated revoke failure".to_string())],
            "S-1-15-2-1",
        )
        .unwrap();
        let recorded = read_pending_revokes(stage.path()).unwrap();
        assert_eq!(recorded.len(), 1, "the failure was not recorded");
        // The staged object no longer exists, so there is no ACE left to remove and
        // the record is dropped instead of blocking forever.
        clear_pending_revokes(stage.path()).unwrap();
        assert!(read_pending_revokes(stage.path()).unwrap().is_empty());
        assert!(!revoke_state_file(stage.path()).exists());
    }

    #[test]
    fn a_hard_link_in_the_stage_is_rejected_before_any_grant() {
        let stage = test_stage("hard-link-");
        let (read_only, work) = stage_dirs(stage.path());
        let program = copy_cmd(&read_only);
        // The link target lives in a sibling stage, so granting the link would
        // write an ACE onto a file object outside this job's stage.
        let outside = test_stage("hard-link-target-");
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside").unwrap();
        fs::hard_link(&outside_file, read_only.join("linked.txt")).unwrap();

        let error = run_unprobed(&job(program, &read_only, &work)).unwrap_err();
        assert_eq!(error.code, crate::ResultCode::IsolationUnavailable);
        assert!(
            error.message.contains("hard links"),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn a_work_dir_outside_the_stage_root_is_rejected() {
        let outside = tempfile::tempdir().unwrap();
        let (read_only, work) = stage_dirs(outside.path());
        let program = copy_cmd(&read_only);
        let error = run_unprobed(&job(program, &read_only, &work)).unwrap_err();
        assert_eq!(error.code, crate::ResultCode::IsolationUnavailable);
        assert!(
            error.message.contains("stage root"),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn a_null_dacl_is_refused_before_any_write() {
        let stage = test_stage("null-dacl-");
        let (read_only, work) = stage_dirs(stage.path());
        let program = copy_cmd(&read_only);
        let input = read_only.join("input.txt");
        fs::write(&input, b"input").unwrap();
        ffi::set_null_dacl_for_tests(&input).unwrap();

        let error = run_unprobed(&job(program, &read_only, &work)).unwrap_err();
        assert_eq!(error.code, crate::ResultCode::IsolationUnavailable);
        assert!(
            error.message.contains("NULL DACL"),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn a_drain_that_misses_its_deadline_is_an_error() {
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(400));
            let _ = sender.send(Ok(vec![1u8, 2, 3]));
        });
        let error = collect_drain(
            receiver,
            Instant::now() + Duration::from_millis(50),
            "stdout",
        )
        .unwrap_err();
        assert_eq!(error.code, crate::ResultCode::IsolationUnavailable);
        assert!(
            error.message.contains("cleanup deadline"),
            "unexpected error: {}",
            error.message
        );
        let _ = handle.join();
    }

    #[test]
    fn a_drain_that_reports_in_time_returns_its_bytes() {
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let _ = sender.send(Ok(vec![7u8, 8, 9]));
        });
        let bytes =
            collect_drain(receiver, Instant::now() + Duration::from_secs(5), "stdout").unwrap();
        assert_eq!(bytes, vec![7, 8, 9]);
        let _ = handle.join();
    }
}
