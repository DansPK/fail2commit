//! Windows AppContainer backend (T-007b, FR-007, SPEC-007).
//!
//! `sandboxrs-windows` 0.1.1 is pinned and its AppContainer path was reviewed,
//! but its public builder grants package access to broad system directories
//! and does not expose enough state to verify every mandatory control before
//! resume.  This module therefore applies the narrowly scoped fixes locally:
//! a fresh zero-capability profile, staged-only ACLs, an explicit handle list,
//! and a read-back-verified Job Object.  See `docs/sandbox-windows.md`.

mod ffi;

use crate::isolation::{JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HANDLE;

const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
const FILE_MODIFY: u32 = 0x0013_01BF;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const POLL_MS: u32 = 25;

#[derive(Default)]
pub struct AppContainer;

impl SandboxBackend for AppContainer {
    fn probe(&self) -> ProbeReport {
        static REPORT: OnceLock<ProbeReport> = OnceLock::new();
        REPORT.get_or_init(probe_host).clone()
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

fn probe_host() -> ProbeReport {
    let mut controls = mandatory_controls();
    let result = probe_host_inner(&mut controls);
    let available = result.is_ok() && controls.iter().all(|(_, ok)| *ok);
    ProbeReport {
        backend: "appcontainer",
        available,
        detail: match result {
            Ok(()) => {
                "all mandatory AppContainer controls verified; LPAC is not enabled or claimed"
                    .to_string()
            }
            Err(err) => err.message,
        },
        controls,
    }
}

fn mark(controls: &mut [(String, bool)], name: &str) {
    if let Some((_, ok)) = controls.iter_mut().find(|(n, _)| n == name) {
        *ok = true;
    }
}

fn probe_host_inner(controls: &mut [(String, bool)]) -> crate::Result<()> {
    // Merely naming the pinned preference keeps accidental migration to the
    // dependency's modern VM/API backend visible at compile time.  We cannot
    // call its public builder: 0.1.1 applies broad baseline ACL grants.
    let _required_dependency_path = sandboxrs_windows::BackendPreference::AppContainer;

    let stage = tempfile::Builder::new()
        .prefix("fail2commit-appcontainer-probe-")
        .tempdir()
        .map_err(|e| crate::Error::isolation_unavailable(format!("create probe stage: {e}")))?;
    let read_only = stage.path().join("read-only");
    let work = stage.path().join("work");
    fs::create_dir_all(&read_only)?;
    fs::create_dir_all(&work)?;
    let system_root = required_system_root()?;
    let cmd_source = system_root.join("System32").join("cmd.exe");
    let cmd = read_only.join("probe-cmd.exe");
    fs::copy(&cmd_source, &cmd).map_err(|e| {
        crate::Error::isolation_unavailable(format!("stage trusted probe executable: {e}"))
    })?;

    let nonce = hex::encode(random_bytes_16()?);
    let intended_name = format!(r"\\.\pipe\fail2commit-probe-intended-{nonce}");
    let default_name = format!(r"\\.\pipe\fail2commit-probe-default-{nonce}");
    let user = ffi::current_user_sid()?;
    let pipe_sddl =
        format!("D:P(D;;GA;;;S-1-15-2-1)(D;;GA;;;S-1-15-2-2)(A;;GA;;;SY)(A;;GA;;;{user})");
    let intended = ffi::listening_pipe(&intended_name, Some(&pipe_sddl))?;
    let default_pipe = ffi::listening_pipe(&default_name, None)?;

    let child_command = format!(
        "(>{intended_name} echo denied) && exit /b 93 & (>{default_name} echo denied) && exit /b 94 & exit /b 0"
    );
    let command = format!(
        "if defined PATH exit /b 90 & (>\"{intended_name}\" echo denied) && exit /b 91 & (>\"{default_name}\" echo denied) && exit /b 92 & \"{}\" /d /c \"{child_command}\" & if errorlevel 1 exit /b 95 & exit /b 0",
        cmd.display()
    );
    let normal = JobSpec {
        program: cmd.clone(),
        args: vec!["/d".into(), "/c".into(), command.into()],
        cwd: work.clone(),
        env: Vec::new(),
        read_only: vec![read_only.clone()],
        work_dir: work.clone(),
        exports: Vec::new(),
        export_to: None,
        limits: crate::isolation::JobLimits {
            timeout: Duration::from_secs(5),
            memory_bytes: Some(128 * 1024 * 1024),
            max_processes: Some(4),
            max_output_bytes: 16 * 1024,
        },
    };
    let outcome = run_unprobed(&normal)?;
    if outcome.status != JobStatus::Exited(0)
        || ffi::pipe_has_client(&intended)
        || ffi::pipe_has_client(&default_pipe)
    {
        return Err(crate::Error::isolation_unavailable(
            "sandbox child reached approval IPC or inherited the parent environment",
        ));
    }
    for name in [
        "appcontainer-zero-capabilities",
        "no-loopback-exemption",
        "staged-restrictive-acls",
        "explicit-stdio-handle-list",
        "approval-ipc-denied",
        "job-tree-and-resource-limits",
        "clean-environment",
    ] {
        mark(controls, name);
    }

    let mut timed = normal.clone();
    timed.args = vec![
        "/d".into(),
        "/c".into(),
        "for /L %i in (1,0,2) do @echo off".into(),
    ];
    timed.limits.timeout = Duration::from_millis(100);
    if run_unprobed(&timed)?.status != JobStatus::TimedOut {
        return Err(crate::Error::isolation_unavailable(
            "timeout probe did not terminate the job",
        ));
    }
    mark(controls, "timeout-kills-job");

    let mut noisy = normal;
    noisy.args = vec![
        "/d".into(),
        "/c".into(),
        "for /L %i in (1,1,200) do @echo 0123456789abcdef".into(),
    ];
    noisy.limits.max_output_bytes = 127;
    let outcome = run_unprobed(&noisy)?;
    if outcome.status != JobStatus::Exited(0)
        || !outcome.truncated
        || outcome.stdout.len() + outcome.stderr.len() > 127
    {
        return Err(crate::Error::isolation_unavailable(
            "bounded output probe failed",
        ));
    }
    mark(controls, "bounded-concurrent-output");
    Ok(())
}

fn run_unprobed(job: &JobSpec) -> crate::Result<JobOutcome> {
    let paths = ValidatedPaths::new(job)?;
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
    let mut grants = StagingGrants::new(profile.sid());
    for root in &paths.read_only {
        grants.grant_tree(root, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, false)?;
    }
    grants.grant_tree(&paths.work_dir, FILE_MODIFY, true)?;

    let job_object = ffi::Job::new(max_processes, memory_bytes)?;
    job_object.verify(max_processes, memory_bytes)?;
    let env = environment_block(&job.env, &paths.cwd)?;
    let mut command_line = command_line(&paths.program, &job.args)?;

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
    let spawned = ffi::spawn_suspended(
        &paths.program,
        &mut command_line,
        &env,
        &paths.cwd,
        profile.sid(),
        stdio,
    )?;
    let facts = match ffi::token_facts(&spawned.process, profile.sid()) {
        Ok(facts) => facts,
        Err(err) => {
            spawned.kill();
            return Err(err);
        }
    };
    if !facts.is_appcontainer || !facts.sid_matches || facts.capability_count != 0 {
        spawned.kill();
        return Err(crate::Error::isolation_unavailable(
            "child token did not verify as the fresh zero-capability AppContainer",
        ));
    }
    // The pinned sandboxrs AppContainer configuration does not request LPAC.
    // Observing LPAC would mean the launch policy changed unexpectedly.
    if facts.is_lpac {
        spawned.kill();
        return Err(crate::Error::isolation_unavailable(
            "unexpected LPAC token; dependency configuration changed",
        ));
    }
    if let Err(err) = job_object.assign(&spawned.process) {
        spawned.kill();
        return Err(err);
    }
    if let Err(err) = spawned.resume() {
        spawned.kill();
        return Err(err);
    }
    drop(stdout_write);
    drop(stderr_write);
    drop(stdin);

    let budget = Arc::new(Mutex::new(OutputBudget {
        remaining: output_cap,
        truncated: false,
    }));
    let stdout_thread = drain(stdout_read, Arc::clone(&budget));
    let stderr_thread = drain(stderr_read, Arc::clone(&budget));
    let started = Instant::now();
    let mut status = None;
    loop {
        if started.elapsed() >= job.limits.timeout {
            job_object.terminate();
            status = Some(JobStatus::TimedOut);
            break;
        }
        if let Some(message) = job_object.next_message(POLL_MS) {
            if message == ffi::MSG_ACTIVE_PROCESS_LIMIT || message == ffi::MSG_JOB_MEMORY_LIMIT {
                job_object.terminate();
                status = Some(JobStatus::Killed);
                break;
            }
            if message == ffi::MSG_ACTIVE_PROCESS_ZERO {
                break;
            }
        }
        if job_object
            .active_processes()
            .is_ok_and(|active| active == 0)
        {
            break;
        }
    }
    job_object.wait_empty();
    let status = status.unwrap_or(JobStatus::Exited(spawned.exit_code()? as i32));
    let stdout = join_drain(stdout_thread)?;
    let stderr = join_drain(stderr_thread)?;
    let truncated = budget.lock().unwrap_or_else(|e| e.into_inner()).truncated;
    Ok(JobOutcome {
        status,
        stdout,
        stderr,
        truncated,
        exported: Vec::new(),
    })
}

struct ValidatedPaths {
    program: PathBuf,
    cwd: PathBuf,
    read_only: Vec<PathBuf>,
    work_dir: PathBuf,
}

impl ValidatedPaths {
    fn new(job: &JobSpec) -> crate::Result<Self> {
        let temp = canonical_dir(&std::env::temp_dir(), "system temp directory")?;
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
        if !cwd.starts_with(&work_dir) {
            return Err(crate::Error::isolation_unavailable(
                "cwd is outside the writable work_dir",
            ));
        }
        if !read_only.iter().any(|p| program.starts_with(p)) {
            return Err(crate::Error::isolation_unavailable(
                "program is outside staged read_only roots",
            ));
        }
        if read_only
            .iter()
            .any(|p| p.starts_with(&work_dir) || work_dir.starts_with(p))
        {
            return Err(crate::Error::isolation_unavailable(
                "read_only and work_dir must not overlap",
            ));
        }
        let stage = first_child_under(&temp, &work_dir).ok_or_else(|| {
            crate::Error::isolation_unavailable("work_dir is not inside a staged temp directory")
        })?;
        if !read_only.iter().all(|p| p.starts_with(&stage)) {
            return Err(crate::Error::isolation_unavailable(
                "all granted paths must share one staged temp directory",
            ));
        }
        reject_reparse_tree(&stage)?;
        Ok(Self {
            program,
            cwd,
            read_only,
            work_dir,
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

fn first_child_under(parent: &Path, path: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(parent).ok()?;
    let first = relative.components().next()?;
    Some(parent.join(first.as_os_str()))
}

fn reject_reparse_tree(root: &Path) -> crate::Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path).map_err(|e| {
            crate::Error::isolation_unavailable(format!(
                "inspect staged path {}: {e}",
                path.display()
            ))
        })?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(crate::Error::isolation_unavailable(format!(
                "staged path is a reparse point: {}",
                path.display()
            )));
        }
        if meta.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        }
    }
    Ok(())
}

struct StagingGrants {
    sid: windows_sys::Win32::Security::PSID,
    paths: Vec<PathBuf>,
}

impl StagingGrants {
    fn new(sid: windows_sys::Win32::Security::PSID) -> Self {
        Self {
            sid,
            paths: Vec::new(),
        }
    }

    fn grant_tree(&mut self, root: &Path, mask: u32, writable: bool) -> crate::Result<()> {
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let meta = fs::symlink_metadata(&path)?;
            ffi::grant(&path, self.sid, mask, meta.is_dir())?;
            self.paths.push(path.clone());
            let actual = ffi::allowed_mask(&path, self.sid)?;
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
            if meta.is_dir() {
                for entry in fs::read_dir(&path)? {
                    pending.push(entry?.path());
                }
            }
        }
        Ok(())
    }
}

impl Drop for StagingGrants {
    fn drop(&mut self) {
        for path in self.paths.iter().rev() {
            let _ = ffi::revoke(path, self.sid);
        }
    }
}

fn verify_no_loopback_exemption(sid: &str) -> crate::Result<()> {
    let exe = required_system_root()?
        .join("System32")
        .join("CheckNetIsolation.exe");
    let output = std::process::Command::new(exe)
        .args(["LoopbackExempt", "-s"])
        .env_clear()
        .env("SystemRoot", required_system_root()?)
        .output()
        .map_err(|e| {
            crate::Error::isolation_unavailable(format!("query loopback exemptions: {e}"))
        })?;
    if !output.status.success() {
        return Err(crate::Error::isolation_unavailable(
            "CheckNetIsolation could not enumerate loopback exemptions",
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text
        .to_ascii_lowercase()
        .contains(&sid.to_ascii_lowercase())
    {
        return Err(crate::Error::isolation_unavailable(
            "fresh AppContainer unexpectedly has a loopback exemption",
        ));
    }
    Ok(())
}

fn required_system_root() -> crate::Result<PathBuf> {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| crate::Error::isolation_unavailable("SystemRoot is unavailable"))
}

fn environment_block(env: &[(OsString, OsString)], cwd: &Path) -> crate::Result<Vec<u16>> {
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
    let root = required_system_root()?.into_os_string();
    vars.insert("SYSTEMROOT".into(), ("SystemRoot".into(), root.clone()));
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .filter(|value| Path::new(value).is_absolute())
        .ok_or_else(|| crate::Error::isolation_unavailable("LOCALAPPDATA is unavailable"))?;
    vars.insert(
        "LOCALAPPDATA".into(),
        ("LOCALAPPDATA".into(), local_app_data),
    );
    if let Some(drive) = Path::new(&root).components().next() {
        let drive = drive.as_os_str().to_os_string();
        vars.insert("SYSTEMDRIVE".into(), ("SystemDrive".into(), drive));
    }
    // CreateProcessW rejects a caller-supplied environment block with
    // ERROR_ENVVAR_NOT_FOUND (203) unless it contains hidden per-drive
    // current-directory entries. These are OS process state, not inherited
    // user configuration. Synthesize one for each mounted drive, pointing
    // the job's drive at the validated staged cwd and every other drive at
    // its root.
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

fn drain(
    mut file: File,
    budget: Arc<Mutex<OutputBudget>>,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let count = file.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            let mut budget = budget.lock().unwrap_or_else(|e| e.into_inner());
            let take = count.min(budget.remaining);
            kept.extend_from_slice(&chunk[..take]);
            budget.remaining -= take;
            if take != count {
                budget.truncated = true;
            }
        }
        Ok(kept)
    })
}

fn join_drain(handle: thread::JoinHandle<std::io::Result<Vec<u8>>>) -> crate::Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| crate::Error::internal("sandbox output drain thread panicked"))?
        .map_err(|e| crate::Error::internal(format!("sandbox output drain failed: {e}")))
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

    #[test]
    fn host_probe_verifies_every_mandatory_control() {
        let report = AppContainer.probe();
        assert!(report.available, "{}: {:?}", report.detail, report.controls);
        assert!(report.controls.iter().all(|(_, verified)| *verified));
    }

    #[test]
    fn missing_mandatory_limit_fails_before_launch() {
        let stage = tempfile::Builder::new()
            .prefix("fail2commit-no-launch-")
            .tempdir()
            .unwrap();
        let read_only = stage.path().join("read-only");
        let work = stage.path().join("work");
        fs::create_dir_all(&read_only).unwrap();
        fs::create_dir_all(&work).unwrap();
        let program = read_only.join("cmd.exe");
        fs::copy(
            required_system_root().unwrap().join("System32/cmd.exe"),
            &program,
        )
        .unwrap();
        let marker = work.join("must-not-exist.txt");
        let command = format!("echo launched > \"{}\"", marker.display());
        let job = JobSpec {
            program,
            args: vec!["/d".into(), "/c".into(), command.into()],
            cwd: work.clone(),
            env: Vec::new(),
            read_only: vec![read_only],
            work_dir: work,
            exports: Vec::new(),
            export_to: None,
            limits: crate::isolation::JobLimits {
                timeout: Duration::from_secs(1),
                memory_bytes: Some(64 * 1024 * 1024),
                max_processes: None,
                max_output_bytes: 1024,
            },
        };
        let error = run_unprobed(&job).unwrap_err();
        assert_eq!(error.code, crate::ResultCode::IsolationUnavailable);
        assert!(
            !marker.exists(),
            "process launched despite a missing control"
        );
    }
}
