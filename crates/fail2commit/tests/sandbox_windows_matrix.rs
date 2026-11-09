#![cfg(windows)]

//! Offline Windows sandbox matrix (T-007b, FR-007, SPEC-007).
//!
//! Every job stage lives directly below the fail2commit stage root
//! (`<trusted cache dir>/sandbox-stage`), which is the stager contract the
//! backend enforces. Each assertion reads a value the child actually produced —
//! a report file, an exit status or a marker — so a discarded return value can
//! never look like a pass.

use fail2commit_core::isolation::{
    JobLimits, JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend,
};
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::policy::{script_decision, DenyReason, ScriptDecision, ScriptSituation};
use fail2commit_core::sandbox;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// The stage root the backend requires. Kept in sync with
/// `docs/sandbox-windows.md`; a mismatch fails every test loudly.
const STAGE_DIR: &str = "sandbox-stage";
const HANDLE_FLAG_INHERIT: u32 = 1;
const ERROR_INVALID_HANDLE: i32 = 6;

fn stage_root() -> PathBuf {
    let paths = TrustedPaths::resolve().expect("trusted paths");
    let root = paths.cache_dir.join(STAGE_DIR);
    fs::create_dir_all(&root).expect("create stage root");
    root
}

struct Stage {
    _root: tempfile::TempDir,
    read_only: PathBuf,
    work: PathBuf,
    helper: PathBuf,
}

fn compile_helper() -> Stage {
    let root = tempfile::Builder::new()
        .prefix("job-")
        .tempdir_in(stage_root())
        .expect("job stage");
    let read_only = root.path().join("read-only");
    let work = root.path().join("work");
    fs::create_dir_all(&read_only).unwrap();
    fs::create_dir_all(&work).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("sandbox-windows")
        .join("attacker.rs");
    let helper = read_only.join("sandbox-windows-helper.exe");
    let status = Command::new("rustc")
        .args(["--edition=2021", "-C", "opt-level=0"])
        .arg(&source)
        .arg("-o")
        .arg(&helper)
        .status()
        .expect("run rustc for helper");
    assert!(status.success(), "helper compilation failed: {status}");
    Stage {
        _root: root,
        read_only,
        work,
        helper,
    }
}

fn spec(stage: &Stage, action: &str, args: &[OsString], limits: JobLimits) -> JobSpec {
    let mut all = vec![OsString::from(action)];
    all.extend_from_slice(args);
    JobSpec {
        program: stage.helper.clone(),
        args: all,
        cwd: stage.work.clone(),
        env: vec![("F2C_TEST_ALLOWED".into(), "yes".into())],
        read_only: vec![stage.read_only.clone()],
        work_dir: stage.work.clone(),
        exports: Vec::new(),
        export_to: None,
        limits,
    }
}

fn normal_limits() -> JobLimits {
    JobLimits {
        timeout: Duration::from_secs(10),
        memory_bytes: Some(256 * 1024 * 1024),
        max_processes: Some(8),
        max_output_bytes: 64 * 1024,
    }
}

fn backend() -> Box<dyn SandboxBackend> {
    let backend = sandbox::platform_backend();
    let report = backend.probe();
    assert!(report.available, "{}: {:?}", report.detail, report.controls);
    assert!(report.controls.iter().all(|(_, verified)| *verified));
    backend
}

fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_os_string()
}

#[test]
fn probe_verifies_every_control_in_one_launch_and_then_reuses_it_briefly() {
    let backend = sandbox::platform_backend();
    let cold = Instant::now();
    let report = backend.probe();
    let cold = cold.elapsed();
    let warm = Instant::now();
    let cached = backend.probe();
    let warm = warm.elapsed();
    println!(
        "cold probe {cold:?}, cached probe {warm:?}, detail: {}",
        report.detail
    );
    assert!(
        report.available && cached.available,
        "{}: {:?}",
        report.detail,
        report.controls
    );
    assert!(report.controls.iter().all(|(_, verified)| *verified));
    // One sandboxed launch and no unsandboxed process: the cold probe is
    // dominated by the timeout it has to measure, the cached one by nothing.
    assert!(cold < Duration::from_secs(30), "cold probe {cold:?}");
    assert!(warm < Duration::from_secs(2), "cached probe {warm:?}");
}

/// A backend that really launches the package code it is given, and counts the
/// calls. If the FR-008 gate ever lets a job through, the marker appears and the
/// counter moves, so the assertion can fail.
struct RecordingLauncher {
    program: PathBuf,
    marker: PathBuf,
    runs: AtomicUsize,
}

impl SandboxBackend for RecordingLauncher {
    fn probe(&self) -> ProbeReport {
        ProbeReport {
            backend: "recording-launcher",
            available: true,
            detail: "test launcher".into(),
            controls: Vec::new(),
        }
    }

    fn run(&self, _job: &JobSpec) -> fail2commit_core::Result<JobOutcome> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let status = Command::new(&self.program)
            .arg("create-marker")
            .arg(&self.marker)
            .status();
        Ok(JobOutcome {
            status: JobStatus::Exited(status.ok().and_then(|s| s.code()).unwrap_or(-1)),
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            exported: Vec::new(),
        })
    }
}

/// The frozen FR-008 contract: only `RunSandboxed` reaches the backend, and a
/// denial or a skip never launches anything.
fn drive_policy(
    decision: &ScriptDecision,
    backend: &dyn SandboxBackend,
    job: &JobSpec,
) -> fail2commit_core::Result<Option<JobOutcome>> {
    match decision {
        ScriptDecision::RunSandboxed => backend.run(job).map(Some),
        ScriptDecision::NoScripts
        | ScriptDecision::SkipScripts
        | ScriptDecision::AskHostOnce
        | ScriptDecision::Deny(_) => Ok(None),
    }
}

#[test]
fn disabled_and_unavailable_policy_never_launches_package_code() {
    let stage = compile_helper();
    let marker = stage.work.join("must-not-launch.txt");
    let launcher = RecordingLauncher {
        program: stage.helper.clone(),
        marker: marker.clone(),
        runs: AtomicUsize::new(0),
    };
    let job = spec(&stage, "create-marker", &[os(&marker)], normal_limits());

    // Positive control: this launcher does create the marker when it is allowed
    // to run, so "the marker is absent" below is a real assertion.
    drive_policy(&ScriptDecision::RunSandboxed, &launcher, &job).expect("positive control");
    assert!(marker.exists(), "the launcher cannot create the marker");
    assert_eq!(launcher.runs.load(Ordering::SeqCst), 1);
    fs::remove_file(&marker).unwrap();

    let scripts = ScriptSituation {
        has_scripts: true,
        required: false,
        flagged: false,
    };
    let disabled = script_decision(false, true, scripts);
    assert_eq!(disabled, ScriptDecision::SkipScripts);
    drive_policy(&disabled, &launcher, &job).expect("disabled gate");

    let unavailable = script_decision(true, false, scripts);
    assert_eq!(
        unavailable,
        ScriptDecision::Deny(DenyReason::IsolationUnavailable)
    );
    drive_policy(&unavailable, &launcher, &job).expect("unavailable gate");

    assert!(
        !marker.exists(),
        "package code was launched although the policy denied it"
    );
    assert_eq!(
        launcher.runs.load(Ordering::SeqCst),
        1,
        "a JobSpec reached the backend after a skip or a denial"
    );
}
/// The report the hostile helper writes; every line is `<generation>:<check>=<value>`.
fn report_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

fn assert_denied_report(lines: &[String], generation: &str) {
    for check in ["tcp", "secret", "checkout", "marker"] {
        let expected = format!("{generation}:{check}=denied");
        assert!(
            lines.contains(&expected),
            "missing {expected} in report: {lines:?}"
        );
    }
    // Git itself may execute (Program Files is executable by AppContainers), so
    // the recorded outcome that matters is that Git cannot read a repository
    // outside the stage.
    let git = lines
        .iter()
        .find(|line| line.starts_with(&format!("{generation}:git_ls_remote=")))
        .unwrap_or_else(|| panic!("no git outcome in report: {lines:?}"));
    assert!(
        git.starts_with(&format!("{generation}:git_ls_remote=denied")),
        "git read a repository outside the stage for {generation}: {git}"
    );
}

#[test]
fn parent_and_grandchild_cannot_reach_network_secret_checkout_or_git() {
    let stage = compile_helper();
    let outside = tempfile::Builder::new()
        .prefix("outside-")
        .tempdir_in(stage_root())
        .unwrap();
    let secret = outside.path().join("credential.txt");
    fs::write(&secret, b"synthetic-secret-value").unwrap();
    let checkout = outside.path().join("checkout");
    let marker = outside.path().join("launch-marker.txt");
    let report = stage.work.join("hostile-report.txt");
    let git = which("git.exe");

    // A disposable bare remote the child must not be able to read. The parent
    // proves it is usable first, so the child's failure is meaningful.
    let remote = outside.path().join("remote.git");
    let init = Command::new(&git)
        .args(["init", "--bare", "--quiet"])
        .arg(&remote)
        .status()
        .expect("git init --bare");
    assert!(init.success(), "could not create a disposable bare remote");
    let reachable = Command::new(&git)
        .args(["ls-remote"])
        .arg(&remote)
        .status()
        .expect("git ls-remote");
    assert!(reachable.success(), "the disposable remote is not readable");

    // Bind but never accept: the child must not be able to connect at all.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let job = spec(
        &stage,
        "hostile-parent",
        &[
            os(&secret),
            os(&checkout),
            os(address.to_string()),
            os(&git),
            os(&remote),
            os(&marker),
            os(&report),
        ],
        normal_limits(),
    );
    let outcome = backend().run(&job).unwrap();
    let stderr = String::from_utf8_lossy(&outcome.stderr).into_owned();
    let lines = report_lines(&report);
    assert_eq!(
        outcome.status,
        JobStatus::Exited(0),
        "stderr={stderr} report={lines:?}"
    );

    assert_denied_report(&lines, "parent");
    assert_denied_report(&lines, "child");
    assert!(!checkout.exists(), "the disposable checkout was writable");
    assert!(!marker.exists(), "the launch marker was written");
    assert_eq!(
        fs::read(&secret).unwrap(),
        b"synthetic-secret-value",
        "the synthetic secret changed"
    );
}

#[test]
fn clean_environment_and_native_workload_succeed() {
    let stage = compile_helper();
    let expected_local_app_data = stage.work.join("localappdata");
    let env_outcome = backend()
        .run(&spec(
            &stage,
            "environment",
            &[os(&expected_local_app_data)],
            normal_limits(),
        ))
        .unwrap();
    assert_eq!(
        env_outcome.status,
        JobStatus::Exited(0),
        "stderr={}",
        String::from_utf8_lossy(&env_outcome.stderr)
    );

    let input = stage.read_only.join("input.txt");
    fs::write(&input, b"compile me").unwrap();
    let output = stage.work.join("artifact.txt");
    let outcome = backend()
        .run(&spec(
            &stage,
            "native-work",
            &[os(&input), os(&output)],
            normal_limits(),
        ))
        .unwrap();
    assert_eq!(outcome.status, JobStatus::Exited(0));
    assert_eq!(fs::read(output).unwrap(), b"native-work: COMPILE ME");
}
#[link(name = "kernel32")]
extern "system" {
    fn SetHandleInformation(handle: *mut core::ffi::c_void, mask: u32, flags: u32) -> i32;
}

#[allow(unsafe_code)]
fn set_inheritable(file: &File, inherit: bool) {
    // SAFETY: `file` owns a live handle for the duration of this call; only its
    // inheritance flag changes, and the result is checked.
    let ok = unsafe {
        SetHandleInformation(
            file.as_raw_handle().cast(),
            HANDLE_FLAG_INHERIT,
            if inherit { HANDLE_FLAG_INHERIT } else { 0 },
        )
    };
    assert_ne!(ok, 0, "SetHandleInformation failed");
}

#[test]
fn explicit_handle_list_excludes_an_inheritable_secret_handle() {
    let stage = compile_helper();
    // The canary sits beside the granted roots, so the child can only reach it
    // through an inherited handle: no staged path names it.
    let secret_path = stage._root.path().join("secret.txt");
    fs::write(&secret_path, b"synthetic-secret-value").unwrap();
    let secret = File::open(&secret_path).unwrap();
    set_inheritable(&secret, true);

    // A numeric handle that the child cannot use reports ERROR_INVALID_HANDLE.
    let job = spec(
        &stage,
        "read-handle",
        &[
            os(format!("{}", secret.as_raw_handle() as usize)),
            os(ERROR_INVALID_HANDLE.to_string()),
        ],
        normal_limits(),
    );
    let outcome = backend().run(&job).unwrap();
    set_inheritable(&secret, false);
    let stderr = String::from_utf8_lossy(&outcome.stderr).into_owned();
    // Both mean "no such handle in the child": ReadFile failing with
    // ERROR_INVALID_HANDLE (helper exit 0), or, where strict handle checks are
    // enforced (GitHub's windows-latest), the STATUS_INVALID_HANDLE exception.
    const STATUS_INVALID_HANDLE: i32 = 0xC000_0008_u32 as i32;
    assert!(
        matches!(outcome.status, JobStatus::Exited(0 | STATUS_INVALID_HANDLE)),
        "the child could read an inheritable handle: status={:?} stderr={stderr}",
        outcome.status
    );
    assert!(
        !stderr.contains("inherited handle was readable"),
        "stderr={stderr}"
    );
    assert_eq!(
        fs::read(&secret_path).unwrap(),
        b"synthetic-secret-value",
        "the synthetic secret changed"
    );
}

#[test]
fn process_memory_time_and_output_limits_are_enforced() {
    let stage = compile_helper();

    let mut process_limits = normal_limits();
    process_limits.max_processes = Some(2);
    let process = backend()
        .run(&spec(&stage, "spawn-many", &[], process_limits))
        .unwrap();
    assert_ne!(process.status, JobStatus::Exited(0));

    let mut memory_limits = normal_limits();
    memory_limits.memory_bytes = Some(48 * 1024 * 1024);
    let memory = backend()
        .run(&spec(&stage, "allocate", &[], memory_limits))
        .unwrap();
    assert_ne!(memory.status, JobStatus::Exited(0));

    let mut timeout_limits = normal_limits();
    timeout_limits.timeout = Duration::from_millis(150);
    let timed = backend()
        .run(&spec(&stage, "spin", &[], timeout_limits))
        .unwrap();
    assert_eq!(timed.status, JobStatus::TimedOut);

    let mut output_limits = normal_limits();
    output_limits.max_output_bytes = 31;
    let output = backend()
        .run(&spec(&stage, "noisy", &[], output_limits))
        .unwrap();
    assert_eq!(output.status, JobStatus::Exited(0));
    assert!(output.truncated);
    assert!(output.stdout.len() + output.stderr.len() <= 31);
}

#[test]
#[ignore = "live external network endpoint; run explicitly on an authorized test host"]
fn external_tcp_is_denied() {
    let stage = compile_helper();
    let outcome = backend()
        .run(&spec(&stage, "external", &[], normal_limits()))
        .unwrap();
    assert_eq!(outcome.status, JobStatus::Exited(0));
}

fn which(name: &str) -> PathBuf {
    let output = Command::new("where.exe").arg(name).output().unwrap();
    assert!(output.status.success(), "{name} not found");
    let first = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .expect("where output")
        .trim()
        .to_owned();
    PathBuf::from(first)
}
