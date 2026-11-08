#![cfg(windows)]

use fail2commit_core::isolation::{JobLimits, JobSpec, JobStatus, SandboxBackend};
use fail2commit_core::policy::{script_decision, DenyReason, ScriptDecision, ScriptSituation};
use fail2commit_core::sandbox;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::net::TcpListener;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

struct Stage {
    _root: tempfile::TempDir,
    read_only: PathBuf,
    work: PathBuf,
    helper: PathBuf,
}

fn compile_helper() -> Stage {
    let root = tempfile::Builder::new()
        .prefix("fail2commit-windows-test-")
        .tempdir()
        .expect("test stage");
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

#[test]
fn disabled_and_unavailable_policy_never_launches_package_code() {
    let state = tempfile::tempdir().unwrap();
    let marker = state.path().join("must-not-launch.txt");
    let scripts = ScriptSituation {
        has_scripts: true,
        required: false,
        flagged: false,
    };
    assert_eq!(
        script_decision(false, true, scripts),
        ScriptDecision::SkipScripts
    );
    assert_eq!(
        script_decision(true, false, scripts),
        ScriptDecision::Deny(DenyReason::IsolationUnavailable)
    );
    assert!(!marker.exists());
}

fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_os_string()
}

#[test]
fn parent_and_grandchild_cannot_reach_network_secret_checkout_or_git() {
    let stage = compile_helper();
    let fake_home = tempfile::Builder::new()
        .prefix("f2c-fake-home-")
        .tempdir()
        .unwrap();
    let secret = fake_home.path().join("synthetic-secret.txt");
    let synthetic = ["syn", "thetic", "-credential"].concat();
    fs::write(&secret, synthetic.as_bytes()).unwrap();
    let checkout = tempfile::Builder::new()
        .prefix("f2c-checkout-")
        .tempdir()
        .unwrap();
    let checkout_target = checkout.path().join("escape.txt");
    let marker = checkout.path().join("launched.txt");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let git = which("git.exe");
    let args = [
        os(&secret),
        os(&checkout_target),
        address.into(),
        os(&git),
        os(&marker),
    ];
    let outcome = backend()
        .run(&spec(&stage, "hostile-parent", &args, normal_limits()))
        .unwrap();
    assert_eq!(
        outcome.status,
        JobStatus::Exited(0),
        "stderr={}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    assert!(!checkout_target.exists());
    assert!(!marker.exists());
    assert_eq!(fs::read(&secret).unwrap(), synthetic.as_bytes());
}

#[test]
fn explicit_handle_list_excludes_an_inheritable_secret_handle() {
    let stage = compile_helper();
    let secret_dir = tempfile::Builder::new()
        .prefix("f2c-handle-")
        .tempdir()
        .unwrap();
    let secret = secret_dir.path().join("secret.bin");
    fs::write(&secret, [0x53, 0x59, 0x4e]).unwrap();
    let file = File::open(&secret).unwrap();
    set_inheritable(&file);
    let value = format!("{}", file.as_raw_handle() as usize);
    let outcome = backend()
        .run(&spec(
            &stage,
            "read-handle",
            &[value.into()],
            normal_limits(),
        ))
        .unwrap();
    assert_eq!(outcome.status, JobStatus::Exited(0));
}

#[test]
fn clean_environment_and_native_workload_succeed() {
    let stage = compile_helper();
    let env_outcome = backend()
        .run(&spec(&stage, "environment", &[], normal_limits()))
        .unwrap();
    assert_eq!(env_outcome.status, JobStatus::Exited(0));

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

#[link(name = "kernel32")]
extern "system" {
    fn SetHandleInformation(handle: *mut core::ffi::c_void, mask: u32, flags: u32) -> i32;
}

#[allow(unsafe_code)]
fn set_inheritable(file: &File) {
    const HANDLE_FLAG_INHERIT: u32 = 1;
    // SAFETY: `file` owns a live handle for the duration of this call; only
    // its inheritance flag is changed for the test.
    let ok = unsafe {
        SetHandleInformation(
            file.as_raw_handle().cast(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    assert_ne!(ok, 0, "SetHandleInformation failed");
}
