#![cfg(windows)]

//! Independent review reproductions for T-007b (FR-007, SPEC-007).
//!
//! Review artifact only: no product code is modified by these tests.
//!
//! * `hard_link_inside_staged_tree_...` reproduces S7B-002: a hard link is not
//!   a reparse point, so `reject_reparse_tree` accepts it and `ffi::grant`
//!   writes an AppContainer ACE onto a file object that lives outside the
//!   staged tree. The sandboxed child then reads content that was never
//!   staged as a copy.
//! * `junction_inside_staged_tree_is_rejected` and
//!   `parent_traversal_out_of_the_stage_is_rejected` record positive evidence
//!   for the reparse-point and `..` rejections.

use fail2commit_core::isolation::{JobLimits, JobSpec, JobStatus, SandboxBackend};
use fail2commit_core::sandbox;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn limits() -> JobLimits {
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
    backend
}

/// Stage `<temp>/<random>/{read-only,work}` plus the dependency-free helper.
fn compile_helper() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let root = tempfile::Builder::new()
        .prefix("f2c-review-paths-")
        .tempdir()
        .expect("review stage");
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
        .expect("run rustc for the review helper");
    assert!(status.success(), "helper compilation failed: {status}");
    (root, read_only, work, helper)
}

fn native_work_job(
    program: PathBuf,
    input: &Path,
    output: &Path,
    read_only: &Path,
    work: &Path,
    cwd: PathBuf,
) -> JobSpec {
    JobSpec {
        program,
        args: vec![
            OsString::from("native-work"),
            input.as_os_str().to_os_string(),
            output.as_os_str().to_os_string(),
        ],
        cwd,
        env: Vec::new(),
        read_only: vec![read_only.to_path_buf()],
        work_dir: work.to_path_buf(),
        exports: Vec::new(),
        export_to: None,
        limits: limits(),
    }
}

fn make_directory_link(link: &Path, target: &Path) -> bool {
    if std::os::windows::fs::symlink_dir(target, link).is_ok() {
        return true;
    }
    Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[test]
fn hard_link_inside_staged_tree_grants_access_to_a_file_outside_the_stage() {
    let (root, read_only, work, helper) = compile_helper();
    // A file object that is deliberately outside the staged tree.
    let outside_dir = tempfile::Builder::new()
        .prefix("f2c-review-outside-")
        .tempdir()
        .expect("outside stage");
    let outside = outside_dir.path().join("outside-secret.txt");
    fs::write(&outside, b"outside-secret").unwrap();

    let link = read_only.join("linked-input.txt");
    fs::hard_link(&outside, &link).expect("create a hard link inside the staged tree");
    assert!(
        !outside.starts_with(root.path()),
        "the link target must live outside the staged tree"
    );

    let output = work.join("artifact.txt");
    let job = native_work_job(helper, &link, &output, &read_only, &work, work.clone());
    let outcome = backend().run(&job).expect("sandbox run");
    assert_eq!(
        outcome.status,
        JobStatus::Exited(0),
        "stderr={}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    assert_eq!(
        fs::read(&output).unwrap(),
        b"native-work: OUTSIDE-SECRET",
        "the sandbox read file content from outside the staged tree"
    );
}

#[test]
fn junction_inside_staged_tree_is_rejected() {
    let (_root, read_only, work, helper) = compile_helper();
    let target = tempfile::Builder::new()
        .prefix("f2c-review-junction-target-")
        .tempdir()
        .expect("junction target");
    let link = read_only.join("junction");
    assert!(
        make_directory_link(&link, target.path()),
        "could not create a directory reparse point for the review"
    );

    let output = work.join("artifact.txt");
    let job = native_work_job(helper, &link, &output, &read_only, &work, work.clone());
    let error = backend().run(&job).unwrap_err();
    assert_eq!(
        error.code,
        fail2commit_core::ResultCode::IsolationUnavailable,
        "{}",
        error.message
    );
    assert!(
        error.message.contains("reparse point"),
        "unexpected error: {}",
        error.message
    );
    assert!(!output.exists());
}
