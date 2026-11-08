#![cfg(windows)]

//! Review reproductions for T-007b (FR-007, SPEC-007), S7B-001.
//!
//! These started as failing reproductions of the review finding and now assert
//! the fixed behaviour:
//!
//! * `hard_link_inside_staged_tree_is_rejected` — a hard link is not a reparse
//!   point, so the pre-fix backend granted an AppContainer ACE onto a file object
//!   whose other directory entry lives outside the stage. The backend now rejects
//!   multi-link files before any ACL write, and the outside file's ACL is
//!   compared before and after to prove nothing was written there.
//! * `junction_inside_staged_tree_is_rejected` — reparse points stay rejected.
//! * `a_read_only_root_from_another_stage_is_rejected` — every granted path must
//!   share the job's own stage below the stage root.

use fail2commit_core::isolation::{JobLimits, JobSpec, SandboxBackend};
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::sandbox;
use fail2commit_core::ResultCode;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const STAGE_DIR: &str = "sandbox-stage";

fn stage_root() -> PathBuf {
    let paths = TrustedPaths::resolve().expect("trusted paths");
    let root = paths.cache_dir.join(STAGE_DIR);
    fs::create_dir_all(&root).expect("create stage root");
    root
}

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

struct Stage {
    root: tempfile::TempDir,
    read_only: PathBuf,
    work: PathBuf,
    helper: PathBuf,
}

/// Stage `<stage_root>/<job>/{read-only,work}` plus the dependency-free helper.
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
        .expect("run rustc for the review helper");
    assert!(status.success(), "helper compilation failed: {status}");
    Stage {
        root,
        read_only,
        work,
        helper,
    }
}

fn native_work_job(
    program: PathBuf,
    input: &Path,
    output: &Path,
    read_only: &Path,
    work: &Path,
) -> JobSpec {
    JobSpec {
        program,
        args: vec![
            OsString::from("native-work"),
            input.as_os_str().to_os_string(),
            output.as_os_str().to_os_string(),
        ],
        cwd: work.to_path_buf(),
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

/// The DACL of a path as `icacls` prints it, so "no ACE was written here" can be
/// asserted instead of assumed.
fn acl(path: &Path) -> String {
    let output = Command::new("icacls.exe")
        .arg(path)
        .output()
        .expect("run icacls");
    String::from_utf8_lossy(&output.stdout).into_owned()
}
#[test]
fn hard_link_inside_staged_tree_is_rejected() {
    let stage = compile_helper();
    // A file object deliberately outside the job's stage: another stage below
    // the same stage root, so nothing about the path looks suspicious.
    let outside = tempfile::Builder::new()
        .prefix("outside-")
        .tempdir_in(stage_root())
        .expect("outside stage");
    let outside_file = outside.path().join("outside-secret.txt");
    fs::write(&outside_file, b"outside-secret").unwrap();
    let acl_before = acl(&outside_file);

    let link = stage.read_only.join("linked-input.txt");
    fs::hard_link(&outside_file, &link).expect("create a hard link inside the staged tree");
    assert!(
        !outside_file.starts_with(stage.root.path()),
        "the link target must live outside the job stage"
    );

    let output = stage.work.join("artifact.txt");
    let job = native_work_job(
        stage.helper.clone(),
        &link,
        &output,
        &stage.read_only,
        &stage.work,
    );
    let error = backend()
        .run(&job)
        .expect_err("the hard link must be refused");
    assert_eq!(
        error.code,
        ResultCode::IsolationUnavailable,
        "{}",
        error.message
    );
    assert!(
        error.message.contains("hard links"),
        "unexpected error: {}",
        error.message
    );
    assert!(!output.exists(), "the job produced an artifact");
    assert_eq!(
        acl(&outside_file),
        acl_before,
        "a grant was written onto a file object outside the job stage"
    );
    assert_eq!(fs::read(&outside_file).unwrap(), b"outside-secret");
}

#[test]
fn junction_inside_staged_tree_is_rejected() {
    let stage = compile_helper();
    let target = tempfile::Builder::new()
        .prefix("junction-target-")
        .tempdir_in(stage_root())
        .expect("junction target");
    let link = stage.read_only.join("junction");
    assert!(
        make_directory_link(&link, target.path()),
        "could not create a directory reparse point for the review"
    );

    let output = stage.work.join("artifact.txt");
    let job = native_work_job(
        stage.helper.clone(),
        &link,
        &output,
        &stage.read_only,
        &stage.work,
    );
    let error = backend()
        .run(&job)
        .expect_err("the junction must be refused");
    assert_eq!(
        error.code,
        ResultCode::IsolationUnavailable,
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

#[test]
fn a_read_only_root_from_another_stage_is_rejected() {
    let stage = compile_helper();
    let other = compile_helper();
    let input = other.read_only.join("input.txt");
    fs::write(&input, b"other stage").unwrap();
    let output = stage.work.join("artifact.txt");
    // Everything except the writable root belongs to the other stage, so only
    // the "one job stage" rule can reject this job.
    let job = native_work_job(
        other.helper.clone(),
        &input,
        &output,
        &other.read_only,
        &stage.work,
    );
    let error = backend()
        .run(&job)
        .expect_err("a grant spanning two stages must be refused");
    assert_eq!(
        error.code,
        ResultCode::IsolationUnavailable,
        "{}",
        error.message
    );
    assert!(
        error.message.contains("one fail2commit job stage"),
        "unexpected error: {}",
        error.message
    );
    assert!(!output.exists());
}
