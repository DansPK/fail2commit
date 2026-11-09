#![cfg(windows)]

//! Review reproduction for T-007b (FR-007, SPEC-007), S7B-003.
//!
//! The pre-fix backend anchored the "staged temp directory" containment check on
//! `std::env::temp_dir()`, which is `%TMP%`, then `%TEMP%`, then
//! `%USERPROFILE%`. This test drives the fixed backend with a caller-selected
//! temp root and asserts that the stage is refused, that the DACL of the
//! caller-selected directory is byte-for-byte unchanged, and that the same holds
//! with `TMP`/`TEMP` removed entirely.

use fail2commit_core::isolation::JobLimits;
use fail2commit_core::isolation::JobSpec;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::sandbox;
use fail2commit_core::ResultCode;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// The stage root the backend requires; kept in sync with
/// `docs/sandbox-windows.md`.
const STAGE_DIR: &str = "sandbox-stage";

fn stage_root() -> PathBuf {
    let paths = TrustedPaths::resolve().expect("trusted paths");
    let root = paths.cache_dir.join(STAGE_DIR);
    fs::create_dir_all(&root).expect("create stage root");
    root
}

fn acl(path: &Path) -> String {
    let output = Command::new("icacls.exe")
        .arg(path)
        .output()
        .expect("run icacls");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A job whose stage sits in `root`, one level too high to be a job stage of the
/// fail2commit stage root.
fn job_in(root: &Path) -> JobSpec {
    let read_only = root.join("read-only");
    let work = root.join("work");
    fs::create_dir_all(&read_only).unwrap();
    fs::create_dir_all(&work).unwrap();
    let program = read_only.join("not-an-executable.txt");
    fs::write(&program, b"not an executable").unwrap();
    JobSpec {
        program,
        args: Vec::new(),
        cwd: work.clone(),
        env: Vec::new(),
        read_only: vec![read_only],
        work_dir: work,
        exports: Vec::new(),
        export_to: None,
        limits: JobLimits {
            timeout: Duration::from_secs(5),
            memory_bytes: Some(64 * 1024 * 1024),
            max_processes: Some(2),
            max_output_bytes: 4096,
        },
    }
}

fn run_and_expect_stage_refusal(root: &Path) {
    let acl_before = acl(root);
    let error = sandbox::platform_backend()
        .run(&job_in(root))
        .expect_err("a stage outside the fail2commit stage root must be refused");
    assert_eq!(
        error.code,
        ResultCode::IsolationUnavailable,
        "{}",
        error.message
    );
    assert!(
        error.message.contains("stage root"),
        "unexpected error: {}",
        error.message
    );
    assert_eq!(
        acl(root),
        acl_before,
        "the caller-selected directory had its ACL changed"
    );
    assert!(
        !root.join("work").join("probe-result.txt").exists(),
        "something ran in the caller-selected directory"
    );
}

#[test]
fn temp_dir_anchor_is_not_used() {
    // (a) A caller who redirects TMP/TEMP and puts a stage there gets nothing:
    // the stage root is a fail2commit-owned directory resolved from the OS.
    let redirected = tempfile::Builder::new()
        .prefix("caller-temp-")
        .tempdir()
        .expect("caller temp root");
    let saved = (std::env::var_os("TMP"), std::env::var_os("TEMP"));
    std::env::set_var("TMP", redirected.path());
    std::env::set_var("TEMP", redirected.path());
    run_and_expect_stage_refusal(redirected.path());

    // (b) With TMP/TEMP removed, `std::env::temp_dir()` falls back into the real
    // user profile. A stage created there is refused as well, which is the case
    // the pre-fix anchor accepted.
    std::env::remove_var("TMP");
    std::env::remove_var("TEMP");
    let fallback = tempfile::Builder::new()
        .prefix("profile-temp-")
        .tempdir()
        .expect("temp dir in the profile");
    let profile = PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE"));
    println!(
        "temp_dir fallback with TMP/TEMP unset: {:?}",
        fallback.path()
    );
    assert!(
        fallback.path().starts_with(&profile),
        "expected the fallback temp dir to be inside the user profile"
    );
    run_and_expect_stage_refusal(fallback.path());

    match saved.0 {
        Some(value) => std::env::set_var("TMP", value),
        None => std::env::remove_var("TMP"),
    }
    match saved.1 {
        Some(value) => std::env::set_var("TEMP", value),
        None => std::env::remove_var("TEMP"),
    }

    // (c) The real stage root still yields an available backend, so the
    // refusals above are about the anchor and not about a broken host.
    let accepted = stage_root();
    assert!(accepted.is_absolute());
    let report = sandbox::platform_backend().probe();
    assert!(report.available, "{}", report.detail);
}
