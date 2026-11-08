#![cfg(windows)]

//! Independent review reproduction for T-007b (FR-007, SPEC-007), S7B-003.
//!
//! `windows.rs` anchors the "staged temp directory" containment check on
//! `std::env::temp_dir()`, which is `%TMP%`, then `%TEMP%`, then
//! `%USERPROFILE%`. These tests show the anchor follows caller-controlled
//! environment variables and degrades to the real user profile when they are
//! absent. No ACLs are written to any real user directory.

use fail2commit_core::isolation::{JobLimits, JobSpec};
use fail2commit_core::sandbox;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn print_temp_exe(dir: &Path) -> PathBuf {
    let source = dir.join("print_temp.rs");
    fs::write(
        &source,
        "fn main() { println!(\"{}\", std::env::temp_dir().display()); }",
    )
    .unwrap();
    let exe = dir.join("print_temp.exe");
    let status = Command::new("rustc")
        .args(["--edition=2021", "-C", "opt-level=0"])
        .arg(&source)
        .arg("-o")
        .arg(&exe)
        .status()
        .expect("run rustc for the temp_dir probe");
    assert!(status.success(), "print_temp compilation failed: {status}");
    exe
}

fn printed_temp_dir(exe: &Path, tmp: Option<&Path>) -> PathBuf {
    let mut command = Command::new(exe);
    match tmp {
        Some(dir) => {
            command.env("TMP", dir).env("TEMP", dir);
        }
        None => {
            command.env_remove("TMP").env_remove("TEMP");
        }
    }
    let output = command.output().expect("run print_temp");
    assert!(output.status.success(), "print_temp failed");
    let text = String::from_utf8_lossy(&output.stdout);
    PathBuf::from(text.trim())
}

#[test]
fn temp_dir_anchor_is_caller_controlled() {
    // Run everything in one test: the containment check below needs TMP/TEMP
    // redirected for the whole process, which would race another test thread.
    let scratch = tempfile::Builder::new()
        .prefix("f2c-review-tempdir-")
        .tempdir()
        .expect("scratch");
    let exe = print_temp_exe(scratch.path());

    // (a) std::env::temp_dir() follows TMP/TEMP.
    let redirected = tempfile::Builder::new()
        .prefix("f2c-review-redirected-temp-")
        .tempdir()
        .expect("redirected temp root");
    let observed = printed_temp_dir(&exe, Some(redirected.path()));
    assert_eq!(
        observed.canonicalize().expect("canonicalize observed"),
        redirected
            .path()
            .canonicalize()
            .expect("canonicalize expected"),
        "std::env::temp_dir() did not follow TMP/TEMP"
    );

    // (b) With TMP/TEMP unset it falls back into the real user profile.
    let fallback = printed_temp_dir(&exe, None);
    println!("temp_dir fallback with TMP/TEMP unset: {fallback:?}");
    assert_ne!(
        fallback.canonicalize().expect("canonicalize fallback"),
        redirected
            .path()
            .canonicalize()
            .expect("canonicalize expected"),
        "fallback temp dir must not be the redirected root"
    );
    let profile = PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE"));
    assert!(
        fallback.starts_with(&profile),
        "with TMP/TEMP unset std::env::temp_dir() resolves to {fallback:?}, USERPROFILE is {profile:?}"
    );

    // (c) The staged-temp containment check accepts that caller-selected root.
    let root = tempfile::Builder::new()
        .prefix("f2c-review-containment-")
        .tempdir()
        .expect("containment root");
    let job_root = root.path().join("job");
    let read_only = job_root.join("read-only");
    let work = job_root.join("work");
    fs::create_dir_all(&read_only).unwrap();
    fs::create_dir_all(&work).unwrap();
    // A non-executable staged program: the run must fail at launch, which
    // proves it already passed the "inside a staged temp directory" check.
    let program = read_only.join("not-an-executable.txt");
    fs::write(&program, b"not an executable").unwrap();

    let saved = (std::env::var_os("TMP"), std::env::var_os("TEMP"));
    // A temp root fail2commit never created and never cleans up.
    std::env::set_var("TMP", root.path());
    std::env::set_var("TEMP", root.path());

    let job = JobSpec {
        program,
        args: Vec::new(),
        cwd: work.clone(),
        env: Vec::new(),
        read_only: vec![read_only],
        work_dir: work.clone(),
        exports: Vec::new(),
        export_to: None,
        limits: JobLimits {
            timeout: Duration::from_secs(5),
            memory_bytes: Some(64 * 1024 * 1024),
            max_processes: Some(2),
            max_output_bytes: 4096,
        },
    };
    let error = sandbox::platform_backend().run(&job).unwrap_err();

    match saved.0 {
        Some(value) => std::env::set_var("TMP", value),
        None => std::env::remove_var("TMP"),
    }
    match saved.1 {
        Some(value) => std::env::set_var("TEMP", value),
        None => std::env::remove_var("TEMP"),
    }

    assert_eq!(
        error.code,
        fail2commit_core::ResultCode::IsolationUnavailable,
        "{}",
        error.message
    );
    assert!(
        error.message.contains("CreateProcessW"),
        "the containment check did not accept the caller-selected temp root: {}",
        error.message
    );
}
