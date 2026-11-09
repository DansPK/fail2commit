#![cfg(windows)]

//! Review reproduction for T-007b (FR-007, SPEC-007), S7B-002.
//!
//! The pre-fix probe launched `<SystemRoot>\System32\CheckNetIsolation.exe`,
//! taking `<SystemRoot>` from the process environment, so a caller-controlled
//! environment substituted both the executable and the verdict. This test points
//! `SystemRoot` at a directory holding a marker-writing stand-in and asserts:
//!
//! * nothing from that directory is executed, and
//! * the probe does not report the backend as available, because the process
//!   environment disagrees with the operating system's own Windows directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn real_system_root() -> PathBuf {
    let root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let root = PathBuf::from(root);
    assert!(root.is_absolute(), "SystemRoot must be absolute");
    root
}

fn compile_stand_in(marker: &Path, dir: &Path) -> PathBuf {
    let source = dir.join("check_net_isolation.rs");
    fs::write(
        &source,
        format!(
            "fn main() {{ let _ = std::fs::write({:?}, b\"executed without a sandbox\"); }}",
            marker.display().to_string()
        ),
    )
    .unwrap();
    let exe = dir.join("CheckNetIsolation.exe");
    let status = Command::new("rustc")
        .args(["--edition=2021", "-C", "opt-level=0"])
        .arg(&source)
        .arg("-o")
        .arg(&exe)
        .status()
        .expect("run rustc for the stand-in");
    assert!(status.success(), "stand-in compilation failed: {status}");
    exe
}

#[test]
fn an_environment_selected_system_root_cannot_answer_the_loopback_control() {
    let real_root = real_system_root();
    let fake_root = tempfile::Builder::new()
        .prefix("fake-systemroot-")
        .tempdir()
        .expect("fake system root");
    let system32 = fake_root.path().join("System32");
    fs::create_dir_all(&system32).unwrap();
    // A real cmd.exe, so a pre-fix probe would have got as far as the control.
    fs::copy(
        real_root.join("System32").join("cmd.exe"),
        system32.join("cmd.exe"),
    )
    .expect("stage a real cmd.exe");
    let marker = fake_root.path().join("hijack-marker.txt");
    let stand_in = compile_stand_in(&marker, fake_root.path());
    fs::rename(&stand_in, system32.join("CheckNetIsolation.exe")).expect("install the stand-in");

    std::env::set_var("SystemRoot", fake_root.path());
    let report = fail2commit_core::sandbox::platform_backend().probe();
    std::env::set_var("SystemRoot", &real_root);

    println!(
        "probe available={} detail={} controls={:?}",
        report.available, report.detail, report.controls
    );
    assert!(
        !marker.exists(),
        "the probe executed a binary from the environment-selected SystemRoot"
    );
    assert!(
        !report.available,
        "the probe reported the backend available from a caller-controlled SystemRoot"
    );
    assert!(
        report.detail.contains("SystemRoot"),
        "the refusal should name the inconsistent SystemRoot: {}",
        report.detail
    );
}
