#![cfg(windows)]

//! Independent review reproduction for T-007b (FR-007, SPEC-007), S7B-001.
//!
//! `verify_no_loopback_exemption` launches `<SystemRoot>\System32\
//! CheckNetIsolation.exe` to prove that the fresh AppContainer has no loopback
//! exemption. `<SystemRoot>` comes from the process environment and the binary
//! is executed unsandboxed with no integrity check, so a caller-controlled
//! environment substitutes both the executable and the verdict.
//!
//! This test only proves the primitive (an environment-selected binary runs in
//! the trusted parent while the probe is evaluating a mandatory control). It
//! writes nothing outside disposable temp directories.

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
fn probe_runs_an_environment_selected_binary_to_verify_the_loopback_control() {
    let real_root = real_system_root();
    let fake_root = tempfile::Builder::new()
        .prefix("f2c-review-fake-systemroot-")
        .tempdir()
        .expect("fake system root");
    let system32 = fake_root.path().join("System32");
    fs::create_dir_all(&system32).unwrap();
    // The probe also stages `<SystemRoot>\System32\cmd.exe`, so the fake root
    // has to carry a real copy for the probe to get as far as the control.
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
        marker.exists(),
        "the probe did not execute the SystemRoot-selected binary; detail={}",
        report.detail
    );
}
