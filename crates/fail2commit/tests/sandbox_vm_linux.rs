//! FR-029 / SPEC-019 Linux QEMU/KVM VM backend tests.
//!
//! Selection, preparation refusal and status run anywhere. The preparation
//! lifecycle needs root and a trusted QEMU; the job lifecycle tests need a
//! prepared image, root and `/dev/kvm`, and are opt-in with `F2C_VM_GATE=1`.
//! A skipped boot test is pending evidence, never a pass.
#![cfg(target_os = "linux")]

mod sandbox_support;

use fail2commit_core::isolation::{JobLimits, JobSpec, JobStatus, NetworkMode};
use fail2commit_core::sandbox::{run_job, select_backend, vm_prepare, vm_remove, vm_status};
use fail2commit_core::settings::{BackendChoice, Settings};
use sandbox_support::skip;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn vm_settings() -> Settings {
    let mut settings = Settings::default();
    settings.sandbox.backend = BackendChoice::Vm;
    settings
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|s| s.trim() == "0")
}

fn kvm_present() -> bool {
    Path::new("/dev/kvm").exists()
}

fn qemu_present() -> bool {
    Path::new("/usr/bin/qemu-system-x86_64").exists()
}

fn prepared() -> bool {
    Path::new("/etc/fail2commit-vm.json").exists()
}

/// TC-029-1: without KVM the VM backend falls back to the platform backend and
/// records the fallback reason; it never stays selected as qemu-kvm.
#[test]
fn selection_falls_back_without_virtualization() {
    if kvm_present() {
        skip(
            "selection_falls_back_without_virtualization",
            "/dev/kvm is present",
        );
        return;
    }
    let probe = select_backend(&vm_settings()).probe();
    assert_ne!(probe.backend, "qemu-kvm", "absent KVM must fall back");
    assert!(
        probe
            .controls
            .iter()
            .any(|(n, ok)| n == "vm_fallback_to_platform" && *ok),
        "fallback must be recorded: {:?}",
        probe.controls
    );
    assert!(probe.detail.contains("VM fallback"), "{}", probe.detail);
}

/// `vm prepare` without root is rejected and creates nothing.
#[test]
fn prepare_requires_root() {
    if is_root() {
        skip("prepare_requires_root", "running as root");
        return;
    }
    let err = vm_prepare().expect_err("non-root prepare must be rejected");
    assert_eq!(err.code, fail2commit_core::ResultCode::Rejected);
    assert!(!Path::new("/var/lib/fail2commit-vm").exists());
}

/// `vm status` always reports a bounded preparation state without starting a VM.
#[test]
fn status_reports_preparation_state() {
    let text = vm_status().expect("status must not fail");
    assert!(!text.is_empty());
    if !prepared() {
        assert!(text.contains("not prepared"), "{text}");
    }
}

/// TC-029-10: root prepares idempotently and removes completely (needs QEMU).
#[test]
fn prepare_and_remove_idempotent() {
    if !is_root() {
        skip("prepare_and_remove_idempotent", "needs root");
        return;
    }
    if !qemu_present() {
        skip(
            "prepare_and_remove_idempotent",
            "qemu-system-x86_64 not installed",
        );
        return;
    }
    vm_prepare().expect("first prepare");
    vm_prepare().expect("second prepare is idempotent");
    let status = vm_status().unwrap();
    assert!(status.contains("hashes: ok"), "{status}");
    assert!(Path::new("/var/lib/fail2commit-vm/initramfs.cpio").is_file());
    vm_remove().expect("first remove");
    vm_remove().expect("second remove is idempotent");
    assert!(!Path::new("/var/lib/fail2commit-vm").exists());
    assert!(!Path::new("/etc/fail2commit-vm.json").exists());
}

/// Boot-gated job tests: prepared image + root + KVM + explicit opt-in.
fn boot_gate(test: &str) -> Option<()> {
    if std::env::var_os("F2C_VM_GATE").is_none_or(|v| v != "1") {
        skip(test, "F2C_VM_GATE=1 not set");
        return None;
    }
    if !is_root() {
        skip(test, "needs root");
        return None;
    }
    if !kvm_present() {
        skip(test, "/dev/kvm absent");
        return None;
    }
    if !prepared() {
        skip(test, "run fail2commit vm prepare first");
        return None;
    }
    Some(())
}

/// Stage a job under a disposable trusted home so the VM stage root is owned.
fn stage_job(
    home: &Path,
    script: &str,
    exports: &[&str],
    to: Option<PathBuf>,
    timeout: Duration,
) -> (PathBuf, JobSpec) {
    let stage_root = home.join("cache").join("sandbox-stage");
    let stage = stage_root.join(format!("job-{}", sandbox_support::marker()));
    let work = stage.join("work");
    let toolchain = stage.join("toolchain");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&toolchain).unwrap();
    let spec = JobSpec {
        program: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), script.into()],
        cwd: work.clone(),
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        read_only: vec![toolchain],
        work_dir: work,
        exports: exports.iter().map(PathBuf::from).collect(),
        export_to: to,
        limits: JobLimits {
            timeout,
            memory_bytes: Some(256 * 1024 * 1024),
            max_processes: Some(16),
            max_output_bytes: 64 * 1024,
            disk_bytes: Some(64 * 1024 * 1024),
        },
        network: NetworkMode::None,
        bait: false,
    };
    (stage, spec)
}

/// TC-029-9 + TC-029-4: a clean VM job exports only after Exited(0), and no
/// QEMU process or VM state remains afterwards.
#[test]
fn exports_after_clean_exit_and_vm_is_gone() {
    if boot_gate("exports_after_clean_exit_and_vm_is_gone").is_none() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("FAIL2COMMIT_HOME", home.path());
    let out = home.path().join("out");
    let (_stage, spec) = stage_job(
        home.path(),
        "echo hello > out.txt",
        &["out.txt"],
        Some(out.clone()),
        Duration::from_secs(30),
    );
    let backend = select_backend(&vm_settings());
    assert!(
        backend.probe().available,
        "VM backend must be available in the gate"
    );
    let outcome = run_job(backend.as_ref(), &spec).expect("clean VM job");
    assert_eq!(outcome.status, JobStatus::Exited(0));
    assert_eq!(outcome.exported.len(), 1);
    assert_eq!(
        fs::read_to_string(out.join("out.txt")).unwrap().trim(),
        "hello"
    );
    assert!(
        sandbox_support::processes_with("qemu-system-x86_64").is_empty(),
        "no QEMU may remain"
    );
    std::env::remove_var("FAIL2COMMIT_HOME");
}

/// TC-029-7: a job that exceeds its timeout ends TimedOut with nothing exported.
#[test]
fn timeout_kills_the_vm() {
    if boot_gate("timeout_kills_the_vm").is_none() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("FAIL2COMMIT_HOME", home.path());
    let out = home.path().join("out");
    let (_stage, spec) = stage_job(
        home.path(),
        "sleep 30; echo late > out.txt",
        &["out.txt"],
        Some(out.clone()),
        Duration::from_secs(2),
    );
    let backend = select_backend(&vm_settings());
    let outcome = run_job(backend.as_ref(), &spec).expect("timeout job returns an outcome");
    assert_eq!(outcome.status, JobStatus::TimedOut);
    assert!(outcome.exported.is_empty());
    assert!(!out.join("out.txt").exists());
    assert!(sandbox_support::processes_with("qemu-system-x86_64").is_empty());
    std::env::remove_var("FAIL2COMMIT_HOME");
}

/// LV-04 boot gate: a comma-bearing stage path must still map correctly through
/// QEMU's real option parser (fd-backed / escaped share path). Pending KVM.
#[test]
fn comma_stage_path_boots() {
    if boot_gate("comma_stage_path_boots").is_none() {
        return;
    }
    let home = tempfile::Builder::new()
        .prefix("f2c,vm-")
        .tempdir()
        .unwrap();
    std::env::set_var("FAIL2COMMIT_HOME", home.path());
    let out = home.path().join("out");
    let (_stage, spec) = stage_job(
        home.path(),
        "echo comma > out.txt",
        &["out.txt"],
        Some(out.clone()),
        Duration::from_secs(30),
    );
    let backend = select_backend(&vm_settings());
    assert!(
        backend.probe().available,
        "VM backend must be available in the gate"
    );
    let outcome = run_job(backend.as_ref(), &spec).expect("comma-path VM job");
    assert_eq!(outcome.status, JobStatus::Exited(0));
    assert_eq!(
        fs::read_to_string(out.join("out.txt")).unwrap().trim(),
        "comma"
    );
    assert!(sandbox_support::processes_with("qemu-system-x86_64").is_empty());
    std::env::remove_var("FAIL2COMMIT_HOME");
}
