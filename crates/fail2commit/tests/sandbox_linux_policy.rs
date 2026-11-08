//! Bubblewrap probe, mount/env policy and fail-closed behavior on Linux
//! (FR-007, SPEC-007, TC-007).
#![cfg(target_os = "linux")]

mod sandbox_support;

use fail2commit_core::isolation::{JobStatus, SandboxBackend};
use fail2commit_core::sandbox::{run_job, Bubblewrap};
use fail2commit_core::ResultCode;
use sandbox_support::*;
use std::path::PathBuf;

const MANDATORY: [&str; 11] = [
    "bwrap_trusted_path",
    "wrapper_shell",
    "user_namespace",
    "net_namespace",
    "pid_namespace",
    "ipc_namespace",
    "uts_namespace",
    "mount_namespace",
    "clean_env",
    "mount_policy",
    "memory_limit",
];

#[test]
fn probe_verifies_every_mandatory_control() {
    let Some(b) = backend(
        Bubblewrap::default(),
        "probe_verifies_every_mandatory_control",
    ) else {
        return;
    };
    let p = b.probe();
    eprintln!("probe: {} {:?}", p.detail, p.controls);
    for c in MANDATORY {
        assert!(
            p.controls.contains(&(c.to_string(), true)),
            "{c} not verified: {:?}",
            p.controls
        );
    }
    let no_cg = Bubblewrap::default().without_cgroup().probe();
    assert!(no_cg.available, "rlimit-only path: {}", no_cg.detail);
    assert!(no_cg.controls.contains(&("cgroup_v2_limits".into(), false)));
}

/// Unavailable: a missing bwrap launches nothing, whatever the job is.
#[test]
fn missing_bwrap_launches_nothing() {
    let b = Bubblewrap::with_bwrap("/nonexistent/bwrap");
    let p = b.probe();
    assert!(!p.available);
    let (work, spec) = job("/bin/bash", &["-c", "touch launched"]);
    let err = run_job(&b, &spec).unwrap_err();
    assert_eq!(err.code, ResultCode::IsolationUnavailable);
    assert_eq!(
        b.run(&spec).unwrap_err().code,
        ResultCode::IsolationUnavailable
    );
    assert!(!work.path().join("launched").exists());
}

#[test]
fn jobs_exposing_home_run_or_root_are_refused_before_launch() {
    let Some(b) = backend(Bubblewrap::default(), "jobs_exposing_home_run_or_root") else {
        return;
    };
    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    for bad in [home.clone(), "/".into(), "/run".into(), "/etc".into()] {
        let (work, mut spec) = job("/bin/bash", &["-c", "touch launched"]);
        spec.read_only = vec![bad.clone()];
        let err = b.run(&spec).unwrap_err();
        assert_eq!(
            err.code,
            ResultCode::Rejected,
            "{}: {}",
            bad.display(),
            err.message
        );
        assert!(!work.path().join("launched").exists());
    }
    // A program the sandbox could rewrite (in the work dir) is refused.
    let (work, mut spec) = job("/bin/true", &[]);
    let prog = work.path().join("tool");
    std::fs::copy("/bin/true", &prog).unwrap();
    spec.program = prog;
    assert_eq!(b.run(&spec).unwrap_err().code, ResultCode::InvalidInput);
}

#[test]
fn sandbox_sees_only_job_env_and_minimal_mounts() {
    let Some(b) = backend(Bubblewrap::default(), "sandbox_sees_only_job_env") else {
        return;
    };
    let script = r#"env; echo ROOT $(ls -A /); echo ETC $(ls -A /etc);
for p in /home /root /run /var /mnt "$HOST_HOME"; do [ -e "$p" ] && echo "VISIBLE $p"; done
touch /usr/x 2>&- && echo "WROTE /usr"; touch "$PWD/ok" && echo WORK_WRITABLE"#;
    let (work, mut spec) = job("/bin/bash", &["-c", script]);
    spec.env
        .push(("HOST_HOME".into(), std::env::var_os("HOME").unwrap()));
    let out = b.run(&spec).unwrap();
    let s = text(&out.stdout);
    assert_eq!(out.status, JobStatus::Exited(0), "{s}{}", text(&out.stderr));
    assert!(!s.contains("VISIBLE"), "{s}");
    assert!(!s.contains("WROTE"), "{s}");
    assert!(
        s.contains("WORK_WRITABLE") && work.path().join("ok").exists(),
        "{s}"
    );
    for line in s.lines().filter(|l| l.contains('=')) {
        let key = line.split('=').next().unwrap();
        assert!(
            ["PATH", "HOST_HOME", "PWD", "SHLVL", "_", "OLDPWD"].contains(&key),
            "unexpected env {key}"
        );
    }
    let etc = s.lines().find(|l| l.starts_with("ETC")).unwrap();
    assert!(
        !etc.contains("shadow") && !etc.contains("hostname"),
        "{etc}"
    );
}
