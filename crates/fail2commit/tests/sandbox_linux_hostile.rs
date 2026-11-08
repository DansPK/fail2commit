//! TC-007 hostile fixtures and resource bounds on real Linux (FR-007,
//! SPEC-007). The hostile program is this test binary itself, run through
//! the `hostile_payload` test with `F2C_HOSTILE_MODE` set.
#![cfg(target_os = "linux")]

mod sandbox_support;

use fail2commit_core::isolation::{JobLimits, JobStatus, SandboxBackend};
use fail2commit_core::sandbox::Bubblewrap;
use sandbox_support::*;
use std::time::{Duration, Instant};

#[test]
fn hostile_payload() {
    payload_main();
}

/// Both cgroup-backed and rlimit-only configurations.
fn backends(test: &str) -> Vec<(&'static str, Bubblewrap)> {
    let mut v = Vec::new();
    if let Some(b) = backend(Bubblewrap::default(), test) {
        v.push(("default", b));
    }
    if let Some(b) = backend(Bubblewrap::default().without_cgroup(), test) {
        v.push(("rlimit-only", b));
    }
    v
}

fn assert_all(stdout: &[u8], verdict: &str, expect: &[&str], external: bool) {
    let got = results(stdout);
    for who in ["parent", "child"] {
        let mut checks: Vec<&str> = expect.to_vec();
        if external {
            checks.push("tcp_external");
        }
        for c in checks {
            let row = got.iter().find(|(w, k, _)| w == who && k == c);
            assert_eq!(
                row.map(|r| r.2.as_str()),
                Some(verdict),
                "{who} {c}; output:\n{}",
                text(stdout)
            );
        }
    }
}

/// Positive control: on the host the same probes really reach every target,
/// so a BLOCKED inside the sandbox is the sandbox's doing.
#[test]
fn host_control_reaches_every_target() {
    let fx = Fixture::new(false);
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(PAYLOAD_ARGS)
        .env("F2C_HOSTILE_MODE", "parent")
        .envs(fx.env.iter().cloned())
        .output()
        .unwrap();
    assert_all(&out.stdout, "LEAK", &CHECKS, false);
    assert!(text(&out.stdout).contains("CHILD_RAN true"));
    assert_eq!(fx.checkout_entries(), 2, "host control wrote the checkout");
}

/// Live-internet positive control for the external endpoint.
#[test]
#[ignore = "needs internet; run explicitly"]
fn host_control_reaches_external_endpoint() {
    let fx = Fixture::new(true);
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(PAYLOAD_ARGS)
        .env("F2C_HOSTILE_MODE", "parent")
        .envs(fx.env.iter().cloned())
        .output()
        .unwrap();
    assert_all(&out.stdout, "LEAK", &["tcp_external"], false);
}

#[test]
fn hostile_parent_and_child_are_blocked() {
    for (name, b) in backends("hostile_parent_and_child_are_blocked") {
        let fx = Fixture::new(true);
        let out = run_payload(&b, "parent", &fx.env, limits()).unwrap();
        eprintln!("[{name}] {}", text(&out.stdout));
        assert_eq!(
            out.status,
            JobStatus::Exited(0),
            "[{name}] {}",
            text(&out.stderr)
        );
        assert!(text(&out.stdout).contains("CHILD_RAN true"), "[{name}]");
        assert_all(&out.stdout, "BLOCKED", &CHECKS, true);
        assert_eq!(fx.checkout_entries(), 0, "[{name}] checkout untouched");
    }
}

#[test]
fn timeout_kills_the_whole_tree() {
    for (name, b) in backends("timeout_kills_the_whole_tree") {
        let m = marker();
        let script = format!("sleep 600.{m} & (sleep 601.{m} &) ; sleep 602.{m}");
        let (_w, mut spec) = job("/bin/bash", &["-c", &script]);
        spec.limits.timeout = Duration::from_secs(2);
        let t = Instant::now();
        let out = b.run(&spec).unwrap();
        assert_eq!(out.status, JobStatus::TimedOut, "[{name}]");
        assert!(
            t.elapsed() < Duration::from_secs(15),
            "[{name}] {:?}",
            t.elapsed()
        );
        assert_eq!(
            processes_with(&m),
            Vec::<String>::new(),
            "[{name}] leftovers"
        );
    }
}

#[test]
fn background_processes_stop_when_the_job_exits() {
    for (name, b) in backends("background_processes_stop_when_the_job_exits") {
        let m = marker();
        let script = format!("(sleep 600.{m} &); sleep 601.{m} & exit 0");
        let (_w, spec) = job("/bin/bash", &["-c", &script]);
        let t = Instant::now();
        let out = b.run(&spec).unwrap();
        assert_eq!(out.status, JobStatus::Exited(0), "[{name}]");
        assert!(t.elapsed() < Duration::from_secs(15), "[{name}]");
        assert_eq!(
            processes_with(&m),
            Vec::<String>::new(),
            "[{name}] leftovers"
        );
    }
}

#[test]
fn process_count_is_bounded() {
    for (name, b) in backends("process_count_is_bounded") {
        let limits = JobLimits {
            max_processes: Some(16),
            ..limits()
        };
        let out = run_payload(&b, "spawn", &[], limits).unwrap();
        let s = text(&out.stdout);
        let n: usize = s
            .lines()
            .find_map(|l| l.strip_prefix("SPAWNED ")?.parse().ok())
            .unwrap_or_else(|| panic!("[{name}] no count: {s} {}", text(&out.stderr)));
        assert!(n < 16, "[{name}] spawned {n} with a limit of 16");
    }
}

#[test]
fn fork_bomb_is_contained() {
    for (name, b) in backends("fork_bomb_is_contained") {
        let (_w, mut spec) = job("/bin/bash", &["-c", "f(){ f | f & }; f; sleep 5"]);
        spec.limits.max_processes = Some(32);
        spec.limits.timeout = Duration::from_secs(10);
        let t = Instant::now();
        let out = b.run(&spec).unwrap();
        assert!(
            t.elapsed() < Duration::from_secs(30),
            "[{name}] {:?}",
            t.elapsed()
        );
        eprintln!("[{name}] fork bomb ended with {:?}", out.status);
    }
}

#[test]
fn memory_hog_is_bounded() {
    for (name, b) in backends("memory_hog_is_bounded") {
        let limits = JobLimits {
            memory_bytes: Some(384 * 1024 * 1024),
            ..limits()
        };
        let out = run_payload(&b, "hog", &[], limits).unwrap();
        let s = text(&out.stdout);
        assert!(!s.contains("HOG_DONE"), "[{name}] allocated 2 GiB: {s}");
        assert_ne!(out.status, JobStatus::Exited(0), "[{name}]");
        eprintln!("[{name}] memory hog ended with {:?}", out.status);
    }
}

#[test]
fn output_is_capped_and_drained() {
    for (name, b) in backends("output_is_capped_and_drained") {
        let (_w, mut spec) = job(
            "/bin/bash",
            &[
                "-c",
                "head -c 4000000 /dev/zero; head -c 4000000 /dev/zero >&2; echo done",
            ],
        );
        spec.limits.max_output_bytes = 1000;
        let out = b.run(&spec).unwrap();
        assert_eq!(
            out.status,
            JobStatus::Exited(0),
            "[{name}] writer never blocked"
        );
        assert!(out.truncated, "[{name}]");
        assert!(out.stdout.len() + out.stderr.len() <= 1000, "[{name}]");
    }
}
