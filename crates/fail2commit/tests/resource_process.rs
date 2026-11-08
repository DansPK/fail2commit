//! TC-012 / NFR-012: Linux has no daemon and no idle sandbox, and at most
//! one sandbox build runs per user.
#![cfg(target_os = "linux")]

mod resource_support;
use resource_support::*;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// fail2commit or bwrap processes that belong to `marker` (a unique temp
/// path found in their environment or command line).
fn leftovers(marker: &str) -> Vec<String> {
    let m = marker.as_bytes();
    let has = |hay: &[u8]| hay.windows(m.len()).any(|w| w == m);
    let mut found = Vec::new();
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default();
        let comm = comm.trim();
        if !(comm.starts_with("fail2commit") || comm == "bwrap") {
            continue;
        }
        let env = std::fs::read(e.path().join("environ")).unwrap_or_default();
        let cmd = std::fs::read(e.path().join("cmdline")).unwrap_or_default();
        if has(&env) || has(&cmd) {
            found.push(format!("{pid}:{comm}"));
        }
    }
    found
}

fn sandbox_ready(h: &Path) -> bool {
    let (_, v) = f2c(h, Path::new("/"), &["sandbox", "status"]);
    v["data"]["available"] == true
}

fn require_or_skip(what: &str) -> bool {
    if std::env::var_os("F2C_REQUIRE_SANDBOX").is_some_and(|v| v == "1") {
        panic!("sandbox required but unavailable ({what})");
    }
    eprintln!("SKIP (pending evidence) {what}: bwrap unavailable");
    false
}

#[test]
fn no_process_remains_after_commands_exit() {
    let h = home("");
    let cwd = tempfile::tempdir().unwrap();
    f2c(h.path(), cwd.path(), &["status"]);
    f2c(h.path(), cwd.path(), &["scan", "--offline", "npm:x@1.0.0"]);
    if sandbox_ready(h.path()) {
        let input = tempfile::tempdir().unwrap();
        let (_, v) = f2c(
            h.path(),
            cwd.path(),
            &[
                "run",
                "--input",
                input.path().to_str().unwrap(),
                "--",
                "/bin/true",
            ],
        );
        assert_eq!(v["code"], "ok", "{v}");
    } else {
        require_or_skip("sandbox leg");
    }
    assert_eq!(
        leftovers(&h.path().to_string_lossy()),
        Vec::<String>::new(),
        "daemon or idle sandbox left behind"
    );
}

/// Wall time of two simultaneous `run -- sleep` jobs sharing one home.
fn two_sleepers(h: &Path, secs: &str) -> Duration {
    let inputs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let t = Instant::now();
    let kids: Vec<_> = inputs
        .iter()
        .map(|i| {
            Command::new(f2c_bin())
                .args(["--json", "run", "--input"])
                .arg(i.path())
                .args(["--", "/bin/sleep", secs])
                .env("FAIL2COMMIT_HOME", h)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for k in kids {
        let o = k.wait_with_output().unwrap();
        assert!(o.status.code().is_some(), "run was killed by a signal");
    }
    t.elapsed()
}

/// Records current behaviour without failing either way, and checks what
/// holds regardless: both jobs finish and nothing lingers.
#[test]
fn two_concurrent_builds_finish_and_leave_nothing() {
    let h = home("");
    if !sandbox_ready(h.path()) {
        require_or_skip("concurrency");
        return;
    }
    let el = two_sleepers(h.path(), "2");
    eprintln!(
        "CONCURRENCY: two 2 s builds took {:.1} s => {}",
        el.as_secs_f32(),
        if el >= Duration::from_secs(4) {
            "serialized"
        } else {
            "ran in parallel (not enforced)"
        }
    );
    assert_eq!(leftovers(&h.path().to_string_lossy()), Vec::<String>::new());
}

/// SPEC-012 default: one active sandbox build per user. NOT enforced today
/// (finding in docs/resources.md); run with `--ignored` to see the gap.
#[test]
#[ignore = "NFR-012 gap: no per-user sandbox build limit is implemented"]
fn second_concurrent_build_is_queued_or_refused() {
    let h = home("");
    if !sandbox_ready(h.path()) {
        require_or_skip("concurrency");
        return;
    }
    let el = two_sleepers(h.path(), "2");
    assert!(el >= Duration::from_secs(4), "builds overlapped ({el:?})");
}
