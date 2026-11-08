//! `fail2commit run` end to end (FR-007, SPEC-007, TC-007): staged input,
//! declared exports, hostile output paths, sandbox toggle on/off/unavailable.

mod sandbox_support;

use fail2commit_core::sandbox::platform_backend;
use sandbox_support::*;
use std::path::Path;
use std::process::{Command, Output};

/// Disposable trusted home with the given sandbox toggle and timeout.
fn home(enabled: bool, timeout_secs: u64) -> tempfile::TempDir {
    let h = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(h.path().join("config")).unwrap();
    std::fs::write(
        h.path().join("config/settings.toml"),
        format!("[sandbox]\nenabled = {enabled}\n[limits]\njob_timeout_secs = {timeout_secs}\n"),
    )
    .unwrap();
    h
}

fn f2c(home: &Path, args: &[&str]) -> (Output, serde_json::Value) {
    let out = Command::new(f2c_bin())
        .arg("--json")
        .args(args)
        .env("FAIL2COMMIT_HOME", home)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    (out, json)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn export_without_destination_is_invalid() {
    let h = home(true, 60);
    let input = tempfile::tempdir().unwrap();
    let (out, _) = f2c(
        h.path(),
        &[
            "run",
            "--input",
            s(input.path()),
            "--export",
            "x",
            "--",
            "prog",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn escaping_export_paths_are_rejected_before_anything_runs() {
    let h = home(true, 60);
    let input = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    for bad in ["../outside", "a/../../b", "/etc/passwd"] {
        let (out, json) = f2c(
            h.path(),
            &[
                "run",
                "--input",
                s(input.path()),
                "--export",
                bad,
                "--to",
                s(to.path()),
                "--",
                "prog",
            ],
        );
        assert_eq!(out.status.code(), Some(10), "{bad}: {json}");
    }
    assert_eq!(std::fs::read_dir(to.path()).unwrap().count(), 0);
}

/// Unavailable means nothing launches, with the toggle on or off.
#[test]
fn unavailable_sandbox_refuses_to_run() {
    if platform_backend().probe().available {
        skip(
            "unavailable_sandbox_refuses_to_run (CLI)",
            "backend available here; covered by missing_bwrap_launches_nothing",
        );
        return;
    }
    let input = tempfile::tempdir().unwrap();
    let marker = input.path().join("launched");
    let me = std::env::current_exe().unwrap();
    for enabled in [true, false] {
        let h = home(enabled, 60);
        let (out, json) = f2c(
            h.path(),
            &["run", "--input", s(input.path()), "--", s(&me), "--help"],
        );
        assert_eq!(out.status.code(), Some(14), "{json}");
        assert_eq!(json["code"], "isolation_unavailable", "{json}");
    }
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use fail2commit_core::sandbox::Bubblewrap;

    const BUILD: &str = r#"mkdir -p out
echo built > out/result.txt
[ -e "$1" ] && echo HOST_HOME_VISIBLE
echo pwned > "$2/pwned" 2>&- && echo CHECKOUT_WRITTEN
echo "done"
"#;

    fn input_with(script: &str) -> tempfile::TempDir {
        let input = tempfile::tempdir().unwrap();
        std::fs::write(input.path().join("build.sh"), script).unwrap();
        std::fs::create_dir(input.path().join(".git")).unwrap();
        std::fs::write(input.path().join(".git/config"), "[remote \"o\"]\n").unwrap();
        input
    }

    fn available(test: &str) -> bool {
        backend(Bubblewrap::default(), test).is_some()
    }

    /// Explicit run is sandboxed with the toggle on and off.
    #[test]
    fn run_builds_in_staged_copy_and_exports_declared_paths() {
        if !available("run_builds_in_staged_copy") {
            return;
        }
        let host_home = std::env::var("HOME").unwrap();
        for enabled in [true, false] {
            let h = home(enabled, 60);
            let input = input_with(BUILD);
            let to = tempfile::tempdir().unwrap();
            let (out, json) = f2c(
                h.path(),
                &[
                    "run",
                    "--input",
                    s(input.path()),
                    "--export",
                    "out",
                    "--to",
                    s(to.path()),
                    "--",
                    "/bin/sh",
                    "build.sh",
                    &host_home,
                    s(input.path()),
                ],
            );
            assert_eq!(out.status.code(), Some(0), "{json}");
            let stdout = json["data"]["stdout"].as_str().unwrap();
            assert!(stdout.contains("done"), "{json}");
            assert!(!stdout.contains("HOST_HOME_VISIBLE"), "{json}");
            assert!(!stdout.contains("CHECKOUT_WRITTEN"), "{json}");
            assert_eq!(
                std::fs::read_to_string(to.path().join("out/result.txt")).unwrap(),
                "built\n"
            );
            assert!(
                !input.path().join("out").exists(),
                "the real input is untouched"
            );
            assert!(!input.path().join("pwned").exists());
        }
    }

    #[test]
    fn hostile_export_links_are_rejected() {
        if !available("hostile_export_links_are_rejected") {
            return;
        }
        let h = home(true, 60);
        let input = input_with("mkdir out; echo ok > out/a; ln -s /etc/passwd out/p\n");
        let to = tempfile::tempdir().unwrap();
        let (out, json) = f2c(
            h.path(),
            &[
                "run",
                "--input",
                s(input.path()),
                "--export",
                "out",
                "--to",
                s(to.path()),
                "--",
                "/bin/sh",
                "build.sh",
            ],
        );
        assert_eq!(out.status.code(), Some(10), "{json}");
        assert_eq!(std::fs::read_dir(to.path()).unwrap().count(), 0, "{json}");
    }

    #[test]
    fn failed_or_timed_out_jobs_export_nothing() {
        if !available("failed_or_timed_out_jobs_export_nothing") {
            return;
        }
        for (script, timeout, code) in [
            ("mkdir out; echo x > out/a; exit 3\n", 60, 3),
            ("mkdir out; echo x > out/a; sleep 30\n", 2, 124),
        ] {
            let h = home(true, timeout);
            let input = input_with(script);
            let to = tempfile::tempdir().unwrap();
            let (out, json) = f2c(
                h.path(),
                &[
                    "run",
                    "--input",
                    s(input.path()),
                    "--export",
                    "out",
                    "--to",
                    s(to.path()),
                    "--",
                    "/bin/sh",
                    "build.sh",
                ],
            );
            assert_eq!(out.status.code(), Some(code), "{json}");
            assert_eq!(std::fs::read_dir(to.path()).unwrap().count(), 0, "{json}");
        }
    }

    #[test]
    fn output_is_sanitized() {
        if !available("output_is_sanitized") {
            return;
        }
        let h = home(true, 60);
        let input = input_with("printf 'a\\033[2Jb\\n'\n");
        let (out, json) = f2c(
            h.path(),
            &[
                "run",
                "--input",
                s(input.path()),
                "--",
                "/bin/sh",
                "build.sh",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{json}");
        assert_eq!(json["data"]["stdout"], "a?[2Jb\n");
    }

    /// `.git` (remote URLs, credentials, hooks) never reaches the sandbox.
    #[test]
    fn git_metadata_is_not_staged() {
        if !available("git_metadata_is_not_staged") {
            return;
        }
        let h = home(true, 60);
        let input = input_with("[ -e .git ] && echo GIT_VISIBLE; echo end\n");
        let (out, json) = f2c(
            h.path(),
            &[
                "run",
                "--input",
                s(input.path()),
                "--",
                "/bin/sh",
                "build.sh",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{json}");
        assert_eq!(json["data"]["stdout"], "end\n");
    }
}
