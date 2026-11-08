//! Helpers for the NFR-012 resource assertions (T-012). Each test crate uses
//! a subset. Everything runs in disposable homes and repos.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The CLI under test; `F2C_BIN` overrides it for prebuilt Linux bundles.
pub fn f2c_bin() -> PathBuf {
    std::env::var_os("F2C_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_fail2commit")))
}

/// A disposable FAIL2COMMIT_HOME with the given `settings.toml` text.
pub fn home(settings: &str) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("config")).unwrap();
    std::fs::write(d.path().join("config").join("settings.toml"), settings).unwrap();
    d
}

/// Run the CLI with `--json`; returns the process output and the Response.
pub fn f2c(home: &Path, cwd: &Path, args: &[&str]) -> (Output, serde_json::Value) {
    let out = Command::new(f2c_bin())
        .arg("--json")
        .args(args)
        .current_dir(cwd)
        .env("FAIL2COMMIT_HOME", home)
        .output()
        .expect("spawn fail2commit");
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "not JSON ({e}): {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out, v)
}

/// A repo on `main` with `files` small files in one commit and no remote.
pub fn repo(files: usize) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let git = |a: &[&str]| {
        let o = Command::new("git")
            .arg("-C")
            .arg(d.path())
            .args(a)
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "git {a:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "t@example.invalid"]);
    git(&["config", "user.name", "t"]);
    git(&["config", "commit.gpgsign", "false"]);
    for i in 0..files {
        std::fs::write(
            d.path().join(format!("f{i}.txt")),
            format!("plain text {i}\n"),
        )
        .unwrap();
    }
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "c"]);
    d
}
