//! The `fail2commit pip` entry point and the pip shim, as processes.

mod pip_support;

use pip_support::*;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_fail2commit")
}

fn run(program: &Path, home: &Path, envs: &[(&str, &str)], a: &[&str]) -> (Output, Value) {
    let git_cfg = home.join("gitconfig");
    std::fs::write(&git_cfg, "").unwrap();
    let mut c = Command::new(program);
    c.args(a)
        .current_dir(home)
        .env("FAIL2COMMIT_HOME", home.join("f2c"))
        .env("GIT_CONFIG_GLOBAL", &git_cfg)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("PIP_INDEX_URL");
    for (k, v) in envs {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out, json)
}

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

#[test]
fn rejects_direct_reference_with_json() {
    let home = tempfile::tempdir().unwrap();
    let (o, j) = run(
        Path::new(exe()),
        home.path(),
        &[],
        &[
            "--json",
            "pip",
            "--python",
            "no-python",
            "install",
            "./local",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(code(&j), "invalid_input");
    assert_eq!(j["findings"][0]["kind"], "unsupported_input");
}

#[test]
fn pip_env_index_directive_is_rejected() {
    let home = tempfile::tempdir().unwrap();
    let (o, j) = run(
        Path::new(exe()),
        home.path(),
        &[("PIP_EXTRA_INDEX_URL", "http://evil.invalid/simple")],
        &["--json", "pip", "--python", "no-python", "install", "alpha"],
    );
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(code(&j), "invalid_input");
}

#[test]
fn unsupported_pip_commands_never_reach_pip() {
    let home = tempfile::tempdir().unwrap();
    for a in [
        &["download", "alpha"][..],
        &["wheel", "alpha"],
        &["config", "list"],
    ] {
        let mut argv = vec!["--json", "pip", "--python", "no-python"];
        argv.extend_from_slice(a);
        let (o, j) = run(Path::new(exe()), home.path(), &[], &argv);
        assert_eq!(o.status.code(), Some(2), "{a:?}");
        assert_eq!(code(&j), "invalid_input");
    }
}

#[test]
fn shim_name_routes_to_guarded_pip() {
    let home = tempfile::tempdir().unwrap();
    let shim: PathBuf = home
        .path()
        .join(if cfg!(windows) { "pip3.exe" } else { "pip3" });
    std::fs::copy(exe(), &shim).unwrap();
    let (o, j) = run(
        &shim,
        home.path(),
        &[],
        &[
            "--json",
            "--python",
            "x",
            "install",
            "git+https://example.invalid/r.git",
        ],
    );
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(j["findings"][0]["kind"], "unsupported_input");
}

#[test]
fn end_to_end_install_pauses_without_an_approver_and_changes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let index = TestIndex::start();
    index.add_wheel("alpha", "1.0", &[]);
    let venv = make_venv(&home.path().join("v"));
    // trusted settings: the loopback index, advisories offline
    let cfg = home.path().join("f2c").join("config");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(
        cfg.join("pip.toml"),
        format!("index_url = \"{}\"\n", index.url()),
    )
    .unwrap();
    std::fs::write(cfg.join("settings.toml"), "[advisories]\noffline = true\n").unwrap();
    let (o, j) = run(
        Path::new(exe()),
        home.path(),
        &[],
        &[
            "--json",
            "--approver",
            "none",
            "pip",
            "--python",
            venv.to_str().unwrap(),
            "install",
            "alpha",
        ],
    );
    // Advisory data is unavailable offline: the install pauses and, with no
    // approver, fails closed.
    assert_eq!(
        o.status.code(),
        Some(11),
        "{} {}",
        String::from_utf8_lossy(&o.stderr),
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(code(&j), "approval_unavailable");
    assert!(!has_name(&venv, "alpha"));

    // read-only commands pass through the isolated pip
    let (o, j) = run(
        Path::new(exe()),
        home.path(),
        &[],
        &["--json", "pip", "--python", venv.to_str().unwrap(), "list"],
    );
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(code(&j), "ok");
}
