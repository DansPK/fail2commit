//! TC-004 through the real binary and the `npm` shim name: unsupported input
//! stops before any resolution, and the production wiring fails closed.

mod npm_support;

use npm_support::*;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fail2commit")
}

fn run(env: &Env, program: &str, args: &[&str]) -> (i32, serde_json::Value, String) {
    let out = Command::new(program)
        .args(args)
        .current_dir(&env.project)
        .env("FAIL2COMMIT_HOME", env.paths.config_dir.parent().unwrap())
        .env("GIT_CONFIG_GLOBAL", env.tmp.path().join("gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let json = stdout
        .lines()
        .last()
        .and_then(|l| serde_json::from_str(l).ok())
        .unwrap_or(serde_json::Value::Null);
    (out.status.code().unwrap_or(-1), json, stdout)
}

fn project(reg: &Registry) -> Env {
    let env = Env::new(
        reg,
        r#"{"name":"cli-app","version":"1.0.0","private":true}"#,
    );
    // Keep the advisory path offline whatever T-006 lands.
    std::fs::write(env.paths.settings_file(), "[advisories]\noffline = true\n").unwrap();
    env
}

#[test]
fn unsupported_sources_exit_2_before_any_network_use() {
    require_node();
    let reg = Registry::start();
    let env = project(&reg);
    let before = snapshot(&env.project);
    for spec in [
        "git+https://example.invalid/x.git",
        "github:user/repo",
        "file:../x",
        "https://example.invalid/x.tgz",
        "npm:other@1",
        "./x.tgz",
    ] {
        let (code, json, _) = run(&env, bin(), &["--json", "npm", "install", spec]);
        assert_eq!(code, 2, "{spec}");
        assert_eq!(json["code"], "invalid_input", "{spec}");
        assert_eq!(json["findings"][0]["kind"], "unsupported_input", "{spec}");
    }
    for args in [
        &["npm", "update"][..],
        &["npm", "exec", "x"],
        &["npm", "rebuild"],
        &["npm", "install", "--registry=https://evil.example/"],
        &["npm", "install", "-g", "x"],
        &["npm", "--prefix", "x", "install"],
    ] {
        let mut a = vec!["--json"];
        a.extend(args);
        let (code, json, _) = run(&env, bin(), &a);
        assert_eq!(code, 2, "{args:?}");
        assert_eq!(json["code"], "invalid_input", "{args:?}");
    }
    assert!(reg.hits().is_empty(), "{:?}", reg.hits());
    assert_eq!(snapshot(&env.project), before);
}

#[test]
fn shim_name_routes_to_the_guard_and_never_to_plain_npm() {
    require_node();
    let reg = Registry::start();
    let env = project(&reg);
    let shim_dir = env.tmp.path().join("shim");
    std::fs::create_dir_all(&shim_dir).unwrap();
    let shim = shim_dir.join(if cfg!(windows) { "npm.exe" } else { "npm" });
    // Like the installed shim: a link on Unix (also avoids ETXTBSY), a copy on Windows.
    #[cfg(unix)]
    std::os::unix::fs::symlink(bin(), &shim).unwrap();
    #[cfg(windows)]
    std::fs::copy(bin(), &shim).unwrap();
    let shim = shim.to_str().unwrap();

    let (code, _, _) = run(
        &env,
        shim,
        &["install", "git+https://example.invalid/x.git"],
    );
    assert_eq!(code, 2, "git source through the shim is refused");
    let (code, _, _) = run(&env, shim, &["update"]);
    assert_eq!(code, 2, "update is not a guarded path and is not forwarded");
    assert!(reg.hits().is_empty());

    // Commands that cannot install pass through to the real npm.
    let (code, _, stdout) = run(&env, shim, &["--version"]);
    assert_eq!(code, 0);
    assert!(
        stdout
            .trim()
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit()),
        "{stdout}"
    );
}

#[test]
fn production_wiring_fails_closed_when_approval_is_needed() {
    require_node();
    let reg = Registry::start();
    reg.publish(&Pkg::new("left-pad", "1.0.0").file("index.js", "module.exports=1"));
    let env = project(&reg);
    let before = snapshot(&env.project);
    // The advisory scanner cannot complete offline -> approval needed -> no
    // approver (--approver none) -> nothing is applied.
    let (code, json, _) = run(
        &env,
        bin(),
        &["--json", "--approver", "none", "npm", "install", "left-pad"],
    );
    assert_eq!(code, 11, "{json}");
    assert_eq!(json["code"], "approval_unavailable");
    assert_eq!(snapshot(&env.project), before, "project untouched");
    assert_no_scratch(&env.project);
    assert_eq!(
        reg.tarball_hits().len(),
        1,
        "artifacts were reviewed before the stop"
    );
}
