//! TC-002 CLI and channel selection without a console (FR-002): non-TTY,
//! closed tray, unattended runs, and secrets passed by argument or
//! environment.

mod approval_support;

use approval_support::*;

const UNAVAILABLE: i32 = 11;
const INVALID: i32 = 2;

#[test]
fn every_channel_fails_closed_without_console_or_tray() {
    let h = home();
    h.set_password(&pw("a"));
    // auto: no tray (T-009 not running) and no terminal -> unavailable;
    // terminal: non-TTY; tray: closed; none: unattended.
    for approver in ["auto", "terminal", "tray", "none"] {
        let r = run(h.cmd(&["--json", "--approver", approver, "password", "verify"]));
        assert_eq!(r.code, UNAVAILABLE, "{approver}: {}{}", r.stdout, r.stderr);
        let v: serde_json::Value = serde_json::from_str(r.stdout.trim()).unwrap();
        assert_eq!(v["code"], "approval_unavailable", "{approver}");
    }
}

#[test]
fn password_management_needs_a_console() {
    let h = home();
    for action in ["set", "change", "reset", "disable"] {
        let r = run(h.cmd(&["password", action]));
        assert_eq!(r.code, UNAVAILABLE, "{action}: {}", r.stderr);
    }
    assert!(!h.paths.state_dir.join("password.json").exists());
}

#[test]
fn secrets_by_argument_are_refused_without_echo() {
    let h = home();
    let secret = pw("argv");
    let forms = [
        vec!["password", "set", secret.as_str()],
        vec!["password", secret.as_str()],
        vec!["password", "--password", secret.as_str(), "set"],
        vec!["password", "change", "--new"],
    ];
    let joined = format!("--password={secret}");
    let mut all = forms.to_vec();
    all.push(vec!["password", "reset", joined.as_str()]);
    for args in all {
        let r = run(h.cmd(&args));
        assert_eq!(r.code, INVALID, "{args:?}: {}", r.stderr);
        assert!(!r.stdout.contains(&secret) && !r.stderr.contains(&secret));
    }
}

#[test]
fn secrets_by_environment_are_refused_without_echo() {
    let h = home();
    let secret = pw("env");
    for var in [
        "FAIL2COMMIT_PASSWORD",
        "FAIL2COMMIT_RECOVERY_CODE",
        "FAIL2COMMIT_NEW_PASSWORD",
    ] {
        for args in [&["password", "status"][..], &["password", "verify"][..]] {
            let mut c = h.cmd(args);
            c.env(var, &secret);
            let r = run(c);
            assert_eq!(r.code, INVALID, "{var} {args:?}");
            assert!(r.stderr.contains(var));
            assert!(!r.stdout.contains(&secret) && !r.stderr.contains(&secret));
        }
    }
}

#[test]
fn status_reports_without_secrets() {
    let h = home();
    let r = run(h.cmd(&["--json", "password", "status"]));
    assert_eq!(r.code, 0);
    let v: serde_json::Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(v["data"]["enabled"], false);

    let code = h.set_password(&pw("a"));
    let r = run(h.cmd(&["--json", "password", "status"]));
    let v: serde_json::Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(v["data"]["enabled"], true);
    assert_eq!(v["data"]["kdf"]["alg"], "argon2id");
    assert_eq!(v["data"]["kdf"]["m_kib"], 19 * 1024);
    for s in [pw("a"), code.clone()] {
        assert!(!r.stdout.contains(&s) && !r.stderr.contains(&s));
        assert!(!h.all_state_text().contains(&s));
    }
    let state = std::fs::read_to_string(h.paths.state_dir.join("password.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&state).unwrap();
    assert_eq!(v["password"]["kdf"]["t"], 2);
    assert_eq!(v["password"]["salt"].as_str().unwrap().len(), 32);
}

#[cfg(unix)]
#[test]
fn state_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let h = home();
    h.set_password(&pw("a"));
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&h.paths.state_dir), 0o700);
    assert_eq!(mode(&h.paths.state_dir.join("password.json")), 0o600);
}
