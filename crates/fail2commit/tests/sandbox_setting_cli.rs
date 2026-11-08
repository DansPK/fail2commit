//! FR-008 / TC-008: `fail2commit sandbox` and the trusted-setting guarantee.

mod sandbox_setting_support;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::settings::Settings;
use sandbox_setting_support::{cli, text};

fn enabled(home: &std::path::Path) -> bool {
    Settings::load(&TrustedPaths::under(home))
        .unwrap()
        .sandbox
        .enabled
}

#[test]
fn defaults_on_and_toggles() {
    let h = tempfile::tempdir().unwrap();
    let w = tempfile::tempdir().unwrap();
    let s = cli(h.path(), w.path(), &["sandbox", "status"]);
    assert!(s.status.success(), "{}", text(&s));
    assert!(text(&s).contains("sandbox: on"), "{}", text(&s));
    assert!(text(&s).contains("backend:"));

    let off = cli(h.path(), w.path(), &["sandbox", "off"]);
    assert!(off.status.success(), "{}", text(&off));
    let t = text(&off);
    assert!(
        t.contains("skipped by default") && t.contains("Run on host once"),
        "{t}"
    );
    assert!(!enabled(h.path()));
    assert!(text(&cli(h.path(), w.path(), &["sandbox", "status"])).contains("sandbox: off"));

    assert!(cli(h.path(), w.path(), &["sandbox", "on"]).status.success());
    assert!(enabled(h.path()));
}

#[test]
fn json_status_has_probe_fields() {
    let h = tempfile::tempdir().unwrap();
    let w = tempfile::tempdir().unwrap();
    let o = cli(h.path(), w.path(), &["--json", "sandbox", "status"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["data"]["sandbox"], true);
    assert!(v["data"]["backend"].is_string() && v["data"]["available"].is_boolean());
}

#[test]
fn malformed_setting_fails_closed() {
    let h = tempfile::tempdir().unwrap();
    let w = tempfile::tempdir().unwrap();
    let p = TrustedPaths::under(h.path());
    std::fs::create_dir_all(&p.config_dir).unwrap();
    std::fs::write(p.settings_file(), "[sandbox]\nenabled = \"off\"\n").unwrap();
    let o = cli(h.path(), w.path(), &["sandbox", "status"]);
    assert!(!o.status.success());
}

#[test]
fn repository_files_cannot_change_policy() {
    let h = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    let r = repo.path();
    let off = "[sandbox]\nenabled = false\n";
    std::fs::create_dir_all(r.join(".fail2commit")).unwrap();
    std::fs::write(r.join(".fail2commit/settings.toml"), off).unwrap();
    std::fs::write(r.join("fail2commit.toml"), off).unwrap();
    std::fs::write(
        r.join(".npmrc"),
        "ignore-scripts=false\nfail2commit-sandbox=off\n",
    )
    .unwrap();
    std::fs::write(r.join("pip.conf"), "[global]\nfail2commit-sandbox = off\n").unwrap();
    let read = || -> Vec<_> {
        ["fail2commit.toml", ".npmrc", "pip.conf"]
            .iter()
            .map(|f| std::fs::read(r.join(f)).unwrap())
            .collect()
    };
    let before = read();

    let s = cli(h.path(), r, &["sandbox", "status"]);
    assert!(text(&s).contains("sandbox: on"), "{}", text(&s));
    assert!(enabled(h.path()));
    // Toggling from inside the repo touches only the trusted file.
    assert!(cli(h.path(), r, &["sandbox", "off"]).status.success());
    assert!(cli(h.path(), r, &["sandbox", "on"]).status.success());
    assert!(enabled(h.path()));
    assert_eq!(before, read());
    assert_eq!(
        std::fs::read_to_string(r.join(".fail2commit/settings.toml")).unwrap(),
        off
    );
}
