//! TC-009 startup toggle (FR-009) against a throw-away
//! `HKCU\Software\fail2commit-test-<random>` key; the real Run key is never
//! touched.
#![cfg(windows)]

use fail2commit_core::digest::random_hex32;
use fail2commit_core::integration::{Integration, SetupCtx};
use fail2commit_core::ipc::startup::{
    delete_test_tree, read_value, write_value, StartupIntegration, VALUE_NAME,
};
use fail2commit_core::paths::TrustedPaths;

struct TempKey(String);
impl TempKey {
    fn new() -> Self {
        TempKey(format!(
            r"Software\fail2commit-test-{}\Run",
            &random_hex32().unwrap()[..16]
        ))
    }
    fn root(&self) -> String {
        self.0.trim_end_matches(r"\Run").to_string()
    }
}
impl Drop for TempKey {
    fn drop(&mut self) {
        delete_test_tree(&self.root());
    }
}

fn ctx(dir: &std::path::Path, tray: bool, dry_run: bool) -> SetupCtx {
    let exe = dir.join("fail2commit.exe");
    std::fs::write(&exe, b"x").unwrap();
    if tray {
        std::fs::write(dir.join("fail2commit-tray.exe"), b"x").unwrap();
    }
    SetupCtx {
        paths: TrustedPaths::under(dir),
        exe,
        dry_run,
    }
}

#[test]
fn install_then_uninstall_removes_only_our_value() {
    let key = TempKey::new();
    let dir = tempfile::tempdir().unwrap();
    write_value(&key.0, "Other App", "keep-me").unwrap();
    let integ = StartupIntegration::with_run_key(&key.0);
    let c = ctx(dir.path(), true, false);

    let owned = integ.install(&c).unwrap();
    assert_eq!(owned.len(), 1);
    let v = read_value(&key.0, VALUE_NAME).unwrap();
    assert!(
        v.starts_with('"') && v.ends_with("fail2commit-tray.exe\""),
        "{v}"
    );
    assert!(integ.status(&c).installed);

    integ.uninstall(&c, &owned).unwrap();
    assert_eq!(read_value(&key.0, VALUE_NAME), None);
    assert_eq!(read_value(&key.0, "Other App").as_deref(), Some("keep-me"));
    assert!(!integ.status(&c).installed);
}

#[test]
fn uninstall_restores_a_previous_value() {
    let key = TempKey::new();
    let dir = tempfile::tempdir().unwrap();
    write_value(&key.0, VALUE_NAME, "\"C:\\old\\thing.exe\"").unwrap();
    let integ = StartupIntegration::with_run_key(&key.0);
    let c = ctx(dir.path(), true, false);
    let owned = integ.install(&c).unwrap();
    assert_ne!(
        read_value(&key.0, VALUE_NAME).unwrap(),
        "\"C:\\old\\thing.exe\""
    );
    integ.uninstall(&c, &owned).unwrap();
    assert_eq!(
        read_value(&key.0, VALUE_NAME).as_deref(),
        Some("\"C:\\old\\thing.exe\"")
    );
}

#[test]
fn dry_run_and_missing_tray_write_nothing() {
    let key = TempKey::new();
    let dir = tempfile::tempdir().unwrap();
    let integ = StartupIntegration::with_run_key(&key.0);
    let dry = integ.install(&ctx(dir.path(), true, true)).unwrap();
    assert_eq!(dry.len(), 1);
    assert_eq!(read_value(&key.0, VALUE_NAME), None);

    let dir2 = tempfile::tempdir().unwrap();
    assert!(integ
        .install(&ctx(dir2.path(), false, false))
        .unwrap()
        .is_empty());
    assert_eq!(read_value(&key.0, VALUE_NAME), None);
}

#[test]
fn tray_menu_toggle_round_trips() {
    let key = TempKey::new();
    let dir = tempfile::tempdir().unwrap();
    let c = ctx(dir.path(), true, false);
    let integ = StartupIntegration::with_run_key(&key.0);
    assert!(!integ.is_enabled());
    integ.set_enabled(&c.exe, true).unwrap();
    assert!(integ.is_enabled());
    integ.set_enabled(&c.exe, false).unwrap();
    assert!(!integ.is_enabled());
    // Turning off twice is fine.
    integ.set_enabled(&c.exe, false).unwrap();
}

#[test]
fn uninstall_ignores_foreign_records() {
    let key = TempKey::new();
    let dir = tempfile::tempdir().unwrap();
    write_value(&key.0, VALUE_NAME, "ours").unwrap();
    let integ = StartupIntegration::with_run_key(&key.0);
    let c = ctx(dir.path(), true, false);
    let mut owned = integ.install(&c).unwrap();
    owned[0].detail["name"] = serde_json::json!("SomeoneElse");
    integ.uninstall(&c, &owned).unwrap();
    assert!(read_value(&key.0, VALUE_NAME).is_some());
}
