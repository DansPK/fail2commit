//! Independent re-review of the W2-006 fix (FR-005, FR-008): the pip shim never
//! replaces or removes a foreign file, and uninstall restores the previous state.

use fail2commit_core::integration::{OwnedChange, SetupCtx};
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::pip;

fn ctx(root: &std::path::Path, exe: &std::path::Path) -> SetupCtx {
    SetupCtx {
        paths: TrustedPaths::under(&root.join("home")),
        exe: exe.to_path_buf(),
        dry_run: false,
    }
}

fn names() -> [&'static str; 2] {
    if cfg!(windows) {
        ["pip.exe", "pip3.exe"]
    } else {
        ["pip", "pip3"]
    }
}

/// Control: a foreign file is neither replaced nor removed, in either slot.
#[test]
fn foreign_file_survives_setup_and_uninstall() {
    let d = tempfile::tempdir().unwrap();
    let exe = d.path().join("f2c.bin");
    std::fs::write(&exe, b"fail2commit v1").unwrap();
    let c = ctx(d.path(), &exe);
    let shim = pip::integration().unwrap();
    for victim in names() {
        let _ = std::fs::remove_dir_all(&c.paths.bin_dir);
        std::fs::create_dir_all(&c.paths.bin_dir).unwrap();
        let foreign = c.paths.bin_dir.join(victim);
        std::fs::write(&foreign, b"user wrapper").unwrap();
        assert!(shim.install(&c).is_err(), "{victim}");
        assert_eq!(std::fs::read(&foreign).unwrap(), b"user wrapper");
        for n in names() {
            if n != victim {
                assert!(!c.paths.bin_dir.join(n).exists(), "nothing half placed");
            }
        }
        // an uninstall with a forged ownership record must not touch it either
        let forged: Vec<OwnedChange> = names()
            .iter()
            .map(|n| OwnedChange {
                integration: "pip".into(),
                kind: "shim".into(),
                path: Some(c.paths.bin_dir.join(n)),
                detail: serde_json::json!({ "target": exe, "mode": "copy", "sha256": null }),
            })
            .collect();
        shim.uninstall(&c, &forged).unwrap();
        assert_eq!(std::fs::read(&foreign).unwrap(), b"user wrapper");
    }
}

/// RP-005: after fail2commit itself is upgraded in place, `uninstall` must
/// still remove the shims it created (the npm shim does, by comparing with the
/// sha256 recorded at setup). The pip shim ignores the recorded hash and
/// compares with the *current* executable instead.
#[test]
fn uninstall_after_in_place_upgrade_removes_our_shims() {
    if !cfg!(windows) {
        eprintln!("copy-mode shim only exists on Windows; not exercised here");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let exe = d.path().join("f2c.exe");
    std::fs::write(&exe, b"fail2commit v1").unwrap();
    let c = ctx(d.path(), &exe);
    let shim = pip::integration().unwrap();
    let owned = shim.install(&c).unwrap();
    for n in names() {
        assert!(c.paths.bin_dir.join(n).is_file());
    }
    std::fs::write(&exe, b"fail2commit v2 (upgraded in place)").unwrap();
    shim.uninstall(&c, &owned).unwrap();
    let left: Vec<&str> = names()
        .into_iter()
        .filter(|n| c.paths.bin_dir.join(n).exists())
        .collect();
    assert!(
        left.is_empty(),
        "RP-005: uninstall left our own pip shims behind after an in-place upgrade: {left:?}"
    );
}

/// RP-005 (companion): re-running setup after the executable changed refuses
/// forever, because our own old shim is "not a fail2commit shim".
#[test]
fn setup_again_after_upgrade_is_not_blocked_by_our_own_old_shim() {
    let d = tempfile::tempdir().unwrap();
    let exe_v1 = d.path().join("f2c-v1.bin");
    let exe_v2 = d.path().join("f2c-v2.bin");
    std::fs::write(&exe_v1, b"fail2commit v1").unwrap();
    std::fs::write(&exe_v2, b"fail2commit v2").unwrap();
    let shim = pip::integration().unwrap();
    shim.install(&ctx(d.path(), &exe_v1)).unwrap();
    let r = shim.install(&ctx(d.path(), &exe_v2));
    assert!(
        r.is_ok(),
        "RP-005: setup refuses to refresh its own previous shim: {:?}",
        r.err().map(|e| e.to_string())
    );
}

/// Install is idempotent and uninstall removes exactly what setup placed.
#[test]
fn install_twice_then_uninstall_restores_an_empty_bin_dir() {
    let d = tempfile::tempdir().unwrap();
    let exe = d.path().join("f2c.bin");
    std::fs::write(&exe, b"fail2commit v1").unwrap();
    let c = ctx(d.path(), &exe);
    let shim = pip::integration().unwrap();
    let owned = shim.install(&c).unwrap();
    assert_eq!(shim.install(&c).unwrap().len(), 2);
    shim.uninstall(&c, &owned).unwrap();
    for n in names() {
        assert!(std::fs::symlink_metadata(c.paths.bin_dir.join(n)).is_err());
    }
}

// ---------------------------------------------------------------------------
// Fix regressions (FR-005, RP-005): ownership by owned-change record + marker.
// ---------------------------------------------------------------------------

fn markers(c: &SetupCtx) -> usize {
    std::fs::read_dir(c.paths.state_dir.join("pip"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("shim-"))
                .count()
        })
        .unwrap_or(0)
}

/// Setup after an upgrade refreshes our own previous shim; a later uninstall
/// removes it and its marker, leaving an empty bin dir (any platform).
#[test]
fn setup_after_upgrade_refreshes_our_shim_and_uninstall_removes_it() {
    let d = tempfile::tempdir().unwrap();
    let (v1, v2) = (d.path().join("f2c-v1.bin"), d.path().join("f2c-v2.bin"));
    std::fs::write(&v1, b"fail2commit v1").unwrap();
    std::fs::write(&v2, b"fail2commit v2").unwrap();
    let shim = pip::integration().unwrap();
    let c1 = ctx(d.path(), &v1);
    let c2 = ctx(d.path(), &v2);
    shim.install(&c1).unwrap();
    assert_eq!(markers(&c1), 2);
    let owned = shim.install(&c2).unwrap();
    for n in names() {
        let p = c2.paths.bin_dir.join(n);
        if cfg!(windows) {
            assert_eq!(std::fs::read(&p).unwrap(), b"fail2commit v2", "refreshed");
        } else {
            assert_eq!(std::fs::read_link(&p).unwrap(), v2);
        }
    }
    // the earlier record (v1) and the new one both identify our shims
    shim.uninstall(&c2, &owned).unwrap();
    for n in names() {
        assert!(std::fs::symlink_metadata(c2.paths.bin_dir.join(n)).is_err());
    }
    assert_eq!(markers(&c2), 0, "markers are removed with the shims");
}

/// A shim that the user replaced after setup is not ours to remove, upgrade or not.
#[test]
fn replaced_shim_is_kept_even_with_our_record() {
    let d = tempfile::tempdir().unwrap();
    let exe = d.path().join("f2c.bin");
    std::fs::write(&exe, b"fail2commit v1").unwrap();
    let c = ctx(d.path(), &exe);
    let shim = pip::integration().unwrap();
    let owned = shim.install(&c).unwrap();
    for n in names() {
        let p = c.paths.bin_dir.join(n);
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"user's own wrapper").unwrap();
    }
    std::fs::write(&exe, b"fail2commit v2").unwrap();
    shim.uninstall(&c, &owned).unwrap();
    for n in names() {
        assert_eq!(
            std::fs::read(c.paths.bin_dir.join(n)).unwrap(),
            b"user's own wrapper"
        );
    }
    assert!(
        shim.install(&c).is_err(),
        "setup still refuses a foreign file"
    );
}
