//! `pip` / `pip3` shims in the fail2commit bin dir. PATH ordering is handled
//! by the Git integration (T-001); these files only need to exist there.
//! The CLI maps the shim's file name to `fail2commit pip`.

use crate::integration::{Integration, IntegrationStatus, OwnedChange, SetupCtx};
use crate::Error;
use std::path::{Path, PathBuf};

pub const ID: &str = "pip";

pub struct PipShim;

fn shim_names() -> [&'static str; 2] {
    if cfg!(windows) {
        ["pip.exe", "pip3.exe"]
    } else {
        ["pip", "pip3"]
    }
}

fn sha(path: &Path) -> Option<String> {
    use sha2::{Digest as _, Sha256};
    std::fs::read(path)
        .ok()
        .map(|b| hex::encode(Sha256::digest(b)))
}

/// Is the file at `shim` the fail2commit shim for `exe`? Same test as the npm shim.
fn is_ours(exe: &Path, shim: &Path) -> bool {
    if cfg!(windows) {
        sha(shim).is_some() && sha(shim) == sha(exe)
    } else {
        std::fs::read_link(shim).is_ok_and(|l| l == exe)
    }
}

/// What the shim at a path looked like when fail2commit placed it: the
/// SHA-256 of the copy (Windows) or the symlink target (Unix).
fn state_of(shim: &Path) -> Option<String> {
    if cfg!(windows) {
        sha(shim)
    } else {
        std::fs::read_link(shim)
            .ok()
            .map(|l| l.to_string_lossy().into_owned())
    }
}

/// Ownership marker kept in the trusted state dir, one per shim (RP-005).
/// It survives an in-place upgrade of fail2commit, which changes the
/// executable the shim is compared with but not the shim itself.
fn marker_path(ctx: &SetupCtx, name: &str) -> PathBuf {
    ctx.paths
        .state_dir
        .join("pip")
        .join(format!("shim-{name}.json"))
}

fn write_marker(ctx: &SetupCtx, name: &str, shim: &Path) -> crate::Result<()> {
    let m = serde_json::json!({ "owner": "fail2commit", "name": name, "state": state_of(shim) });
    crate::fsutil::atomic_write(&marker_path(ctx, name), m.to_string().as_bytes())
}

/// Does the marker for `name` describe exactly the file now at `shim`?
fn marked(ctx: &SetupCtx, name: &str, shim: &Path) -> bool {
    let Ok(bytes) = crate::fsutil::read_bounded(&marker_path(ctx, name), 4096) else {
        return false;
    };
    let Ok(m) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    m["owner"] == "fail2commit"
        && m["name"] == name
        && m["state"].as_str().is_some()
        && m["state"].as_str().map(str::to_owned) == state_of(shim)
}

/// Create the shim, never replacing a file that is not ours (W2-006). A shim
/// of ours that points at an older executable is refreshed.
fn place(ctx: &SetupCtx, name: &str, shim: &Path) -> crate::Result<()> {
    if std::fs::symlink_metadata(shim).is_ok() {
        if is_ours(&ctx.exe, shim) {
            return write_marker(ctx, name, shim);
        }
        if !marked(ctx, name, shim) {
            return Err(Error::invalid(format!(
                "{} already exists and is not a fail2commit shim; not replacing it",
                shim.display()
            )));
        }
        std::fs::remove_file(shim)?; // our own older shim
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&ctx.exe, shim)?;
    #[cfg(not(unix))]
    std::fs::copy(&ctx.exe, shim)?;
    write_marker(ctx, name, shim)
}

impl Integration for PipShim {
    fn id(&self) -> &'static str {
        ID
    }

    fn install(&self, ctx: &SetupCtx) -> crate::Result<Vec<OwnedChange>> {
        let mut changes = Vec::new();
        // Check every shim first so a foreign file leaves nothing half done.
        for name in shim_names() {
            let shim = ctx.paths.bin_dir.join(name);
            if std::fs::symlink_metadata(&shim).is_ok()
                && !is_ours(&ctx.exe, &shim)
                && !marked(ctx, name, &shim)
            {
                return Err(Error::invalid(format!(
                    "{} already exists and is not a fail2commit shim; not replacing it",
                    shim.display()
                )));
            }
        }
        for name in shim_names() {
            let shim = ctx.paths.bin_dir.join(name);
            if !ctx.dry_run {
                crate::fsutil::ensure_private_dir(&ctx.paths.bin_dir)?;
                place(ctx, name, &shim)?;
            }
            changes.push(OwnedChange {
                integration: ID.into(),
                kind: "shim".into(),
                path: Some(shim),
                detail: serde_json::json!({
                    "target": ctx.exe,
                    "mode": if cfg!(windows) { "copy" } else { "symlink" },
                    "sha256": sha(&ctx.exe),
                }),
            });
        }
        Ok(changes)
    }

    fn uninstall(&self, ctx: &SetupCtx, owned: &[OwnedChange]) -> crate::Result<()> {
        for c in owned
            .iter()
            .filter(|c| c.integration == ID && c.kind == "shim")
        {
            let Some(p) = &c.path else { continue };
            // Only files inside our own bin dir are ever removed.
            if p.parent() != Some(ctx.paths.bin_dir.as_path()) {
                return Err(Error::invalid(format!(
                    "refusing to remove {} outside the fail2commit bin dir",
                    p.display()
                )));
            }
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
            let name = name.unwrap_or_default();
            // Ours when the marker written at setup still describes the file, or
            // the setup record's own hash/target does (older state): never by
            // comparing with the current executable, which an upgrade changes.
            let recorded = if cfg!(windows) {
                c.detail["sha256"].as_str().map(str::to_owned)
            } else {
                c.detail["target"].as_str().map(str::to_owned)
            };
            let ours = marked(ctx, &name, p) || (recorded.is_some() && recorded == state_of(p));
            if !ours {
                continue; // replaced since setup: not ours to remove
            }
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let _ = std::fs::remove_file(marker_path(ctx, &name));
        }
        Ok(())
    }

    fn status(&self, ctx: &SetupCtx) -> IntegrationStatus {
        let missing: Vec<PathBuf> = shim_names()
            .iter()
            .map(|n| ctx.paths.bin_dir.join(n))
            .filter(|p| std::fs::symlink_metadata(p).is_err())
            .collect();
        IntegrationStatus {
            id: ID.into(),
            installed: missing.is_empty(),
            detail: if missing.is_empty() {
                "pip and pip3 shims present".into()
            } else {
                format!("{} shim(s) missing", missing.len())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::TrustedPaths;

    #[test]
    fn install_status_uninstall() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("fail2commit-fake");
        std::fs::write(&exe, b"x").unwrap();
        let ctx = SetupCtx {
            paths: TrustedPaths::under(&d.path().join("home")),
            exe,
            dry_run: false,
        };
        let s = PipShim;
        assert!(!s.status(&ctx).installed);
        let owned = s.install(&ctx).unwrap();
        assert_eq!(owned.len(), 2);
        assert!(s.status(&ctx).installed);
        s.uninstall(&ctx, &owned).unwrap();
        assert!(!s.status(&ctx).installed);
        // a record pointing outside the bin dir is refused
        let evil = OwnedChange {
            path: Some(d.path().join("keep.txt")),
            ..owned[0].clone()
        };
        std::fs::write(d.path().join("keep.txt"), b"k").unwrap();
        assert!(s.uninstall(&ctx, &[evil]).is_err());
        assert!(d.path().join("keep.txt").exists());
    }

    #[test]
    fn foreign_file_is_neither_replaced_nor_removed() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("fail2commit-fake");
        std::fs::write(&exe, b"x").unwrap();
        let ctx = SetupCtx {
            paths: TrustedPaths::under(&d.path().join("home")),
            exe,
            dry_run: false,
        };
        let s = PipShim;
        let owned = s.install(&ctx).unwrap();
        assert_eq!(s.install(&ctx).unwrap().len(), 2, "re-run is a no-op");
        s.uninstall(&ctx, &owned).unwrap();

        std::fs::create_dir_all(&ctx.paths.bin_dir).unwrap();
        let pip3 = ctx.paths.bin_dir.join(shim_names()[1]);
        std::fs::write(&pip3, b"user's own pip3 wrapper").unwrap();
        let e = s.install(&ctx).unwrap_err();
        assert_eq!(e.code, crate::ResultCode::InvalidInput);
        assert_eq!(std::fs::read(&pip3).unwrap(), b"user's own pip3 wrapper");
        assert!(
            std::fs::symlink_metadata(ctx.paths.bin_dir.join(shim_names()[0])).is_err(),
            "nothing was placed before the refusal"
        );
        s.uninstall(&ctx, &owned).unwrap();
        assert_eq!(std::fs::read(&pip3).unwrap(), b"user's own pip3 wrapper");
    }
}
