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

fn place(exe: &Path, shim: &Path) -> crate::Result<()> {
    if std::fs::symlink_metadata(shim).is_ok() {
        std::fs::remove_file(shim)?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(exe, shim)?;
    #[cfg(not(unix))]
    std::fs::copy(exe, shim)?;
    Ok(())
}

impl Integration for PipShim {
    fn id(&self) -> &'static str {
        ID
    }

    fn install(&self, ctx: &SetupCtx) -> crate::Result<Vec<OwnedChange>> {
        let mut changes = Vec::new();
        for name in shim_names() {
            let shim = ctx.paths.bin_dir.join(name);
            if !ctx.dry_run {
                crate::fsutil::ensure_private_dir(&ctx.paths.bin_dir)?;
                place(&ctx.exe, &shim)?;
            }
            changes.push(OwnedChange {
                integration: ID.into(),
                kind: "shim".into(),
                path: Some(shim),
                detail: serde_json::json!({ "target": ctx.exe }),
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
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
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
}
