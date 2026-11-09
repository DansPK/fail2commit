//! `npm` shim integration (SPEC-004). The shim is the fail2commit binary
//! itself under the name `npm`; `main` maps that name to `fail2commit npm`.
//! PATH ordering is handled by the Git integration (T-001).

use crate::integration::{Integration, IntegrationStatus, OwnedChange, SetupCtx};
use crate::{Error, Result};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

pub struct NpmShim;

fn shim_path(ctx: &SetupCtx) -> PathBuf {
    ctx.paths
        .bin_dir
        .join(if cfg!(windows) { "npm.exe" } else { "npm" })
}

fn sha(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|b| hex::encode(Sha256::digest(b)))
}

impl Integration for NpmShim {
    fn id(&self) -> &'static str {
        "npm"
    }

    fn install(&self, ctx: &SetupCtx) -> Result<Vec<OwnedChange>> {
        let target = shim_path(ctx);
        let exe_sha = sha(&ctx.exe);
        let mode = if cfg!(windows) { "copy" } else { "symlink" };
        let change = OwnedChange {
            integration: self.id().into(),
            kind: "shim".into(),
            path: Some(target.clone()),
            detail: serde_json::json!({ "mode": mode, "exe": ctx.exe, "sha256": exe_sha }),
        };
        let exists = std::fs::symlink_metadata(&target).is_ok();
        let ours = || {
            if cfg!(windows) {
                sha(&target).is_some() && sha(&target) == exe_sha
            } else {
                std::fs::read_link(&target).is_ok_and(|l| l == ctx.exe)
            }
        };
        if exists && !ours() {
            return Err(Error::invalid(format!(
                "{} already exists and is not a fail2commit shim; not replacing it",
                target.display()
            )));
        }
        if ctx.dry_run || exists {
            return Ok(vec![change]);
        }
        crate::fsutil::ensure_private_dir(&ctx.paths.bin_dir)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&ctx.exe, &target)?;
        #[cfg(windows)]
        std::fs::copy(&ctx.exe, &target)?;
        Ok(vec![change])
    }

    fn uninstall(&self, _ctx: &SetupCtx, owned: &[OwnedChange]) -> Result<()> {
        for c in owned.iter().filter(|c| c.kind == "shim") {
            let Some(p) = &c.path else { continue };
            let still_ours = if c.detail["mode"] == "copy" {
                sha(p).is_some() && sha(p).as_deref() == c.detail["sha256"].as_str()
            } else {
                std::fs::read_link(p).is_ok_and(|l| {
                    Some(l.to_string_lossy().into_owned()).as_deref() == c.detail["exe"].as_str()
                })
            };
            if still_ours {
                std::fs::remove_file(p)?;
            }
        }
        Ok(())
    }

    fn status(&self, ctx: &SetupCtx) -> IntegrationStatus {
        let p = shim_path(ctx);
        IntegrationStatus {
            id: self.id().into(),
            installed: std::fs::symlink_metadata(&p).is_ok(),
            detail: format!("npm shim at {}", p.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent_and_uninstall_only_removes_ours() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join(if cfg!(windows) {
            "fail2commit.exe"
        } else {
            "fail2commit"
        });
        std::fs::write(&exe, b"binary").unwrap();
        let ctx = SetupCtx {
            paths: crate::paths::TrustedPaths::under(&d.path().join("home")),
            exe,
            dry_run: false,
        };
        let s = NpmShim;
        let dry = SetupCtx {
            dry_run: true,
            paths: ctx.paths.clone(),
            exe: ctx.exe.clone(),
        };
        s.install(&dry).unwrap();
        assert!(!s.status(&ctx).installed, "dry run writes nothing");
        let owned = s.install(&ctx).unwrap();
        assert!(s.status(&ctx).installed);
        assert_eq!(s.install(&ctx).unwrap(), owned, "re-run is a no-op");
        s.uninstall(&ctx, &owned).unwrap();
        assert!(!s.status(&ctx).installed);

        // A foreign file is neither replaced nor removed.
        std::fs::create_dir_all(&ctx.paths.bin_dir).unwrap();
        let foreign = shim_path(&ctx);
        std::fs::write(&foreign, b"user's own npm wrapper").unwrap();
        assert!(s.install(&ctx).is_err());
        s.uninstall(&ctx, &owned).unwrap();
        assert_eq!(std::fs::read(&foreign).unwrap(), b"user's own npm wrapper");
    }
}
