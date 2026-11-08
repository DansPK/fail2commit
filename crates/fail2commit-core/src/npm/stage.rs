//! CR-007: the read-only toolchain for sandboxed lifecycle scripts, staged next
//! to the npm staging tree (the writable work dir) inside one job stage.

use super::runner::Toolchain;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Tools {
    pub toolchain: Toolchain,
    /// Read-only roots: staged node, npm and (Windows) the command shell.
    pub read_only: Vec<PathBuf>,
    /// Staged `cmd.exe`; `None` where `/bin/sh` is a system tool.
    pub shell: Option<PathBuf>,
}

impl Tools {
    /// Copy the toolchain into `<stage_dir>/tools`. `stage_dir` is the npm
    /// staging directory itself, a direct child of `<cache_dir>/sandbox-stage`
    /// that the caller removes; the lifecycle work dir is its `proj` tree.
    pub fn create(stage_dir: &Path, tc: &Toolchain) -> Result<Tools> {
        let tools = stage_dir.join("tools");
        let node_dir = tools.join("node");
        fs::create_dir_all(&node_dir)?;
        let node = node_dir.join(tc.node.file_name().unwrap_or_default());
        fs::copy(&tc.node, &node)?;
        let mut t = Tools {
            toolchain: Toolchain {
                node,
                npm_cli: tc.npm_cli.clone(),
            },
            read_only: vec![node_dir],
            shell: None,
        };
        if let Some(root) = tc.npm_root() {
            let npm = tools.join("npm");
            fs::create_dir(&npm)?;
            copy_tree(root, &npm)?;
            let rel = tc
                .npm_cli
                .strip_prefix(root)
                .map_err(|_| Error::internal("npm-cli.js is not below the npm root"))?;
            t.toolchain.npm_cli = npm.join(rel);
            t.read_only.push(npm);
        }
        #[cfg(windows)]
        {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
            let sys = tools.join("sys");
            fs::create_dir(&sys)?;
            let cmd = sys.join("cmd.exe");
            fs::copy(Path::new(&root).join("System32").join("cmd.exe"), &cmd)?;
            t.shell = Some(cmd);
            t.read_only.push(sys);
        }
        Ok(t)
    }
}

/// Recursive copy that never follows links. Symlinks are recreated as links on
/// Unix (npm's `.bin`); any link or special file elsewhere is refused.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let (from, to) = (entry.path(), dst.join(entry.file_name()));
        let md = fs::symlink_metadata(&from)?;
        if is_link(&md) {
            copy_link(&from, &to)?;
        } else if md.is_dir() {
            fs::create_dir(&to)?;
            copy_tree(&from, &to)?;
        } else if md.is_file() {
            fs::copy(&from, &to)?;
        } else {
            return Err(Error::rejected(format!(
                "special file in install tree: {}",
                from.display()
            )));
        }
    }
    Ok(())
}

fn is_link(md: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if md.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    md.file_type().is_symlink()
}

#[cfg(unix)]
fn copy_link(from: &Path, to: &Path) -> Result<()> {
    std::os::unix::fs::symlink(fs::read_link(from)?, to)?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_link(from: &Path, _to: &Path) -> Result<()> {
    Err(Error::rejected(format!(
        "link or junction in install tree: {}",
        from.display()
    )))
}

/// A job stage not touched for this long is a leftover of a killed run.
const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);

/// ER-005: remove `npm-*` and `run-*` stages under `root` (the
/// `sandbox-stage` directory) that are older than an hour, holding the
/// per-user sandbox lock so no job is mid-flight. Best effort: failures are
/// ignored and other entries (such as backend state files) are never touched.
pub fn sweep_stale(root: &Path) {
    let Ok(paths) = crate::paths::TrustedPaths::resolve() else {
        return;
    };
    let lock = paths.state_dir.join("sandbox-job");
    let _ = crate::fsutil::with_lock(&lock, || {
        sweep_older_than(root, STALE_AFTER);
        Ok(())
    });
}

fn sweep_older_than(root: &Path, age: std::time::Duration) {
    let Ok(rd) = fs::read_dir(root) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("npm-") || name.starts_with("run-")) {
            continue;
        }
        let stale = e
            .metadata()
            .ok()
            .filter(|m| m.is_dir() && !is_link(m))
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|d| d >= age);
        if stale {
            remove_tree(&e.path());
        }
    }
}

/// Remove a stage, making read-only entries sandbox code left behind writable
/// first when the plain removal fails.
pub(crate) fn remove_tree(p: &Path) {
    if fs::remove_dir_all(p).is_err() {
        make_writable(p);
        let _ = fs::remove_dir_all(p);
    }
}

fn make_writable(p: &Path) {
    let Ok(md) = fs::symlink_metadata(p) else {
        return;
    };
    if md.is_dir() && !is_link(&md) {
        let mut perm = md.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perm.set_mode(0o700);
        }
        #[cfg(not(unix))]
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        let _ = fs::set_permissions(p, perm);
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                make_writable(&e.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweeps_only_old_stage_dirs() {
        let root = tempfile::tempdir().unwrap();
        for n in ["npm-old", "run-old", "keep-me", "npm-fresh"] {
            fs::create_dir(root.path().join(n)).unwrap();
            fs::write(root.path().join(n).join("f"), "x").unwrap();
        }
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        for n in ["npm-old", "run-old", "keep-me"] {
            let mut o = fs::OpenOptions::new();
            o.write(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                o.custom_flags(0x0200_0000); // FILE_FLAG_BACKUP_SEMANTICS: open a directory
            }
            #[cfg(unix)]
            o.read(true).write(false);
            o.open(root.path().join(n))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        sweep_older_than(root.path(), STALE_AFTER);
        assert!(!root.path().join("npm-old").exists());
        assert!(!root.path().join("run-old").exists());
        assert!(
            root.path().join("npm-fresh").exists(),
            "younger than an hour"
        );
        assert!(root.path().join("keep-me").exists(), "not a stage name");
    }
}
