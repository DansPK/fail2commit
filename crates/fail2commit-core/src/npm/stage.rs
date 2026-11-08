//! CR-007: the sandbox job stage for lifecycle scripts. Every stage is a direct
//! child of `<cache_dir>/sandbox-stage`; the staged toolchain is the read-only
//! input and a copy of the install tree is the writable work dir. The copy is
//! merged back only after every script exited 0.

use super::runner::Toolchain;
use crate::paths::TrustedPaths;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub struct JobStage {
    dir: PathBuf,
    pub toolchain: Toolchain,
    /// Read-only roots: staged node, npm and (Windows) the command shell.
    pub read_only: Vec<PathBuf>,
    pub work: PathBuf,
    /// Staged `cmd.exe`; `None` where `/bin/sh` is a system tool.
    pub shell: Option<PathBuf>,
}

impl JobStage {
    pub fn create(paths: &TrustedPaths, tc: &Toolchain, tree: &Path) -> Result<JobStage> {
        let root = paths.cache_dir.join("sandbox-stage");
        crate::fsutil::ensure_private_dir(&root)?;
        let dir = tempfile::Builder::new()
            .prefix("npm-")
            .tempdir_in(&root)?
            .keep();
        let mut s = JobStage {
            work: dir.join("work"),
            dir,
            toolchain: tc.clone(),
            read_only: Vec::new(),
            shell: None,
        };
        // On error `s` drops and removes the stage.
        s.fill(tc, tree)?;
        Ok(s)
    }

    fn fill(&mut self, tc: &Toolchain, tree: &Path) -> Result<()> {
        let node_dir = self.dir.join("node");
        fs::create_dir(&node_dir)?;
        let node = node_dir.join(tc.node.file_name().unwrap_or_default());
        fs::copy(&tc.node, &node)?;
        self.read_only.push(node_dir);
        let mut staged = Toolchain {
            node,
            npm_cli: tc.npm_cli.clone(),
        };
        if let Some(root) = tc.npm_root() {
            let npm = self.dir.join("npm");
            fs::create_dir(&npm)?;
            copy_tree(root, &npm)?;
            let rel = tc
                .npm_cli
                .strip_prefix(root)
                .map_err(|_| Error::internal("npm-cli.js is not below the npm root"))?;
            staged.npm_cli = npm.join(rel);
            self.read_only.push(npm);
        }
        self.toolchain = staged;
        #[cfg(windows)]
        {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
            let sys = self.dir.join("sys");
            fs::create_dir(&sys)?;
            let cmd = sys.join("cmd.exe");
            fs::copy(Path::new(&root).join("System32").join("cmd.exe"), &cmd)?;
            self.shell = Some(cmd);
            self.read_only.push(sys);
        }
        fs::create_dir(&self.work)?;
        copy_tree(tree, &self.work)
    }

    /// Replace `tree` with the stage's work copy (all scripts succeeded).
    pub fn merge_back(&self, tree: &Path) -> Result<()> {
        for e in fs::read_dir(tree)? {
            let p = e?.path();
            if fs::symlink_metadata(&p)?.is_dir() {
                fs::remove_dir_all(&p)?;
            } else {
                fs::remove_file(&p)?;
            }
        }
        copy_tree(&self.work, tree)
    }
}

impl Drop for JobStage {
    fn drop(&mut self) {
        if fs::remove_dir_all(&self.dir).is_err() {
            // Sandbox code ran as this user and may have left read-only dirs.
            make_writable(&self.dir);
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

fn make_writable(p: &Path) {
    let Ok(md) = fs::symlink_metadata(p) else {
        return;
    };
    if md.is_dir() {
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
