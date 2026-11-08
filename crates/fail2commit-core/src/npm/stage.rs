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
