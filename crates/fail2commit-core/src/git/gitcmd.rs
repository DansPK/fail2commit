//! Small, hardened wrapper around the real `git` binary (structured args,
//! never a shell). Output of untrusted repositories is parsed as bytes.

use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) struct GitOut {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
}

impl GitOut {
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_string()
    }
}

pub(crate) fn command(git: &Path, repo: &Path) -> Command {
    let mut c = Command::new(git);
    c.current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    c
}

/// Run `git <args>` in `repo`, capturing stdout (small queries only).
pub(crate) fn run(git: &Path, repo: &Path, args: &[&str]) -> crate::Result<GitOut> {
    let out = command(git, repo)
        .args(args)
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| crate::Error::internal(format!("cannot run git: {e}")))?;
    Ok(GitOut {
        status: out.status.code(),
        stdout: out.stdout,
    })
}

/// Valid object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
pub(crate) fn valid_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn check_oid(s: &str) -> crate::Result<()> {
    if valid_oid(s) {
        Ok(())
    } else {
        Err(crate::Error::invalid("malformed object id from Git"))
    }
}

/// Object type of `oid` if present locally (`commit`, `tag`, ...).
pub(crate) fn object_type(git: &Path, repo: &Path, oid: &str) -> crate::Result<Option<String>> {
    check_oid(oid)?;
    let o = run(git, repo, &["cat-file", "-t", oid])?;
    Ok(o.ok().then(|| o.text()))
}
