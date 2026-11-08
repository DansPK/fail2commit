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

/// The one place every guard `git` subprocess (scanner, classifier,
/// pre-push, server pre-receive ancestry) gets its environment. Repository
/// state must not change what the guard sees (R1-001):
/// - `GIT_NO_REPLACE_OBJECTS`: `refs/replace/*` could swap a secret blob for a
///   clean one in `cat-file`/`log` while a push still sends the real object.
///   Git also ignores `info/grafts` under this switch where it reads them.
/// - `core.commitGraph=false`: a forged commit-graph file is a repository
///   controlled cache that could alter traversal.
/// - `core.fsmonitor=false`: a repository config value there names a program.
/// - `log.showSignature=false`: with it on, `git log` runs the repository's
///   `gpg.program` (R2-003).
/// - `GIT_NO_LAZY_FETCH`: a partial clone must not start a network fetch.
/// - no prompts, no optional locks.
pub(crate) fn command(git: &Path, repo: &Path) -> Command {
    let mut c = Command::new(git);
    c.current_dir(repo)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_CONFIG_COUNT", "3")
        .env("GIT_CONFIG_KEY_0", "core.commitGraph")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_1", "false")
        .env("GIT_CONFIG_KEY_2", "log.showSignature")
        .env("GIT_CONFIG_VALUE_2", "false")
        .env_remove("GIT_REPLACE_REF_BASE")
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
