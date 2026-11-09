//! Resolve real tool executables outside our shims (CHORE-001, frozen).
//!
//! Repo-defined tool paths are untrusted, so only PATH is consulted, and any
//! entry inside the shim dir or resolving to our own executable is skipped
//! to avoid recursion.

use std::path::{Path, PathBuf};

/// Find `name` (e.g. "git") on PATH, skipping `skip_dir` and any file that
/// canonicalizes to the current executable. Windows: tries PATHEXT `.exe`
/// and `.com` only, never `.bat`/`.cmd` (cmd.exe interpolation risk).
pub fn find_real(name: &str, skip_dir: Option<&Path>) -> crate::Result<PathBuf> {
    let path = std::env::var_os("PATH").ok_or_else(|| crate::Error::internal("PATH is not set"))?;
    let me = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    let skip = skip_dir.and_then(|d| d.canonicalize().ok());
    for dir in std::env::split_paths(&path) {
        if !dir.is_absolute() {
            continue; // relative PATH entries resolve against an untrusted cwd
        }
        if let (Some(s), Ok(c)) = (&skip, dir.canonicalize()) {
            if &c == s {
                continue;
            }
        }
        for cand in candidates(&dir, name) {
            if !cand.is_file() {
                continue;
            }
            let canon = cand.canonicalize().unwrap_or_else(|_| cand.clone());
            if me.as_ref() == Some(&canon) {
                continue;
            }
            return Ok(canon);
        }
    }
    Err(crate::Error::invalid(format!(
        "{name} was not found on PATH outside fail2commit shims"
    )))
}

#[cfg(windows)]
fn candidates(dir: &Path, name: &str) -> Vec<PathBuf> {
    // "cmd.exe" is a bare name too; only .exe/.com are ever accepted as-is.
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".exe") || lower.ends_with(".com") {
        return vec![dir.join(name)];
    }
    vec![
        dir.join(format!("{name}.exe")),
        dir.join(format!("{name}.com")),
    ]
}

#[cfg(not(windows))]
fn candidates(dir: &Path, name: &str) -> Vec<PathBuf> {
    vec![dir.join(name)]
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_git_and_skips_dir() {
        // git is a hard prerequisite of the dev environment.
        let git = super::find_real("git", None).expect("git on PATH");
        let dir = git.parent().unwrap().to_path_buf();
        if let Ok(other) = super::find_real("git", Some(&dir)) {
            assert_ne!(other.parent().unwrap(), dir);
        }
    }

    #[cfg(windows)]
    #[test]
    fn explicit_exe_suffix_resolves_but_scripts_never_do() {
        let git = super::find_real("git", None).expect("git on PATH");
        assert_eq!(super::find_real("git.exe", None).unwrap(), git);
        assert_eq!(super::find_real("GIT.EXE", None).unwrap(), git);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tool.cmd"), "@echo off").unwrap();
        assert!(super::candidates(dir.path(), "tool.cmd")
            .iter()
            .all(|c| !c.is_file()));
    }
}
