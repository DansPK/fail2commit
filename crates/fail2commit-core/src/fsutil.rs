//! Private, atomic, locked state files (CHORE-001, frozen).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Create `dir` (and parents) readable only by the current user.
/// Windows: directories under %APPDATA%/%LOCALAPPDATA% inherit a user-only
/// DACL; T-002 may tighten explicitly. Unix: mode 0700.
pub fn ensure_private_dir(dir: &Path) -> crate::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to `path` atomically: temp file in the same directory,
/// fsync, rename over the target. A crash leaves the old or new file only.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| crate::Error::internal("state path has no parent"))?;
    ensure_private_dir(dir)?;
    let mut tmp = tempfile::Builder::new().prefix(".f2c-").tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| crate::Error::from(e.error))?;
    Ok(())
}

/// Hold an exclusive advisory lock on `<path>.lock` while `f` runs.
pub fn with_lock<T>(path: &Path, f: impl FnOnce() -> crate::Result<T>) -> crate::Result<T> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock_path = std::path::PathBuf::from(lock_path);
    if let Some(dir) = lock_path.parent() {
        ensure_private_dir(dir)?;
    }
    let file: File = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)?;
    file.lock()?;
    let out = f();
    let _ = file.unlock();
    out
}

/// Read a file of at most `max` bytes; larger files are an error, not a
/// silent truncation.
pub fn read_bounded(path: &Path, max: u64) -> crate::Result<Vec<u8>> {
    use std::io::Read;
    let f = File::open(path)?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(crate::Error::invalid(format!(
            "{} exceeds {max} bytes",
            path.display()
        )));
    }
    Ok(buf)
}

/// The plain DOS form of a canonical path: the extended `\\?\` prefix removed,
/// and `\\?\UNC\server` restored to `\\server`. Use it for paths handed to a
/// child process (CreateProcessW, cmd.exe and Node 22's main-script resolution
/// reject `\\?\`); containment checks keep the canonical form.
pub fn plain_path(path: &Path) -> std::path::PathBuf {
    let text = path.as_os_str().to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) => match rest.strip_prefix("UNC\\") {
            Some(unc) => format!(r"\\{unc}").into(),
            None => rest.into(),
        },
        None => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_path_strips_only_the_extended_prefix() {
        assert_eq!(
            plain_path(Path::new(r"\\?\C:\a\b.js")),
            Path::new(r"C:\a\b.js")
        );
        assert_eq!(
            plain_path(Path::new(r"\\?\UNC\srv\s\x")),
            Path::new(r"\\srv\s\x")
        );
        assert_eq!(
            plain_path(Path::new("/usr/bin/node")),
            Path::new("/usr/bin/node")
        );
    }

    #[test]
    fn atomic_write_replaces_and_locks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub").join("state.json");
        atomic_write(&p, b"one").unwrap();
        with_lock(&p, || atomic_write(&p, b"two")).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert!(read_bounded(&p, 2).is_err());
        assert_eq!(read_bounded(&p, 3).unwrap(), b"two");
    }
}
