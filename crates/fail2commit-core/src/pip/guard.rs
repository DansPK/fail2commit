//! The guard's own pip (RP-003).
//!
//! Every pip invocation the guard makes runs from a private snapshot of the
//! target environment's `pip` package, never from the environment itself. A
//! wheel can overwrite files of other distributions, so importing the
//! environment's pip would let package code run inside the guard, outside any
//! sandbox and without approval. The snapshot is taken before anything is
//! installed, lives under `paths.cache_dir`, and a SHA-256 manifest is
//! re-verified before every launch; any difference is an `IntegrityFailure`.

use super::interp::{pip_command, python_c, run, Cancel, RunLimits};
use crate::paths::TrustedPaths;
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const MANIFEST: &str = "manifest.json";

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    /// Relative path (forward slashes) to SHA-256.
    files: BTreeMap<String, String>,
}

/// A verified-on-demand snapshot of the target environment's pip.
#[derive(Debug, Clone)]
pub struct Guard {
    exe: PathBuf,
    dir: PathBuf,
    files: BTreeMap<String, String>,
}

fn sha256_file(p: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(hex::encode(h.finalize()));
        }
        h.update(&buf[..n]);
    }
}

/// Every regular file under `root`, relative with `/`. Symlinks and special
/// files are an error: the snapshot never contains them.
fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for e in rd {
        let e = e.map_err(|e| e.to_string())?;
        let p = e.path();
        let meta = std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if meta.is_dir() {
            walk(root, &p, out)?;
        } else if meta.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let h = sha256_file(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            out.insert(rel, h);
        } else {
            return Err(format!("{} is not a regular file", p.display()));
        }
    }
    Ok(())
}

/// Copy `src` into `dst`, skipping `__pycache__` and refusing symlinks.
fn copy_tree(src: &Path, dst: &Path) -> crate::Result<()> {
    crate::fsutil::ensure_private_dir(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let (from, to) = (e.path(), dst.join(e.file_name()));
        let meta = std::fs::symlink_metadata(&from)?;
        if meta.is_dir() {
            if e.file_name() != "__pycache__" {
                copy_tree(&from, &to)?;
            }
        } else if meta.is_file() {
            std::fs::copy(&from, &to)?;
        } else {
            return Err(Error::invalid(format!(
                "{} is a symlink or special file; the guard will not snapshot it",
                from.display()
            )));
        }
    }
    Ok(())
}

impl Guard {
    /// The directory placed first on `sys.path` for the guard's pip.
    pub fn site(&self) -> PathBuf {
        self.dir.join("site")
    }

    /// Take the snapshot for `identity` if none exists, else verify the one
    /// that does. `site_dirs` are where the target's pip may live.
    pub fn ensure(
        paths: &TrustedPaths,
        exe: &Path,
        identity: &str,
        site_dirs: &[String],
        limits: &RunLimits,
        cancel: &Cancel,
    ) -> crate::Result<Guard> {
        let root = paths.cache_dir.join("pip").join("guard");
        crate::fsutil::ensure_private_dir(&root)?;
        let id = hex::encode(&Sha256::digest(identity.as_bytes())[..8]);
        let dir = root.join(&id);
        crate::fsutil::with_lock(&dir, || {
            if dir.join(MANIFEST).is_file() {
                let g = Guard::load(exe, &dir)?;
                g.verify()?;
                return Ok(g);
            }
            // A crashed earlier build leaves no manifest: start over.
            let _ = std::fs::remove_dir_all(&dir);
            Guard::build(exe, &dir, site_dirs, limits, cancel)
        })
    }

    fn load(exe: &Path, dir: &Path) -> crate::Result<Guard> {
        let bytes = crate::fsutil::read_bounded(&dir.join(MANIFEST), 16 * 1024 * 1024)?;
        let m: Manifest = serde_json::from_slice(&bytes)
            .map_err(|e| Error::integrity(format!("pip guard manifest unreadable: {e}")))?;
        if m.version != 1 {
            return Err(Error::integrity(
                "pip guard manifest has an unknown version",
            ));
        }
        Ok(Guard {
            exe: exe.to_path_buf(),
            dir: dir.to_path_buf(),
            files: m.files,
        })
    }

    fn build(
        exe: &Path,
        dir: &Path,
        site_dirs: &[String],
        limits: &RunLimits,
        cancel: &Cancel,
    ) -> crate::Result<Guard> {
        let no_pip = || Error::invalid(format!("no pip package found in {}", site_dirs.join(", ")));
        let found = site_dirs
            .iter()
            .map(Path::new)
            .find(|d| d.join("pip").join("__init__.py").is_file())
            .ok_or_else(no_pip)?;
        if !found
            .join("pip")
            .join("_vendor")
            .join("requests")
            .join("__init__.py")
            .is_file()
        {
            return Err(Error::invalid(
                "pip in this environment is distribution-unbundled (its vendored libraries live outside the pip package); use a venv with the standard pip",
            ));
        }
        let site = dir.join("site");
        crate::fsutil::ensure_private_dir(&site)?;
        copy_tree(&found.join("pip"), &site.join("pip"))?;
        for e in std::fs::read_dir(found)? {
            let e = e?;
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            if n.starts_with("pip-") && n.ends_with(".dist-info") && e.path().is_dir() {
                copy_tree(&e.path(), &site.join(e.file_name()))?;
            }
        }
        // Precompile once so each launch starts fast with `dont_write_bytecode`.
        // The bytecode is part of the manifest.
        let mut cmd = crate::winenv::command(exe);
        cmd.args(["-I", "-S", "-m", "compileall", "-q"]).arg(&site);
        let _ = run(&mut cmd, limits, cancel)?;
        let mut files = BTreeMap::new();
        walk(&site, &site, &mut files).map_err(Error::integrity)?;
        let m = Manifest { version: 1, files };
        let bytes = serde_json::to_vec(&m).map_err(|e| Error::internal(e.to_string()))?;
        crate::fsutil::atomic_write(&dir.join(MANIFEST), &bytes)?;
        Ok(Guard {
            exe: exe.to_path_buf(),
            dir: dir.to_path_buf(),
            files: m.files,
        })
    }

    /// The snapshot must still be byte for byte what was taken.
    pub fn verify(&self) -> crate::Result<()> {
        let mut now = BTreeMap::new();
        let broken = |why: String| {
            Error::integrity(format!(
                "the fail2commit pip snapshot {} changed ({why}); refusing to run it. Delete that directory to take a fresh snapshot",
                self.dir.display()
            ))
        };
        walk(&self.site(), &self.site(), &mut now).map_err(broken)?;
        if now != self.files {
            let why = now
                .iter()
                .find(|(k, v)| self.files.get(*k) != Some(*v))
                .map(|(k, _)| k.clone())
                .or_else(|| self.files.keys().find(|k| !now.contains_key(*k)).cloned())
                .unwrap_or_default();
            return Err(broken(format!("{why} differs from the manifest")));
        }
        Ok(())
    }

    /// `python -I -S -c <BOOT + pip-from-snapshot + body>`, after re-verifying.
    pub fn python_c(&self, body: &str) -> crate::Result<Command> {
        self.verify()?;
        Ok(python_c(&self.exe, Some(&self.site()), body))
    }

    /// The snapshot's pip with the given leading flags, after re-verifying.
    pub fn pip(&self, flags: &[&str]) -> crate::Result<Command> {
        self.verify()?;
        Ok(pip_command(&self.exe, &self.site(), flags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_detects_changed_added_and_removed_files() {
        let d = tempfile::tempdir().unwrap();
        let site = d.path().join("site");
        std::fs::create_dir_all(site.join("pip")).unwrap();
        std::fs::write(site.join("pip").join("a.py"), b"a").unwrap();
        let mut files = BTreeMap::new();
        walk(&site, &site, &mut files).unwrap();
        let g = Guard {
            exe: PathBuf::from("python"),
            dir: d.path().to_path_buf(),
            files,
        };
        g.verify().unwrap();
        std::fs::write(site.join("pip").join("b.py"), b"b").unwrap();
        assert_eq!(
            g.verify().unwrap_err().code,
            crate::ResultCode::IntegrityFailure
        );
        std::fs::remove_file(site.join("pip").join("b.py")).unwrap();
        std::fs::write(site.join("pip").join("a.py"), b"tampered").unwrap();
        assert_eq!(
            g.verify().unwrap_err().code,
            crate::ResultCode::IntegrityFailure
        );
        std::fs::remove_file(site.join("pip").join("a.py")).unwrap();
        assert!(g.verify().is_err());
    }
}
