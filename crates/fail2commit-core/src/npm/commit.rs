//! Journaled commit and recovery (SPEC-004). The verified tree is built in a
//! scratch directory next to the project; committing swaps it in with
//! renames. A journal under trusted state records what is needed to restore
//! the original project byte-for-byte if the process dies half way.

use crate::paths::TrustedPaths;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

/// Test seam: simulate the process dying after a commit step (no rollback).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    AfterJournal,
    AfterBackup,
    AfterSwap,
    AfterFiles,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Building,
    Committing,
    Committed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Journal {
    version: u32,
    project: PathBuf,
    apply_dir: PathBuf,
    backup: PathBuf,
    had_nm: bool,
    had_lock: bool,
    phase: Phase,
}

pub fn project_key(project: &Path) -> String {
    hex::encode(Sha256::digest(project.to_string_lossy().as_bytes()))
}

fn state_root(paths: &TrustedPaths) -> PathBuf {
    paths.state_dir.join("npm")
}

/// Path whose `.lock` sibling serializes operations on one project.
pub fn lock_path(paths: &TrustedPaths, project: &Path) -> PathBuf {
    state_root(paths).join(project_key(project))
}

fn jdir(paths: &TrustedPaths, project: &Path) -> PathBuf {
    lock_path(paths, project)
}

fn write_journal(dir: &Path, j: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(j).map_err(|e| Error::internal(e.to_string()))?;
    crate::fsutil::atomic_write(&dir.join("journal.json"), &bytes)
}

/// Record that a scratch tree exists so a crash can clean it up.
pub fn begin(paths: &TrustedPaths, project: &Path, apply_dir: &Path) -> Result<()> {
    let dir = jdir(paths, project);
    crate::fsutil::ensure_private_dir(&dir)?;
    write_journal(
        &dir,
        &Journal {
            version: 1,
            project: project.to_path_buf(),
            apply_dir: apply_dir.to_path_buf(),
            backup: apply_dir.with_extension("old"),
            had_nm: false,
            had_lock: false,
            phase: Phase::Building,
        },
    )
}

/// Drop the scratch tree and journal after a failed or cancelled build.
pub fn abandon(paths: &TrustedPaths, project: &Path, apply_dir: &Path) {
    let _ = std::fs::remove_dir_all(apply_dir);
    let _ = std::fs::remove_dir_all(jdir(paths, project));
}

/// Replace `path` with `bytes`, keeping the original file's permissions.
pub fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".f2c-tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes)?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(())
}

fn remove_any(p: &Path) {
    if p.is_dir() {
        let _ = std::fs::remove_dir_all(p);
    } else if p.exists() {
        let _ = std::fs::remove_file(p);
    }
}

fn restore_file(project: &Path, orig: &Path, name: &str, had: bool) -> Result<()> {
    let target = project.join(name);
    if had {
        let want = std::fs::read(orig.join(name))?;
        if std::fs::read(&target).ok().as_deref() != Some(&want) {
            replace_file(&target, &want)?;
        }
    } else if target.exists() {
        std::fs::remove_file(&target)?;
    }
    Ok(())
}

fn rollback(paths: &TrustedPaths, j: &Journal) -> Result<()> {
    let dir = jdir(paths, &j.project);
    let nm = j.project.join("node_modules");
    if j.phase == Phase::Committing {
        if j.backup.exists() {
            remove_any(&nm); // ours: the swap happened
            std::fs::rename(&j.backup, &nm)?;
        } else if !j.had_nm {
            remove_any(&nm);
        }
        let orig = dir.join("orig");
        restore_file(&j.project, &orig, "package.json", true)?;
        restore_file(&j.project, &orig, "package-lock.json", j.had_lock)?;
    }
    remove_any(&j.apply_dir);
    remove_any(&dir);
    Ok(())
}

/// Finish or undo an interrupted apply. Returns a note when one was found.
/// Callers hold the project lock.
pub fn recover(paths: &TrustedPaths, project: &Path) -> Result<Option<String>> {
    let dir = jdir(paths, project);
    let file = dir.join("journal.json");
    if !file.is_file() {
        return Ok(None);
    }
    let bytes = crate::fsutil::read_bounded(&file, 1024 * 1024)?;
    let j: Journal = serde_json::from_slice(&bytes)
        .map_err(|e| Error::internal(format!("npm journal is unreadable: {e}")))?;
    if j.project != project {
        return Err(Error::internal("npm journal belongs to another project"));
    }
    let note = match j.phase {
        Phase::Committed => {
            remove_any(&j.backup);
            remove_any(&j.apply_dir);
            remove_any(&dir);
            "completed an interrupted npm apply".to_string()
        }
        _ => {
            rollback(paths, &j)?;
            "rolled back an interrupted npm apply; the project is as it was before".to_string()
        }
    };
    Ok(Some(note))
}

pub struct Commit<'a> {
    pub project: &'a Path,
    pub apply_dir: &'a Path,
    pub package_json: &'a [u8],
    pub lock: &'a [u8],
}

/// Swap the verified tree into the project. Any failure rolls back.
pub fn commit(paths: &TrustedPaths, c: &Commit<'_>, crash: Option<CrashPoint>) -> Result<()> {
    let dir = jdir(paths, c.project);
    let nm = c.project.join("node_modules");
    let new_nm = c.apply_dir.join("node_modules");
    if !new_nm.is_dir() {
        std::fs::create_dir(&new_nm)?; // a graph with no packages
    }
    let orig = dir.join("orig");
    crate::fsutil::ensure_private_dir(&orig)?;
    let pj = c.project.join("package.json");
    let lock = c.project.join("package-lock.json");
    std::fs::copy(&pj, orig.join("package.json"))?;
    let had_lock = lock.is_file();
    if had_lock {
        std::fs::copy(&lock, orig.join("package-lock.json"))?;
    }
    let mut j = Journal {
        version: 1,
        project: c.project.to_path_buf(),
        apply_dir: c.apply_dir.to_path_buf(),
        backup: c.apply_dir.with_extension("old"),
        had_nm: nm.exists(),
        had_lock,
        phase: Phase::Committing,
    };
    write_journal(&dir, &j)?;
    let crashed = |p: CrashPoint| -> Option<Error> {
        (crash == Some(p)).then(|| Error::internal(format!("simulated crash {p:?}")))
    };
    let steps = || -> Result<Option<Error>> {
        if let Some(e) = crashed(CrashPoint::AfterJournal) {
            return Ok(Some(e));
        }
        if j.had_nm {
            std::fs::rename(&nm, &j.backup)?;
        }
        if let Some(e) = crashed(CrashPoint::AfterBackup) {
            return Ok(Some(e));
        }
        std::fs::rename(&new_nm, &nm)?;
        if let Some(e) = crashed(CrashPoint::AfterSwap) {
            return Ok(Some(e));
        }
        for (path, bytes) in [(&pj, c.package_json), (&lock, c.lock)] {
            if std::fs::read(path).ok().as_deref() != Some(bytes) {
                replace_file(path, bytes)?;
            }
        }
        Ok(crashed(CrashPoint::AfterFiles))
    };
    match steps() {
        Ok(Some(crash_err)) => Err(crash_err), // process "died": leave the journal behind
        Ok(None) => {
            j.phase = Phase::Committed;
            write_journal(&dir, &j)?;
            remove_any(&j.backup);
            remove_any(&j.apply_dir);
            remove_any(&dir);
            Ok(())
        }
        Err(e) => {
            rollback(paths, &j)?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        fn walk(d: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
            let mut es: Vec<_> = std::fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            es.sort();
            for p in es {
                if p.is_dir() {
                    walk(&p, root, out);
                } else {
                    out.push((
                        p.strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                        std::fs::read(&p).unwrap(),
                    ));
                }
            }
        }
        walk(root, root, &mut out);
        out
    }

    fn setup() -> (tempfile::TempDir, TrustedPaths, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let paths = TrustedPaths::under(&d.path().join("home"));
        let proj = d.path().join("proj");
        std::fs::create_dir_all(proj.join("node_modules/old")).unwrap();
        std::fs::write(proj.join("node_modules/old/index.js"), "old").unwrap();
        std::fs::write(proj.join("package.json"), "{\"name\":\"p\"}").unwrap();
        std::fs::write(proj.join("package-lock.json"), "LOCK0").unwrap();
        let apply = proj.join(".f2c-npm-test");
        std::fs::create_dir_all(apply.join("node_modules/new")).unwrap();
        std::fs::write(apply.join("node_modules/new/index.js"), "new").unwrap();
        (d, paths, proj.canonicalize().unwrap(), apply)
    }

    #[test]
    fn commit_and_every_crash_point_recovers() {
        for crash in [
            None,
            Some(CrashPoint::AfterJournal),
            Some(CrashPoint::AfterBackup),
            Some(CrashPoint::AfterSwap),
            Some(CrashPoint::AfterFiles),
        ] {
            let (_d, paths, proj, apply) = setup();
            let before = tree(&proj.join("node_modules"));
            let apply = proj.join(apply.file_name().unwrap());
            begin(&paths, &proj, &apply).unwrap();
            let c = Commit {
                project: &proj,
                apply_dir: &apply,
                package_json: b"{\"name\":\"p\",\"x\":1}",
                lock: b"LOCK1",
            };
            let r = commit(&paths, &c, crash);
            match crash {
                None => {
                    r.unwrap();
                    assert_eq!(
                        std::fs::read(proj.join("package-lock.json")).unwrap(),
                        b"LOCK1"
                    );
                    assert!(proj.join("node_modules/new/index.js").is_file());
                    assert!(!proj.join("node_modules/old").exists());
                    assert!(!apply.exists() && recover(&paths, &proj).unwrap().is_none());
                }
                Some(_) => {
                    assert!(r.is_err());
                    let note = recover(&paths, &proj).unwrap().expect("journal present");
                    assert!(note.contains("rolled back"), "{note}");
                    assert_eq!(tree(&proj.join("node_modules")), before, "{crash:?}");
                    assert_eq!(
                        std::fs::read(proj.join("package.json")).unwrap(),
                        b"{\"name\":\"p\"}"
                    );
                    assert_eq!(
                        std::fs::read(proj.join("package-lock.json")).unwrap(),
                        b"LOCK0"
                    );
                    assert!(!apply.exists());
                    assert!(recover(&paths, &proj).unwrap().is_none());
                }
            }
        }
    }

    #[test]
    fn project_without_node_modules_or_lock_rolls_back_clean() {
        let (_d, paths, proj, apply) = setup();
        std::fs::remove_dir_all(proj.join("node_modules")).unwrap();
        std::fs::remove_file(proj.join("package-lock.json")).unwrap();
        let apply = proj.join(apply.file_name().unwrap());
        begin(&paths, &proj, &apply).unwrap();
        let c = Commit {
            project: &proj,
            apply_dir: &apply,
            package_json: b"{\"name\":\"p\"}",
            lock: b"L",
        };
        assert!(commit(&paths, &c, Some(CrashPoint::AfterFiles)).is_err());
        recover(&paths, &proj).unwrap().unwrap();
        assert!(!proj.join("node_modules").exists());
        assert!(!proj.join("package-lock.json").exists());
    }
}
