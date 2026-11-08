//! Offline apply from the reviewed wheel set, with a recovery journal.
//!
//! The reviewed directory holds exactly the planned wheels. Each is installed
//! with `--no-index --no-deps --require-hashes`, so pip cannot re-resolve,
//! reach an index, or accept different bytes. Progress is journaled. A journal
//! is never rolled forward implicitly (W2-002, CR-002): while one exists for an
//! interpreter, guarded installs stop, and `fail2commit pip recover` either
//! completes it after a fresh approval or discards it.
//!
//! The journal is keyed by the interpreter's canonical identity (RP-006) and
//! lives only under `paths.state_dir`. It is validated whenever it is read
//! (RP-007, RP-008): identity, plan digest recomputed from the journal's own
//! plan inputs, wheel names and hashes, and `reviewed` confined to the
//! fail2commit-owned reviewed-wheel directory. A journal that fails is refused
//! with a message offering `recover --discard`; it still blocks installs.

use super::guard::Guard;
use super::interp::{Cancel, Interpreter, RunLimits};
use super::plan::PlanWheel;
use crate::paths::TrustedPaths;
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const JOURNAL_VERSION: u32 = 2;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub version: u32,
    /// How the user spelled the interpreter when the plan was made. Display only;
    /// the journal is found and checked by `identity`.
    pub python: String,
    pub identity: String,
    /// The interpreter facts the plan digest was computed over.
    pub interpreter: Interpreter,
    pub index: String,
    pub requested: Vec<String>,
    pub digest: String,
    pub reviewed: PathBuf,
    pub wheels: Vec<PlanWheel>,
    /// Wheels already installed, in plan order.
    pub done: usize,
    /// Set when apply stopped at a wheel boundary because it was canceled.
    #[serde(default)]
    pub cancelled: bool,
}

pub type BeforeWheel = Box<dyn Fn(usize, &PlanWheel) -> crate::Result<()>>;

/// Test seam: runs before each wheel is installed; an error simulates a
/// crash at that point (the journal is left behind, as after a real one).
#[derive(Default)]
pub struct ApplyHooks {
    pub before_wheel: Option<BeforeWheel>,
}

/// `state_dir/pip/journal-<hash of the canonical identity>.json`.
pub fn journal_path(paths: &TrustedPaths, identity: &str) -> PathBuf {
    let id = hex::encode(&Sha256::digest(identity.as_bytes())[..8]);
    paths
        .state_dir
        .join("pip")
        .join(format!("journal-{id}.json"))
}

fn reviewed_root(paths: &TrustedPaths) -> PathBuf {
    paths.cache_dir.join("pip").join("reviewed")
}

fn refused(paths: &TrustedPaths, interp: &Interpreter, why: &str) -> Error {
    Error::integrity(format!(
        "the pip journal {} is not trusted ({why}); nothing was installed. Run `fail2commit pip --python \"{}\" recover --discard` to drop it",
        journal_path(paths, &interp.identity).display(),
        interp.executable
    ))
}

/// Everything a journal claims must be consistent with itself, with the
/// interpreter asked about, and with the directories fail2commit owns.
fn validate(paths: &TrustedPaths, interp: &Interpreter, j: &Journal) -> Result<(), String> {
    if j.version != JOURNAL_VERSION {
        return Err("unknown journal version".into());
    }
    if j.identity != interp.identity || j.interpreter.identity != interp.identity {
        return Err("it was written for a different interpreter".into());
    }
    if j.done > j.wheels.len() {
        return Err("inconsistent progress".into());
    }
    let hex_ok = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex_ok(&j.digest, 64) {
        return Err("malformed plan digest".into());
    }
    let root = reviewed_root(paths);
    let name_ok = j.reviewed.file_name().is_some_and(|n| {
        let n = n.to_string_lossy();
        hex_ok(&n, 16)
    });
    if j.reviewed.parent() != Some(root.as_path()) || !name_ok {
        return Err("its wheel directory is outside the fail2commit cache".into());
    }
    for w in &j.wheels {
        let plain = Path::new(&w.filename)
            .file_name()
            .is_some_and(|n| n == w.filename.as_str())
            && !w.filename.contains(['/', '\\', ':']);
        let named = super::wheel::parse_filename(&w.filename).is_some_and(|(n, _)| n == w.name);
        if !plain || !named || !hex_ok(&w.sha256, 64) {
            return Err(format!("wheel entry {} is malformed", w.filename));
        }
    }
    let expected = super::plan::plan_digest(&j.interpreter, &j.index, &j.requested, &j.wheels)
        .map_err(|e| e.message)?;
    if !expected.matches(&j.digest) {
        return Err("it does not match the plan digest that was approved".into());
    }
    Ok(())
}

/// Is there a journal file (trusted or not) for this interpreter's environment?
pub fn journal_exists(paths: &TrustedPaths, interp: &Interpreter) -> bool {
    journal_path(paths, &interp.identity).exists()
}

pub fn read_journal(paths: &TrustedPaths, interp: &Interpreter) -> crate::Result<Option<Journal>> {
    let p = journal_path(paths, &interp.identity);
    if !p.exists() {
        return Ok(None);
    }
    let bytes = crate::fsutil::read_bounded(&p, 4 * 1024 * 1024)
        .map_err(|e| refused(paths, interp, &e.message))?;
    let j: Journal = serde_json::from_slice(&bytes)
        .map_err(|e| refused(paths, interp, &format!("unreadable: {e}")))?;
    validate(paths, interp, &j).map_err(|why| refused(paths, interp, &why))?;
    Ok(Some(j))
}

/// Delete a reviewed-wheel directory, but only one under our own cache.
fn remove_reviewed(paths: &TrustedPaths, dir: &Path) {
    let root = reviewed_root(paths);
    let plain = dir
        .components()
        .all(|c| !matches!(c, std::path::Component::ParentDir));
    if plain && dir.starts_with(&root) && dir != root {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Drop a pending journal (valid or not) and, when it was trusted, its
/// reviewed wheels. Installed wheels stay.
pub fn discard(paths: &TrustedPaths, identity: &str, trusted: Option<&Journal>) {
    let _ = std::fs::remove_file(journal_path(paths, identity));
    if let Some(j) = trusted {
        remove_reviewed(paths, &j.reviewed);
    }
}

fn write_journal(paths: &TrustedPaths, j: &Journal) -> crate::Result<()> {
    let bytes = serde_json::to_vec(j).map_err(|e| Error::internal(e.to_string()))?;
    crate::fsutil::atomic_write(&journal_path(paths, &j.identity), &bytes)
}

fn sha256_file(p: &Path) -> crate::Result<String> {
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

/// Copy the staged wheels into a fresh directory, re-hashing as we go.
pub fn materialize(
    paths: &TrustedPaths,
    wheels: &[(PlanWheel, PathBuf)],
) -> crate::Result<PathBuf> {
    let root = reviewed_root(paths);
    crate::fsutil::ensure_private_dir(&root)?;
    let dir = root.join(&crate::digest::random_hex32()?[..16]);
    crate::fsutil::ensure_private_dir(&dir)?;
    for (w, src) in wheels {
        let dest = dir.join(&w.filename);
        std::fs::copy(src, &dest)?;
        if sha256_file(&dest)? != w.sha256 {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(Error::integrity(format!(
                "{} changed while staging",
                w.filename
            )));
        }
    }
    Ok(dir)
}

/// The directory must hold exactly the reviewed files with the reviewed
/// bytes: a substituted, added or modified wheel invalidates the plan.
pub fn verify_reviewed(dir: &Path, wheels: &[PlanWheel]) -> crate::Result<()> {
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| Error::integrity(format!("reviewed set unreadable: {e}")))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    let mut want: Vec<String> = wheels.iter().map(|w| w.filename.clone()).collect();
    want.sort();
    if found != want {
        return Err(Error::integrity(
            "the reviewed wheel set changed (files added or removed); plan invalidated",
        ));
    }
    for w in wheels {
        let p = dir.join(&w.filename);
        let meta = std::fs::symlink_metadata(&p)?;
        if !meta.is_file() || meta.len() != w.size || sha256_file(&p)? != w.sha256 {
            return Err(Error::integrity(format!(
                "{} no longer matches the reviewed hash; plan invalidated",
                w.filename
            )));
        }
    }
    Ok(())
}

/// Arguments after `-m pip` for one offline install. No index, no
/// dependency resolution, hashes required.
pub fn apply_args(reviewed: &Path, hashes_file: &Path) -> Vec<OsString> {
    let mut a: Vec<OsString> = [
        "install",
        "--no-index",
        "--no-deps",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-cache-dir",
        "--find-links",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    a.push(reviewed.into());
    a.push("-r".into());
    a.push(hashes_file.into());
    a
}

pub struct ApplyCtx<'a> {
    pub paths: &'a TrustedPaths,
    pub interp: &'a Interpreter,
    pub guard: &'a Guard,
    pub limits: &'a RunLimits,
    pub cancel: &'a Cancel,
    pub hooks: &'a ApplyHooks,
}

/// What the plan digest was computed over besides the wheels; stored in the
/// journal so a later `recover` can recompute it.
pub struct PlanInputs<'a> {
    pub digest: &'a str,
    pub index: &'a str,
    pub requested: &'a [String],
}

/// Journal, install every wheel in order, verify, then clear the journal.
/// Refuses to start while another journal exists for the interpreter.
pub fn apply(
    cx: &ApplyCtx<'_>,
    plan: &PlanInputs<'_>,
    reviewed: &Path,
    wheels: &[PlanWheel],
) -> crate::Result<()> {
    let journal = Journal {
        version: JOURNAL_VERSION,
        python: cx.interp.executable.clone(),
        identity: cx.interp.identity.clone(),
        interpreter: cx.interp.clone(),
        index: plan.index.to_string(),
        requested: plan.requested.to_vec(),
        digest: plan.digest.to_string(),
        reviewed: reviewed.to_path_buf(),
        wheels: wheels.to_vec(),
        done: 0,
        cancelled: false,
    };
    let jp = journal_path(cx.paths, &journal.identity);
    crate::fsutil::with_lock(&jp, || {
        if let Some(other) = read_journal(cx.paths, cx.interp)? {
            return Err(pending_error(&other));
        }
        write_journal(cx.paths, &journal)?;
        run_journal(cx, journal, true)
    })
}

/// The error every guarded install raises while a journal exists.
pub fn pending_error(j: &Journal) -> Error {
    Error::invalid(format!(
        "an earlier pip install into {py} is unfinished ({done} of {total} wheels installed{why}); run `fail2commit pip --python \"{py}\" recover` to review and finish it, or add --discard to drop it",
        py = j.python,
        done = j.done,
        total = j.wheels.len(),
        why = if j.cancelled { ", canceled" } else { "" },
    ))
}

/// Continue a journal that the caller has already had approved. The reviewed
/// set is re-verified byte for byte first.
pub fn resume(cx: &ApplyCtx<'_>, mut j: Journal) -> crate::Result<()> {
    j.cancelled = false;
    run_journal(cx, j, false)
}

/// The reviewed set must still be exactly what the journal lists.
pub fn verify_pending(cx: &ApplyCtx<'_>, j: &Journal) -> crate::Result<()> {
    verify_reviewed(&j.reviewed, &j.wheels).map_err(|e| {
        Error::integrity(format!(
            "{} (journal: {})",
            e.message,
            journal_path(cx.paths, &j.identity).display()
        ))
    })
}

/// `fresh`: this call just created the journal, so a cancel before the first
/// wheel changes nothing and leaves no journal behind.
fn run_journal(cx: &ApplyCtx<'_>, mut j: Journal, fresh: bool) -> crate::Result<()> {
    verify_pending(cx, &j)?;
    let hashes_dir = cx.paths.state_dir.join("pip");
    crate::fsutil::ensure_private_dir(&hashes_dir)?;
    // A cancel is honored only between wheels: a pip that is already
    // installing one is allowed to finish, never killed half way.
    let never: super::interp::Cancel =
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let inner = ApplyCtx {
        cancel: &never,
        ..*cx
    };
    for i in j.done..j.wheels.len() {
        if cx.cancel.load(std::sync::atomic::Ordering::SeqCst) {
            if fresh && j.done == 0 {
                discard(cx.paths, &j.identity, Some(&j));
                return Err(Error::rejected("canceled; nothing was installed"));
            }
            j.cancelled = true;
            write_journal(cx.paths, &j)?;
            return Err(Error::rejected(format!(
                "canceled after {} of {} wheels; the journal was kept: run `fail2commit pip recover` to finish or `recover --discard` to drop it",
                j.done,
                j.wheels.len()
            )));
        }
        let w = &j.wheels[i];
        if let Some(h) = &cx.hooks.before_wheel {
            h(i, w)?;
        }
        let hf = hashes_dir.join(format!("hashes-{:.16}.txt", j.digest));
        std::fs::write(&hf, w.hash_line())?;
        // The snapshot is re-verified by `Guard::pip` before this launch.
        let mut cmd = cx
            .guard
            .pip(&["--isolated", "--disable-pip-version-check", "--no-input"])?;
        cmd.args(apply_args(&j.reviewed, &hf));
        let out = super::interp::run(&mut cmd, cx.limits, &never);
        let _ = std::fs::remove_file(&hf);
        let out = out?;
        if out.status != Some(0) {
            return Err(Error::internal(format!(
                "offline install of {} failed: {}",
                w.filename,
                super::interp::tail(&out.stderr)
            )));
        }
        j.done = i + 1;
        write_journal(cx.paths, &j)?;
    }
    verify_installed(&inner, &j.wheels)?;
    let _ = std::fs::remove_file(journal_path(cx.paths, &j.identity));
    remove_reviewed(cx.paths, &j.reviewed);
    Ok(())
}

/// The environment must now contain exactly the planned versions, as recorded
/// by the `dist-info` directories on disk. Nothing from it is imported.
pub fn verify_installed(cx: &ApplyCtx<'_>, wheels: &[PlanWheel]) -> crate::Result<()> {
    let installed = cx.interp.installed(cx.limits, cx.cancel)?;
    for w in wheels {
        let ok = installed
            .iter()
            .any(|(n, v)| *n == w.name && v.eq_ignore_ascii_case(&w.version));
        if !ok {
            return Err(Error::integrity(format!(
                "{}=={} is not installed as planned (substitution or failed install)",
                w.name, w.version
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_uses_no_index_and_no_resolution() {
        let a: Vec<String> = apply_args(Path::new("/r"), Path::new("/h.txt"))
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        for must in [
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--find-links",
        ] {
            assert!(a.iter().any(|x| x == must), "{must}");
        }
        assert!(!a
            .iter()
            .any(|x| x.contains("index-url") || x == "--upgrade"));
        let fl = a.iter().position(|x| x == "--find-links").unwrap();
        assert_eq!(a[fl + 1], "/r");
    }

    #[test]
    fn reviewed_set_detects_changes() {
        let d = tempfile::tempdir().unwrap();
        let bytes = b"wheel bytes";
        let w = PlanWheel {
            name: "a".into(),
            version: "1".into(),
            filename: "a-1-py3-none-any.whl".into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        std::fs::write(d.path().join(&w.filename), bytes).unwrap();
        verify_reviewed(d.path(), std::slice::from_ref(&w)).unwrap();
        std::fs::write(d.path().join("extra-1-py3-none-any.whl"), b"x").unwrap();
        assert!(verify_reviewed(d.path(), std::slice::from_ref(&w)).is_err());
        std::fs::remove_file(d.path().join("extra-1-py3-none-any.whl")).unwrap();
        std::fs::write(d.path().join(&w.filename), b"tampered!!!").unwrap();
        let e = verify_reviewed(d.path(), std::slice::from_ref(&w)).unwrap_err();
        assert_eq!(e.code, crate::ResultCode::IntegrityFailure);
    }
}
