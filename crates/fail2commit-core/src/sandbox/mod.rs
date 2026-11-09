//! T-007 (FR-007, SPEC-007) owns this directory. Split ownership:
//! `linux.rs`, this `mod.rs` and the export step: T-007a (Bubblewrap).
//! `windows.rs`: T-007b (sandboxrs-windows AppContainer).
//!
//! Frozen API: [`platform_backend`], [`run_job`].

use crate::isolation::{JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// Linux backend, public so tests can simulate a missing install
/// (`Bubblewrap::with_bwrap`) or force the rlimit-only path.
#[cfg(target_os = "linux")]
pub use linux::Bubblewrap;

/// The backend for this platform. Unsupported platforms get a backend whose
/// probe reports unavailable, so callers fail closed.
pub fn platform_backend() -> Box<dyn SandboxBackend> {
    #[cfg(target_os = "linux")]
    return Box::new(linux::Bubblewrap::default());
    #[cfg(windows)]
    return Box::new(windows::AppContainer);
    #[allow(unreachable_code)]
    Box::new(Unavailable)
}

/// Probe, run, then export declared paths only after a clean exit.
/// Backends never export themselves.
pub fn run_job(backend: &dyn SandboxBackend, job: &JobSpec) -> crate::Result<JobOutcome> {
    // SPEC-012: one active sandbox build per user; later jobs wait their turn.
    let lock = crate::paths::TrustedPaths::resolve()?
        .state_dir
        .join("sandbox-job");
    crate::fsutil::with_lock(&lock, || run_job_locked(backend, job))
}

fn run_job_locked(backend: &dyn SandboxBackend, job: &JobSpec) -> crate::Result<JobOutcome> {
    let probe = backend.probe();
    if !probe.available {
        return Err(crate::Error::isolation_unavailable(format!(
            "{}: {}",
            probe.backend, probe.detail
        )));
    }
    let mut outcome = backend.run(job)?;
    if outcome.status == JobStatus::Exited(0) && job.export_to.is_some() && !job.exports.is_empty()
    {
        outcome.exported = export(job)?;
    }
    Ok(outcome)
}

/// Total bytes one job may export; matches the default
/// `settings.limits.artifact_max_bytes` (the job spec carries no artifact cap).
const EXPORT_MAX_BYTES: u64 = 512 * 1024 * 1024;
/// Files plus directories one job may export.
const EXPORT_MAX_ENTRIES: usize = 100_000;

/// Copy `job.exports` from `job.work_dir` to `job.export_to`, rejecting
/// links, reparse points, paths escaping the work dir and oversized output.
fn export(job: &JobSpec) -> crate::Result<Vec<PathBuf>> {
    export_capped(job, EXPORT_MAX_BYTES)
}

/// One validated export entry, relative to both roots.
enum Entry {
    Dir(PathBuf),
    File(PathBuf, u64),
}

fn rejected(what: &str, rel: &Path) -> crate::Error {
    crate::Error::rejected(format!("export {}: {what}", rel.display()))
}

fn export_capped(job: &JobSpec, max_bytes: u64) -> crate::Result<Vec<PathBuf>> {
    let Some(dest_root) = job.export_to.as_deref() else {
        return Ok(Vec::new());
    };
    // Everything below work_dir was written by untrusted code. Every sandbox
    // process has stopped (backend contract), so the tree cannot change
    // between this validation and the copy.
    let src_root = job.work_dir.canonicalize()?;
    let mut plan = Vec::new();
    let mut total = 0u64;
    for rel in &job.exports {
        check_relative(rel)?;
        // Ancestors inside the work dir must be real directories, not links.
        let parts: Vec<_> = rel.components().collect();
        let mut cur = PathBuf::new();
        for part in &parts[..parts.len() - 1] {
            cur.push(part);
            let md = fs::symlink_metadata(src_root.join(&cur))
                .map_err(|_| rejected("does not exist", rel))?;
            if classify(&md, &src_root.join(&cur), rel)? != Kind::Dir {
                return Err(rejected("a parent is not a directory", rel));
            }
            plan.push(Entry::Dir(cur.clone()));
        }
        walk(&src_root, rel.clone(), &mut plan, &mut total, max_bytes)?;
    }
    if plan.len() > EXPORT_MAX_ENTRIES {
        return Err(crate::Error::rejected(format!(
            "export has more than {EXPORT_MAX_ENTRIES} entries"
        )));
    }
    fs::create_dir_all(dest_root)?;
    let mut created = Vec::new();
    let result = copy_plan(&src_root, dest_root, &plan, &mut created);
    if result.is_err() {
        // Leave nothing half-exported.
        for p in created.iter().rev() {
            let _ = fs::remove_file(p).or_else(|_| fs::remove_dir(p));
        }
    }
    result
}

/// Relative, non-empty, and only plain names (no `..`, `.`, root or prefix).
fn check_relative(rel: &Path) -> crate::Result<()> {
    let ok =
        !rel.as_os_str().is_empty() && rel.components().all(|c| matches!(c, Component::Normal(_)));
    if ok {
        Ok(())
    } else {
        Err(rejected(
            "must be a plain relative path inside the work dir",
            rel,
        ))
    }
}

#[derive(PartialEq, Eq)]
enum Kind {
    Dir,
    File,
}

fn classify(md: &fs::Metadata, path: &Path, rel: &Path) -> crate::Result<Kind> {
    if md.file_type().is_symlink() {
        return Err(rejected("symbolic links are not exported", rel));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(rejected("reparse points are not exported", rel));
        }
    }
    if md.is_dir() {
        return Ok(Kind::Dir);
    }
    if !md.is_file() {
        return Err(rejected("special files are not exported", rel));
    }
    if link_count(md, path)? > 1 {
        return Err(rejected("hard-linked files are not exported", rel));
    }
    Ok(Kind::File)
}

#[cfg(unix)]
fn link_count(md: &fs::Metadata, _path: &Path) -> crate::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(md.nlink())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn link_count(_md: &fs::Metadata, path: &Path) -> crate::Result<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let f = fs::File::open(path)?;
    // SAFETY: `f` owns a valid handle for the duration of the call and
    // `info` is a writable, correctly sized out parameter.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(u64::from(info.nNumberOfLinks))
}

#[cfg(not(any(unix, windows)))]
fn link_count(_md: &fs::Metadata, _path: &Path) -> crate::Result<u64> {
    Err(crate::Error::isolation_unavailable("unsupported platform"))
}

fn walk(
    src_root: &Path,
    rel: PathBuf,
    plan: &mut Vec<Entry>,
    total: &mut u64,
    max_bytes: u64,
) -> crate::Result<()> {
    let path = src_root.join(&rel);
    let md = fs::symlink_metadata(&path).map_err(|_| rejected("does not exist", &rel))?;
    match classify(&md, &path, &rel)? {
        Kind::File => {
            *total = total.saturating_add(md.len());
            if *total > max_bytes {
                return Err(crate::Error::rejected(format!(
                    "export exceeds {max_bytes} bytes"
                )));
            }
            plan.push(Entry::File(rel, md.len()));
        }
        Kind::Dir => {
            plan.push(Entry::Dir(rel.clone()));
            let mut names = Vec::new();
            for e in fs::read_dir(&path)? {
                names.push(e?.file_name());
                if names.len() > EXPORT_MAX_ENTRIES {
                    return Err(rejected("directory has too many entries", &rel));
                }
            }
            names.sort();
            for n in names {
                walk(src_root, rel.join(n), plan, total, max_bytes)?;
                if plan.len() > EXPORT_MAX_ENTRIES {
                    return Err(crate::Error::rejected(format!(
                        "export has more than {EXPORT_MAX_ENTRIES} entries"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn copy_plan(
    src_root: &Path,
    dest_root: &Path,
    plan: &[Entry],
    created: &mut Vec<PathBuf>,
) -> crate::Result<Vec<PathBuf>> {
    use std::io::Read;
    let mut exported = Vec::new();
    for entry in plan {
        match entry {
            Entry::Dir(rel) => {
                let dest = dest_root.join(rel);
                match fs::symlink_metadata(&dest) {
                    // The destination may be an untrusted checkout: never
                    // follow a link placed there.
                    Ok(md) if md.is_dir() && classify(&md, &dest, rel).is_ok() => {}
                    Ok(_) => return Err(rejected("destination is not a plain directory", rel)),
                    Err(_) => {
                        fs::create_dir(&dest)?;
                        created.push(dest);
                    }
                }
            }
            Entry::File(rel, len) => {
                let dest = dest_root.join(rel);
                let src = fs::File::open(src_root.join(rel))?;
                // create_new refuses existing files and dangling links alike.
                let mut out = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dest)
                    .map_err(|e| rejected(&format!("cannot create destination: {e}"), rel))?;
                created.push(dest.clone());
                let n = std::io::copy(&mut src.take(len + 1), &mut out)?;
                if n != *len {
                    return Err(rejected("changed size while exporting", rel));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(src_root.join(rel))?.permissions().mode() & 0o755;
                    out.set_permissions(fs::Permissions::from_mode(mode))?;
                }
                exported.push(dest);
            }
        }
    }
    Ok(exported)
}

/// Fallback backend: never runs anything.
pub struct Unavailable;

impl SandboxBackend for Unavailable {
    fn probe(&self) -> ProbeReport {
        ProbeReport {
            backend: "unavailable",
            available: false,
            detail: "no sandbox backend for this platform".into(),
            controls: vec![],
        }
    }
    fn run(&self, _job: &JobSpec) -> crate::Result<JobOutcome> {
        Err(crate::Error::isolation_unavailable(
            "no sandbox backend for this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::JobLimits;
    use crate::ResultCode;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn job(work: &Path, to: &Path, exports: &[&str]) -> JobSpec {
        JobSpec {
            program: PathBuf::from("/nonexistent"),
            args: vec![],
            cwd: work.to_path_buf(),
            env: vec![],
            read_only: vec![],
            work_dir: work.to_path_buf(),
            exports: exports.iter().map(PathBuf::from).collect(),
            export_to: Some(to.to_path_buf()),
            limits: JobLimits {
                timeout: Duration::from_secs(1),
                memory_bytes: None,
                max_processes: None,
                max_output_bytes: 1024,
            },
        }
    }

    fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let work = d.path().join("work");
        let to = d.path().join("out");
        fs::create_dir_all(work.join("dist/sub")).unwrap();
        fs::write(work.join("dist/app.bin"), b"binary").unwrap();
        fs::write(work.join("dist/sub/x.txt"), b"x").unwrap();
        fs::write(work.join("other.txt"), b"not exported").unwrap();
        (d, work, to)
    }

    fn code(r: crate::Result<Vec<PathBuf>>) -> ResultCode {
        r.expect_err("export must be rejected").code
    }

    #[test]
    fn exports_declared_files_and_dirs_only() {
        let (_d, work, to) = dirs();
        let got = export(&job(&work, &to, &["dist"])).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(fs::read(to.join("dist/app.bin")).unwrap(), b"binary");
        assert_eq!(fs::read(to.join("dist/sub/x.txt")).unwrap(), b"x");
        assert!(!to.join("other.txt").exists());
        let got = export(&job(&work, &to.join("2"), &["dist/sub/x.txt"])).unwrap();
        assert_eq!(got, vec![to.join("2/dist/sub/x.txt")]);
    }

    #[test]
    fn rejects_escaping_and_missing_paths() {
        let (_d, work, to) = dirs();
        for bad in [
            "../work/other.txt",
            "dist/../other.txt",
            "./dist",
            "missing",
        ] {
            assert_eq!(
                code(export(&job(&work, &to, &[bad]))),
                ResultCode::Rejected,
                "{bad}"
            );
        }
        let abs = work.join("other.txt");
        assert_eq!(
            code(export(&job(&work, &to, &[abs.to_str().unwrap()]))),
            ResultCode::Rejected
        );
        assert!(!to.join("other.txt").exists());
    }

    #[test]
    fn rejects_hard_links_and_oversize() {
        let (d, work, to) = dirs();
        let outside = d.path().join("outside.txt");
        fs::write(&outside, b"host file").unwrap();
        fs::hard_link(&outside, work.join("dist/linked")).unwrap();
        assert_eq!(
            code(export(&job(&work, &to, &["dist"]))),
            ResultCode::Rejected
        );
        assert!(!to.join("dist/app.bin").exists(), "nothing half-exported");
        fs::remove_file(work.join("dist/linked")).unwrap();
        assert_eq!(
            code(export_capped(&job(&work, &to, &["dist"]), 6)),
            ResultCode::Rejected
        );
        assert_eq!(
            export_capped(&job(&work, &to, &["dist"]), 7).unwrap().len(),
            2
        );
    }

    #[test]
    fn refuses_to_overwrite_or_follow_destination_links() {
        let (_d, work, to) = dirs();
        fs::create_dir_all(to.join("dist")).unwrap();
        fs::write(to.join("dist/app.bin"), b"keep").unwrap();
        assert_eq!(
            code(export(&job(&work, &to, &["dist"]))),
            ResultCode::Rejected
        );
        assert_eq!(fs::read(to.join("dist/app.bin")).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_and_special_files() {
        use std::os::unix::fs::symlink;
        let (d, work, to) = dirs();
        symlink("/etc/passwd", work.join("dist/passwd")).unwrap();
        assert_eq!(
            code(export(&job(&work, &to, &["dist"]))),
            ResultCode::Rejected
        );
        fs::remove_file(work.join("dist/passwd")).unwrap();
        // A link as a parent component escapes the work dir.
        symlink(d.path(), work.join("up")).unwrap();
        assert_eq!(
            code(export(&job(&work, &to, &["up/out/x"]))),
            ResultCode::Rejected
        );
        let _sock = std::os::unix::net::UnixListener::bind(work.join("dist/sock")).unwrap();
        assert_eq!(
            code(export(&job(&work, &to, &["dist"]))),
            ResultCode::Rejected
        );
        fs::remove_file(work.join("dist/sock")).unwrap();
        // Destination link planted by an untrusted checkout is not followed.
        let elsewhere = d.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::create_dir_all(&to).unwrap();
        symlink(&elsewhere, to.join("dist")).unwrap();
        assert_eq!(
            code(export(&job(&work, &to, &["dist"]))),
            ResultCode::Rejected
        );
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_symlinks_and_junction_like_reparse_points() {
        let (_d, work, to) = dirs();
        // Creating symlinks needs Developer Mode or admin; skip if denied.
        match std::os::windows::fs::symlink_file(work.join("other.txt"), work.join("dist/l")) {
            Ok(()) => {
                assert_eq!(
                    code(export(&job(&work, &to, &["dist"]))),
                    ResultCode::Rejected
                )
            }
            Err(e) => eprintln!("symlink creation unavailable ({e}); reparse check not exercised"),
        }
    }

    /// Records whether `run` was reached and returns a fixed status.
    struct Fake {
        available: bool,
        status: JobStatus,
        runs: AtomicUsize,
    }

    impl SandboxBackend for Fake {
        fn probe(&self) -> ProbeReport {
            ProbeReport {
                backend: "unavailable",
                available: self.available,
                detail: "fake".into(),
                controls: vec![],
            }
        }
        fn run(&self, _job: &JobSpec) -> crate::Result<JobOutcome> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Ok(JobOutcome {
                status: self.status.clone(),
                stdout: vec![],
                stderr: vec![],
                truncated: false,
                exported: vec![],
            })
        }
    }

    #[test]
    fn run_job_exports_only_after_clean_exit() {
        for (status, exports) in [
            (JobStatus::Exited(0), true),
            (JobStatus::Exited(1), false),
            (JobStatus::TimedOut, false),
            (JobStatus::Killed, false),
        ] {
            let (_d, work, to) = dirs();
            let b = Fake {
                available: true,
                status: status.clone(),
                runs: AtomicUsize::new(0),
            };
            let out = run_job(&b, &job(&work, &to, &["dist"])).unwrap();
            assert_eq!(out.status, status);
            assert_eq!(!out.exported.is_empty(), exports, "{status:?}");
            assert_eq!(to.join("dist/app.bin").exists(), exports, "{status:?}");
        }
    }

    #[test]
    fn unavailable_backend_launches_nothing() {
        let (_d, work, to) = dirs();
        let b = Fake {
            available: false,
            status: JobStatus::Exited(0),
            runs: AtomicUsize::new(0),
        };
        let err = run_job(&b, &job(&work, &to, &["dist"])).unwrap_err();
        assert_eq!(err.code, ResultCode::IsolationUnavailable);
        assert_eq!(b.runs.load(Ordering::SeqCst), 0);
        let err = run_job(&Unavailable, &job(&work, &to, &["dist"])).unwrap_err();
        assert_eq!(err.code, ResultCode::IsolationUnavailable);
        assert!(!to.exists());
    }
}
