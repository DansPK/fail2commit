//! Private VM guest launcher (SPEC-019). The host passes a bounded JobFile;
//! only fixed guest mounts are accepted and the normal platform sandbox still
//! owns the actual untrusted process.

use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const MAX_GUEST_JOB: u64 = 1024 * 1024;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

pub(crate) fn launch(jobfile: &Path) -> crate::Result<()> {
    let identity = guest_identity(jobfile)?;
    #[cfg(windows)]
    std::env::set_var("FAIL2COMMIT_HOME", r"C:\f2c");
    let bytes = read_control_job(jobfile)?;
    let job = crate::sandbox::hardened::protocol::decode_job(&bytes)?;
    let work = guest_work_path(&identity);
    let stage = guest_stage_root();
    crate::sandbox::hardened::protocol::validate_vm_guest_job(
        &job,
        &work,
        std::slice::from_ref(&stage),
    )?;
    #[cfg(windows)]
    {
        let anchor = crate::sandbox::windows::stage_root()?;
        let validated = crate::sandbox::windows::ValidatedPaths::new(&job, &anchor)?;
        let expected_work = work.canonicalize().map_err(|error| {
            crate::Error::integrity(format!("canonicalize assigned VM work mount: {error}"))
        })?;
        if validated.work_dir != expected_work {
            return Err(crate::Error::integrity(
                "VM work mount identity does not match the bound guest job",
            ));
        }
        for (index, input) in validated.read_only.iter().enumerate() {
            let expected = stage
                .join(format!("input-{index}"))
                .canonicalize()
                .map_err(|error| {
                    crate::Error::integrity(format!(
                        "canonicalize assigned VM input mount: {error}"
                    ))
                })?;
            if input != &expected {
                return Err(crate::Error::integrity(
                    "VM read-only input identity does not match the bound guest job",
                ));
            }
        }
    }

    let outcome = crate::sandbox::run_job(&*crate::sandbox::platform_backend(), &job)?;
    let outcome_bytes = crate::sandbox::hardened::protocol::encode_outcome(&outcome)?;
    let outcome_path = guest_outcome_path(&identity);
    let outcome_dir = outcome_path.parent().expect("fixed guest outcome parent");
    let mut temp = tempfile::NamedTempFile::new_in(outcome_dir)
        .map_err(|e| crate::Error::isolation_unavailable(format!("create VM outcome: {e}")))?;
    use std::io::Write;
    temp.write_all(&outcome_bytes)
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|e| crate::Error::isolation_unavailable(format!("write VM outcome: {e}")))?;
    temp.persist_noclobber(&outcome_path)
        .map_err(|e| crate::Error::isolation_unavailable(format!("publish VM outcome: {e}")))?;
    Ok(())
}

fn guest_identity(jobfile: &Path) -> crate::Result<String> {
    #[cfg(windows)]
    {
        let parent = jobfile
            .parent()
            .ok_or_else(|| crate::Error::integrity("VM control path has no parent"))?;
        let identity = parent
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !valid_identity(identity)
            || parent.parent() != Some(Path::new(r"C:\f2c\control"))
            || jobfile.file_name() != Some(std::ffi::OsStr::new("job.json"))
        {
            return Err(crate::Error::integrity(
                "VM control file is outside its per-job immutable mount",
            ));
        }
        Ok(identity.to_owned())
    }
    #[cfg(target_os = "linux")]
    {
        if jobfile != Path::new("/f2c/job/job.json") {
            return Err(crate::Error::integrity(
                "VM control file is outside its assigned mount",
            ));
        }
        Ok("linux-job".into())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = jobfile;
        Err(crate::Error::isolation_unavailable(
            "VM guest launcher is unsupported on this platform",
        ))
    }
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_file_identity_must_be_fresh_safe_hex_component() {
        let path = Path::new(r"C:\f2c\control\0123456789abcdef0123456789abcdef\job.json");
        assert_eq!(
            guest_identity(path).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        assert!(guest_identity(Path::new(r"C:\f2c\control\..\bad\job.json")).is_err());
        assert!(guest_identity(Path::new(r"C:\f2c\control\ABC\job.json")).is_err());
    }
}

fn read_control_job(jobfile: &Path) -> crate::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(jobfile).map_err(|error| {
        crate::Error::integrity(format!("open immutable VM control file: {error}"))
    })?;
    let metadata = file.metadata().map_err(|error| {
        crate::Error::integrity(format!("inspect immutable VM control file: {error}"))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_GUEST_JOB {
        return Err(crate::Error::integrity(
            "VM control input is not a bounded regular file",
        ));
    }
    let expected_len = metadata.len();
    let mut bytes = Vec::with_capacity(expected_len as usize);
    file.take(MAX_GUEST_JOB + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| crate::Error::integrity(format!("read VM control file: {error}")))?;
    if bytes.len() as u64 != expected_len {
        return Err(crate::Error::integrity(
            "VM control file identity or length changed during read",
        ));
    }
    Ok(bytes)
}

fn valid_identity(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(windows)]
fn guest_stage_root() -> PathBuf {
    PathBuf::from(r"C:\f2c\cache\sandbox-stage")
}

#[cfg(windows)]
fn guest_work_path(identity: &str) -> PathBuf {
    guest_stage_root().join(identity).join("work")
}

#[cfg(windows)]
fn guest_outcome_path(identity: &str) -> PathBuf {
    PathBuf::from(r"C:\f2c\result")
        .join(identity)
        .join("outcome.json")
}

#[cfg(target_os = "linux")]
fn guest_stage_root() -> PathBuf {
    PathBuf::from("/f2c/job")
}

#[cfg(target_os = "linux")]
fn guest_work_path(_: &str) -> PathBuf {
    PathBuf::from("/f2c/job/work")
}

#[cfg(target_os = "linux")]
fn guest_outcome_path(_: &str) -> PathBuf {
    PathBuf::from("/f2c/job/outcome.json")
}

#[cfg(not(any(windows, target_os = "linux")))]
fn guest_stage_root() -> PathBuf {
    PathBuf::from("/f2c/work")
}

#[cfg(not(any(windows, target_os = "linux")))]
fn guest_work_path(_: &str) -> PathBuf {
    PathBuf::from("/f2c/work")
}

#[cfg(not(any(windows, target_os = "linux")))]
fn guest_outcome_path(_: &str) -> PathBuf {
    PathBuf::from("/f2c/outcome.json")
}
