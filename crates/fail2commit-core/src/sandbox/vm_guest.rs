//! Private VM guest launcher (SPEC-019). The host passes a bounded JobFile;
//! only fixed guest mounts are accepted and the normal platform sandbox still
//! owns the actual untrusted process.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_GUEST_JOB: u64 = 1024 * 1024;

pub(crate) fn launch(jobfile: &Path) -> crate::Result<()> {
    if jobfile != guest_job_path() {
        return Err(crate::Error::integrity(
            "VM guest job file is outside its assigned mount",
        ));
    }
    let meta = fs::symlink_metadata(jobfile)
        .map_err(|e| crate::Error::invalid(format!("read VM guest job: {e}")))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_GUEST_JOB {
        return Err(crate::Error::integrity(
            "VM guest job is not a bounded regular file",
        ));
    }
    let mut file = fs::File::open(jobfile)
        .map_err(|e| crate::Error::invalid(format!("open VM guest job: {e}")))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_GUEST_JOB + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| crate::Error::invalid(format!("read VM guest job: {e}")))?;
    if bytes.len() as u64 > MAX_GUEST_JOB {
        return Err(crate::Error::integrity("VM guest job exceeds size limit"));
    }
    let job = crate::sandbox::hardened::protocol::decode_job(&bytes)?;
    let work = guest_work_path();
    let mounts = guest_mounts();
    crate::sandbox::hardened::protocol::validate_vm_guest_job(&job, &work, &mounts)?;

    let outcome = crate::sandbox::run_job(&*crate::sandbox::platform_backend(), &job)?;
    let outcome_bytes = crate::sandbox::hardened::protocol::encode_outcome(&outcome)?;
    let outcome_path = guest_outcome_path();
    let outcome_dir = outcome_path.parent().expect("fixed guest outcome parent");
    let mut temp = tempfile::NamedTempFile::new_in(outcome_dir)
        .map_err(|e| crate::Error::isolation_unavailable(format!("create VM outcome: {e}")))?;
    use std::io::Write;
    temp.write_all(&outcome_bytes)
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|e| crate::Error::isolation_unavailable(format!("write VM outcome: {e}")))?;
    temp.persist(&outcome_path)
        .map_err(|e| crate::Error::isolation_unavailable(format!("publish VM outcome: {e}")))?;

    #[cfg(windows)]
    {
        let status = std::process::Command::new("shutdown.exe")
            .args(["/s", "/t", "0"])
            .status()
            .map_err(|e| crate::Error::isolation_unavailable(format!("power off VM guest: {e}")))?;
        if !status.success() {
            return Err(crate::Error::isolation_unavailable(
                "Windows Sandbox guest power off failed",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn guest_work_path() -> PathBuf {
    PathBuf::from(r"C:\f2c\work")
}

#[cfg(windows)]
fn guest_mounts() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\f2c\work"),
        PathBuf::from(r"C:\f2c\in"),
        PathBuf::from(r"C:\f2c\bin"),
    ]
}

#[cfg(windows)]
fn guest_job_path() -> PathBuf {
    guest_work_path().join("job.json")
}

#[cfg(windows)]
fn guest_outcome_path() -> PathBuf {
    guest_work_path().join("outcome.json")
}

#[cfg(target_os = "linux")]
fn guest_work_path() -> PathBuf {
    PathBuf::from("/f2c/job/work")
}

#[cfg(target_os = "linux")]
fn guest_mounts() -> Vec<PathBuf> {
    [
        "/f2c/job", "/f2c/usr", "/f2c/bin", "/usr", "/lib", "/lib64", "/bin", "/sbin",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(target_os = "linux")]
fn guest_job_path() -> PathBuf {
    PathBuf::from("/f2c/job/job.json")
}

#[cfg(target_os = "linux")]
fn guest_outcome_path() -> PathBuf {
    PathBuf::from("/f2c/job/outcome.json")
}

#[cfg(not(any(windows, target_os = "linux")))]
fn guest_work_path() -> PathBuf {
    PathBuf::from("/f2c/work")
}

#[cfg(not(any(windows, target_os = "linux")))]
fn guest_mounts() -> Vec<PathBuf> {
    vec![PathBuf::from("/f2c")]
}

#[cfg(not(any(windows, target_os = "linux")))]
fn guest_job_path() -> PathBuf {
    guest_work_path().join("job.json")
}

#[cfg(not(any(windows, target_os = "linux")))]
fn guest_outcome_path() -> PathBuf {
    guest_work_path().join("outcome.json")
}
