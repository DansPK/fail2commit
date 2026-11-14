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
    #[cfg(target_os = "linux")]
    verify_linux_vm_context(&identity)?;
    let bytes = read_control_job(jobfile)?;
    let job = crate::sandbox::hardened::protocol::decode_job(&bytes)?;
    let work = guest_work_path(&identity);
    #[cfg(target_os = "linux")]
    let stage = guest_stage_root(&identity);
    #[cfg(not(target_os = "linux"))]
    let stage = guest_stage_root();
    #[cfg(target_os = "linux")]
    let mounts = guest_mount_allowlist(&stage);
    #[cfg(not(target_os = "linux"))]
    let mounts = vec![stage.clone()];
    crate::sandbox::hardened::protocol::validate_vm_guest_job(&job, &work, &mounts)?;
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

    #[cfg(target_os = "linux")]
    verify_linux_mount_identities(&job, &stage, &work, jobfile, &identity)?;

    let outcome = crate::sandbox::run_job(&*crate::sandbox::platform_backend(), &job)?;
    #[cfg(target_os = "linux")]
    let outcome_bytes = crate::sandbox::hardened::protocol::encode_vm_outcome(&identity, &outcome)?;
    #[cfg(not(target_os = "linux"))]
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
        let parent = jobfile
            .parent()
            .ok_or_else(|| crate::Error::integrity("VM control path has no parent"))?;
        let identity = parent
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !valid_identity(identity)
            || parent.parent() != Some(Path::new("/mnt/fail2commit-vm/control"))
            || jobfile.file_name() != Some(std::ffi::OsStr::new("job.json"))
        {
            return Err(crate::Error::integrity(
                "VM control file is outside its per-job immutable mount",
            ));
        }
        Ok(identity.to_owned())
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

/// Fixed outer-guest namespace (FR-029, SPEC-019 Linux layout correction). It
/// lives outside the inner Bubblewrap control mount `/f2c`, so the package's
/// sandbox never sees the request, result or job trees through that mount.
#[cfg(target_os = "linux")]
const GUEST_ROOT: &str = "/mnt/fail2commit-vm";

/// Read-only system shares the guest mounts at their host paths. The job's
/// program may be a staged input or one of these system tools; nothing else.
#[cfg(target_os = "linux")]
const GUEST_SYSTEM_MOUNTS: [&str; 7] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32",
];

#[cfg(target_os = "linux")]
fn guest_mount_allowlist(stage: &Path) -> Vec<PathBuf> {
    let mut mounts = vec![stage.to_path_buf()];
    mounts.extend(GUEST_SYSTEM_MOUNTS.iter().map(PathBuf::from));
    mounts
}

#[cfg(target_os = "linux")]
fn guest_stage_root(identity: &str) -> PathBuf {
    PathBuf::from(GUEST_ROOT).join("jobs").join(identity)
}

#[cfg(target_os = "linux")]
fn guest_work_path(identity: &str) -> PathBuf {
    guest_stage_root(identity).join("work")
}

#[cfg(target_os = "linux")]
fn guest_outcome_path(identity: &str) -> PathBuf {
    PathBuf::from(GUEST_ROOT)
        .join("results")
        .join(identity)
        .join("outcome.json")
}

/// Bind guest dispatch to this kernel boot: the host passes the fresh job id
/// on the command line and the outer boundary must be KVM. A launcher started
/// outside the prepared VM (or for another run) is refused.
#[cfg(target_os = "linux")]
fn verify_linux_vm_context(identity: &str) -> crate::Result<()> {
    let cmdline = std::fs::read("/proc/cmdline")
        .map_err(|error| crate::Error::integrity(format!("read guest kernel context: {error}")))?;
    if cmdline.len() > 64 * 1024 {
        return Err(crate::Error::integrity("guest kernel context is oversized"));
    }
    let cmdline = String::from_utf8_lossy(&cmdline);
    let expected = format!("f2c_job_id={identity}");
    if !cmdline
        .split_ascii_whitespace()
        .any(|item| item == expected)
    {
        return Err(crate::Error::integrity(
            "VM guest dispatch is not bound to this kernel boot identity",
        ));
    }
    let hypervisor = std::fs::read_to_string("/sys/hypervisor/type")
        .map_err(|error| crate::Error::integrity(format!("verify KVM guest context: {error}")))?;
    if hypervisor.trim() != "kvm" {
        return Err(crate::Error::integrity(
            "VM guest dispatch requires the KVM outer boundary",
        ));
    }
    Ok(())
}

/// Validate resolved mount/file identities, not just path spelling: the control
/// file, writable work mount and every read-only input must resolve to the
/// anchors the host assigned, and the result exchange must be a real directory.
#[cfg(target_os = "linux")]
fn verify_linux_mount_identities(
    job: &crate::isolation::JobSpec,
    stage: &Path,
    work: &Path,
    jobfile: &Path,
    identity: &str,
) -> crate::Result<()> {
    let canonical = |path: &Path, what: &str| -> crate::Result<PathBuf> {
        path.canonicalize()
            .map_err(|error| crate::Error::integrity(format!("canonicalize {what}: {error}")))
    };
    if canonical(jobfile, "VM control file")? != jobfile {
        return Err(crate::Error::integrity(
            "VM control file identity does not match its immutable mount",
        ));
    }
    let expected_work = canonical(work, "assigned VM work mount")?;
    if canonical(&job.work_dir, "VM work dir")? != expected_work {
        return Err(crate::Error::integrity(
            "VM work mount identity does not match the bound guest job",
        ));
    }
    for (index, input) in job.read_only.iter().enumerate() {
        let expected = canonical(
            &stage.join(format!("input-{index}")),
            "assigned VM input mount",
        )?;
        if canonical(input, "VM read-only input")? != expected {
            return Err(crate::Error::integrity(
                "VM read-only input identity does not match the bound guest job",
            ));
        }
    }
    let result_dir = guest_outcome_path(identity)
        .parent()
        .expect("fixed guest result parent")
        .to_path_buf();
    if !result_dir.is_dir() {
        return Err(crate::Error::integrity(
            "VM result exchange is not a mounted directory",
        ));
    }
    Ok(())
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

#[cfg(target_os = "linux")]
#[cfg(test)]
mod linux_tests {
    use super::*;

    #[test]
    fn control_file_identity_must_be_fresh_safe_hex_component() {
        let id = "0123456789abcdef0123456789abcdef";
        let path = PathBuf::from("/mnt/fail2commit-vm/control")
            .join(id)
            .join("job.json");
        assert_eq!(guest_identity(&path).unwrap(), id);
        assert!(guest_identity(Path::new("/mnt/fail2commit-vm/control/../bad/job.json")).is_err());
        assert!(guest_identity(Path::new("/mnt/fail2commit-vm/control/ABC/job.json")).is_err());
        assert!(guest_identity(Path::new("/f2c/job/job.json")).is_err());
        assert!(guest_identity(Path::new("/mnt/fail2commit-vm/control/job.json")).is_err());
    }

    #[test]
    fn guest_paths_stay_outside_the_inner_control_mount() {
        let id = "0123456789abcdef0123456789abcdef";
        let stage = guest_stage_root(id);
        let work = guest_work_path(id);
        let outcome = guest_outcome_path(id);
        assert_eq!(stage, Path::new("/mnt/fail2commit-vm/jobs").join(id));
        assert_eq!(work, stage.join("work"));
        assert_eq!(
            outcome,
            Path::new("/mnt/fail2commit-vm/results")
                .join(id)
                .join("outcome.json")
        );
        // None of the job/request/result trees may live under the inner /f2c.
        for path in [&stage, &work, &outcome] {
            assert!(!path.starts_with("/f2c"));
        }
        let mounts = guest_mount_allowlist(&stage);
        assert!(mounts.contains(&stage));
        assert!(mounts.contains(&PathBuf::from("/usr")));
        assert!(!mounts.contains(&PathBuf::from("/mnt/fail2commit-vm/control")));
        assert!(!mounts.contains(&PathBuf::from("/mnt/fail2commit-vm/results")));
    }
}
