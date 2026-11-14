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

/// Root-only capability baked into the prepared initramfs (LV-02). Only the
/// prepared guest's root init can open it; it hands the open fd to the launcher
/// so dispatch is bound to the prepared guest, not just a readable cmdline id.
#[cfg(target_os = "linux")]
const GUEST_CAPABILITY: &str = "/mnt/fail2commit-vm/.vm-capability";
/// The inherited descriptor init passes the capability file on.
#[cfg(target_os = "linux")]
const CAPABILITY_FD: std::os::fd::RawFd = 3;

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

/// Bind guest dispatch to the prepared KVM guest (LV-02). The fresh cmdline job
/// id is correlation, not authentication: the trust boundary is the supported
/// KVM hypervisor signal plus a root-only prepared-guest capability that only
/// the prepared init can hand over. A launcher started outside the prepared VM
/// — even with a syntactically valid control tree — is refused.
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
    // Supported KVM guest signal: the hypervisor CPUID signature. The old
    // /sys/hypervisor/type path is the Xen ABI and is not populated by KVM.
    if !kvm_hypervisor_present() {
        return Err(crate::Error::integrity(
            "VM guest dispatch requires the KVM outer boundary",
        ));
    }
    verify_prepared_capability(Path::new(GUEST_CAPABILITY), CAPABILITY_FD)
}

/// KVM advertises the vendor string "KVMKVMKVM\0\0\0" in the hypervisor CPUID
/// leaf 0x40000000 (EBX/ECX/EDX). This is the supported KVM guest detection.
#[cfg(target_os = "linux")]
fn kvm_signature_is_kvm(ebx: u32, ecx: u32, edx: u32) -> bool {
    let mut sig = [0u8; 12];
    sig[0..4].copy_from_slice(&ebx.to_le_bytes());
    sig[4..8].copy_from_slice(&ecx.to_le_bytes());
    sig[8..12].copy_from_slice(&edx.to_le_bytes());
    &sig == b"KVMKVMKVM\0\0\0"
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn kvm_hypervisor_present() -> bool {
    // __cpuid_count is a read-only, serializing CPU instruction always available
    // on x86_64; it has no memory or privilege side effects.
    let leaf = std::arch::x86_64::__cpuid_count(0x4000_0000, 0);
    kvm_signature_is_kvm(leaf.ebx, leaf.ecx, leaf.edx)
}

/// The VM backend is x86_64-only; any other architecture cannot be the prepared
/// KVM guest, so dispatch is refused.
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn kvm_hypervisor_present() -> bool {
    false
}

/// Verify the inherited capability fd refers to the root-only prepared file.
/// Only the prepared guest's root init can open that 0400 file, so a matching
/// fd proves the launcher was dispatched by the prepared guest. Outside the
/// guest the file is absent; an untrusted job cannot open it or forge the fd.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn verify_prepared_capability(cap_path: &Path, fd: std::os::fd::RawFd) -> crate::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::symlink_metadata(cap_path).map_err(|_| {
        crate::Error::integrity("prepared guest capability is missing (outside the prepared VM)")
    })?;
    if !md.is_file() || md.file_type().is_symlink() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(crate::Error::integrity(
            "prepared guest capability is not a root-owned, non-writable regular file",
        ));
    }
    // SAFETY: stat is a correctly sized writable buffer; fstat on an arbitrary
    // fd only reads kernel state and returns EBADF for a closed descriptor.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(crate::Error::integrity(
            "prepared guest capability fd was not inherited from init",
        ));
    }
    if (st.st_dev, st.st_ino) != (md.dev(), md.ino()) {
        return Err(crate::Error::integrity(
            "prepared guest capability fd does not match the prepared file",
        ));
    }
    // The token is 64 lowercase hex bytes.
    let mut buf = [0u8; 65];
    // SAFETY: buf is a valid writable buffer of the given length; fd is the
    // live inherited capability descriptor. read does not take ownership.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n != 64
        || !buf[..64]
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(crate::Error::integrity(
            "prepared guest capability token is malformed",
        ));
    }
    // Consume the capability: the inner Bubblewrap child must not keep or be
    // able to re-present the fd that authenticates prepared-guest dispatch.
    // SAFETY: fd is the live descriptor this launcher owns (handed by init);
    // after verification it is closed exactly once here.
    unsafe { libc::close(fd) };
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

    #[test]
    fn kvm_signature_detection_matches_only_kvm() {
        let kvm = b"KVMKVMKVM\0\0\0";
        let ebx = u32::from_le_bytes(kvm[0..4].try_into().unwrap());
        let ecx = u32::from_le_bytes(kvm[4..8].try_into().unwrap());
        let edx = u32::from_le_bytes(kvm[8..12].try_into().unwrap());
        assert!(kvm_signature_is_kvm(ebx, ecx, edx));
        assert!(!kvm_signature_is_kvm(0, 0, 0));
        // The VMware hypervisor signature (this dev VM) is not KVM.
        let vmw = b"VMwareVMware";
        let ebx = u32::from_le_bytes(vmw[0..4].try_into().unwrap());
        let ecx = u32::from_le_bytes(vmw[4..8].try_into().unwrap());
        let edx = u32::from_le_bytes(vmw[8..12].try_into().unwrap());
        assert!(!kvm_signature_is_kvm(ebx, ecx, edx));
    }

    #[test]
    fn capability_refuses_outside_the_prepared_guest() {
        let dir = tempfile::tempdir().unwrap();
        // A missing capability file means we are outside the prepared guest.
        let missing = dir.path().join("absent");
        assert!(verify_prepared_capability(&missing, 3).is_err());
        // A present file that is not root-owned is refused (unit tests run
        // unprivileged; the root-owned success path is a boot gate).
        let cap = dir.path().join("cap");
        std::fs::write(&cap, "a".repeat(64)).unwrap();
        let f = std::fs::File::open(&cap).unwrap();
        use std::os::fd::AsRawFd;
        assert!(verify_prepared_capability(&cap, f.as_raw_fd()).is_err());
        // A closed descriptor is refused.
        let closed = {
            let tmp = std::fs::File::open(&cap).unwrap();
            tmp.as_raw_fd()
        };
        assert!(verify_prepared_capability(&cap, closed).is_err());
    }

    #[test]
    fn dispatch_outside_the_prepared_guest_is_refused() {
        // A syntactically valid control tree path, but this host is not the
        // prepared KVM guest: dispatch refuses at the context check before the
        // control file is ever read.
        let id = "0123456789abcdef0123456789abcdef";
        let path = PathBuf::from("/mnt/fail2commit-vm/control")
            .join(id)
            .join("job.json");
        let err = launch(&path).expect_err("outside-guest dispatch must refuse");
        assert!(
            err.message.contains("boot identity")
                || err.message.contains("KVM")
                || err.message.contains("capability"),
            "{}",
            err.message
        );
    }
}
