//! Linux QEMU/KVM micro-VM host backend (FR-029, SPEC-019 §4, CR-025, CR-026).
//!
//! The host stages the job, writes a guest `job.json` into a per-run read-only
//! control share, starts a disposable micro-VM with explicit virtio-mmio 9p and
//! network devices, and waits for an identity-bound outcome plus a clean QEMU
//! exit before the unchanged `run_job` exports from the host work dir. The
//! inner Bubblewrap backend runs unchanged inside the guest.

// kill(2)/fstat(2)/geteuid and O_PATH pinning need libc; each block has a
// SAFETY note.
#![allow(unsafe_code)]

use super::prepare::{self, VmState};
use super::PlatformFallback;
use crate::isolation::{
    ActivityReport, JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend,
};
use crate::sandbox::hardened::protocol::{self, MAX_VM_OUTCOME_BYTES};
use crate::sandbox::Bubblewrap;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BOOT_GRACE: Duration = Duration::from_secs(45);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MICROVM_MAX_DEVICES: usize = 8;
const GUEST_ROOT: &str = "/mnt/fail2commit-vm";
const SYSTEM_DIRS: [&str; 7] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32",
];
const MAX_STAGE_OBJECTS: usize = 100_000;

enum ProbeFailure {
    /// Proven hardware/OS feature absence: fall back to the platform backend.
    Absent(String),
    /// Missing preparation, permissions, corruption or runtime error: fail closed.
    Failed(String),
}

struct ReadyHost {
    state: VmState,
}

enum Selection {
    Ready(Box<ReadyHost>),
    Failed(String),
}

pub(super) fn selected() -> Box<dyn SandboxBackend> {
    match preflight() {
        Ok(host) => Box::new(QemuVm {
            selection: Selection::Ready(Box::new(host)),
        }),
        Err(ProbeFailure::Absent(reason)) => Box::new(PlatformFallback::new(
            crate::sandbox::platform_backend(),
            reason,
        )),
        Err(ProbeFailure::Failed(reason)) => Box::new(QemuVm {
            selection: Selection::Failed(reason),
        }),
    }
}

struct QemuVm {
    selection: Selection,
}

impl SandboxBackend for QemuVm {
    fn probe(&self) -> ProbeReport {
        match &self.selection {
            Selection::Ready(_) => ProbeReport {
                backend: "qemu-kvm",
                available: true,
                detail: "QEMU/KVM micro-VM prerequisites and inner Bubblewrap probe passed".into(),
                controls: vec![
                    ("kvm-device-accessible".into(), true),
                    ("qemu-microvm-mmio-devices".into(), true),
                    ("prepared-image-hash-match".into(), true),
                    ("guest-virtio-9p-modules".into(), true),
                    ("inner-bubblewrap-controls".into(), true),
                ],
            },
            Selection::Failed(reason) => ProbeReport {
                backend: "qemu-kvm",
                available: false,
                detail: reason.clone(),
                controls: vec![("qemu-kvm-preflight".into(), false)],
            },
        }
    }

    fn run(&self, job: &JobSpec) -> crate::Result<JobOutcome> {
        match &self.selection {
            Selection::Ready(host) => run_job(host, job),
            Selection::Failed(reason) => Err(crate::Error::isolation_unavailable(format!(
                "QEMU/KVM unavailable: {reason}"
            ))),
        }
    }
}

fn preflight() -> Result<ReadyHost, ProbeFailure> {
    // Hardware/OS feature absence is the only fallback (FR-029). Check it first
    // so an absent KVM never depends on preparation state.
    classify_kvm()?;
    let state = prepare::load_state(Path::new(prepare::STATE_FILE))
        .map_err(|e| ProbeFailure::Failed(e.message))?;
    prepare::verify_hashes(&state).map_err(|e| ProbeFailure::Failed(e.message))?;
    let qemu = Path::new(&state.qemu);
    let md = fs::metadata(qemu)
        .map_err(|e| ProbeFailure::Failed(format!("prepared qemu is unavailable: {e}")))?;
    if !md.is_file() || md.uid() != 0 || md.mode() & 0o022 != 0 || md.mode() & 0o111 == 0 {
        return Err(ProbeFailure::Failed(
            "prepared qemu is not a root-owned, non-writable executable".into(),
        ));
    }
    let inner = Bubblewrap::default().probe();
    if !inner.available {
        return Err(ProbeFailure::Failed(format!(
            "inner Bubblewrap controls failed: {}",
            inner.detail
        )));
    }
    Ok(ReadyHost { state })
}

/// `/dev/kvm` absent with no CPU virtualization flags is proven hardware
/// absence; absent with flags is the KVM OS feature not being available. Both
/// fall back. An existing but inaccessible device is a permission failure.
fn classify_kvm() -> Result<(), ProbeFailure> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/kvm")
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if cpu_has_virtualization() {
                Err(ProbeFailure::Absent(
                    "KVM device is absent (kernel module not loaded)".into(),
                ))
            } else {
                Err(ProbeFailure::Absent(
                    "hardware virtualization is not available".into(),
                ))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(ProbeFailure::Failed(
            "permission denied opening /dev/kvm (add the user to the kvm group)".into(),
        )),
        Err(e) => Err(ProbeFailure::Failed(format!("cannot access /dev/kvm: {e}"))),
    }
}

fn cpu_has_virtualization() -> bool {
    let Ok(info) = fs::read_to_string("/proc/cpuinfo") else {
        return false;
    };
    info.lines()
        .filter(|l| l.starts_with("flags"))
        .any(|l| l.split_whitespace().any(|w| w == "vmx" || w == "svm"))
}

/// One 9p share: host path, mount tag, read-only. The guest mount point is
/// derived from the tag by the prepared init, so it is not carried here.
struct Share {
    host: PathBuf,
    tag: String,
    read_only: bool,
    /// Fixed child-side pin slot (LV-05). When set, QEMU maps
    /// `/proc/self/fd/N` instead of the pathname, so a later rename/replace of
    /// the host path cannot redirect the share to a different inode. Only the
    /// QEMU spawn duplicates descriptors into these slots (R2-03).
    fd: Option<RawFd>,
}

struct HostMappings {
    guest_work: PathBuf,
    entries: Vec<(PathBuf, PathBuf)>,
}

/// How long to keep trying to contain a QEMU process group after the run
/// ends or its deadline fires. Bounded; expiry means containment Unconfirmed.
const CLEANUP_GRACE: Duration = Duration::from_secs(5);
/// Durable quarantine record (R2-01) under the sandbox stage root.
const CONTAINMENT_FILE: &str = "f2c-vm-containment.json";
const MAX_CONTAINMENT_BYTES: u64 = 64 * 1024;

/// Durable refusal/recovery record for a micro-VM whose process group could
/// not be confirmed dead. `pgid` + `bound_ticks` give the exact identity used
/// to decide "still live" (pid reuse cannot resurrect or fake liveness).
#[derive(Serialize, Deserialize)]
struct QuarantineRecord {
    reason: String,
    pgid: u32,
    bound_ticks: u64,
    control_dir: Option<String>,
    result_dir: Option<String>,
    created_unix: u64,
}

#[derive(Serialize, Deserialize)]
struct QuarantineFile {
    version: u32,
    records: Vec<QuarantineRecord>,
}

/// The retained containment owner for one unconfirmed VM: every mapped guard
/// (share pins, control dir, result dir) plus the unreaped child stays held
/// here for the process lifetime, so a live QEMU can never observe released
/// or recycled exchanges (R2-01). Recovery later drops these entries only
/// after the group's exact identity is proven gone.
struct Contained {
    record: QuarantineRecord,
    _pins: Vec<PinnedShare>,
    _control: tempfile::TempDir,
    _result: tempfile::TempDir,
    _child: Option<Child>,
}

/// Process-lifetime registry of retained containment owners. A mutex poison
/// only means a quarantining path panicked; the inner Vec is still valid.
static CONTAINED: Mutex<Vec<Contained>> = Mutex::new(Vec::new());

fn contained_registry() -> std::sync::MutexGuard<'static, Vec<Contained>> {
    CONTAINED
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Persist the durable quarantine record. Written 0600 with create+rename so
/// the next process can find exactly which group and directories to check.
fn persist_quarantine(stage_root: &Path, record: &QuarantineRecord) -> crate::Result<()> {
    let path = stage_root.join(CONTAINMENT_FILE);
    let mut file = if path.exists() {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .and_then(|f| {
                let mut b = Vec::new();
                let mut limited = f.take(MAX_CONTAINMENT_BYTES + 1);
                limited.read_to_end(&mut b)?;
                Ok::<Vec<u8>, std::io::Error>(b)
            })
            .and_then(|b| {
                serde_json::from_slice::<QuarantineFile>(&b).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })
            })
            .map_err(|e| {
                crate::Error::integrity(format!(
                    "VM containment record is unreadable or corrupt ({e}); resolve the contained process group and remove {}",
                    path.display()
                ))
            })?
    } else {
        QuarantineFile {
            version: 1,
            records: Vec::new(),
        }
    };
    if file.records.len() >= 8 {
        file.records.remove(0);
    }
    file.records.push(QuarantineRecord {
        reason: record.reason.clone(),
        pgid: record.pgid,
        bound_ticks: record.bound_ticks,
        control_dir: record.control_dir.clone(),
        result_dir: record.result_dir.clone(),
        created_unix: record.created_unix,
    });
    let json = serde_json::to_vec_pretty(&file)
        .map_err(|e| crate::Error::internal(format!("serialize containment record: {e}")))?;
    let tmp = stage_root.join(format!("{CONTAINMENT_FILE}.tmp"));
    write_new_file_force(&tmp, &json)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Like `write_new_file` but replaces a stale tmp left by an earlier crash.
fn write_new_file_force(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            crate::Error::isolation_unavailable(format!("create VM containment tmp: {e}"))
        })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Hand the mapped guards to the retained containment owner and produce the
/// fail-closed error (R2-01). Persistence failure does not release the guards.
fn retain_containment(stage_root: &Path, guards: Contained) -> crate::Error {
    let record = QuarantineRecord {
        reason: guards.record.reason.clone(),
        pgid: guards.record.pgid,
        bound_ticks: guards.record.bound_ticks,
        control_dir: guards.record.control_dir.clone(),
        result_dir: guards.record.result_dir.clone(),
        created_unix: guards.record.created_unix,
    };
    let persist = persist_quarantine(stage_root, &record);
    contained_registry().push(guards);
    match persist {
        Ok(()) => crate::Error::isolation_unavailable(format!(
            "micro-VM containment unconfirmed; mapped state is quarantined in memory and {} for recovery",
            stage_root.join(CONTAINMENT_FILE).display()
        )),
        Err(e) => crate::Error::isolation_unavailable(format!(
            "micro-VM containment unconfirmed and the durable quarantine record failed to persist ({e}); mapped state stays quarantined in memory"
        )),
    }
}

/// Refuse or recover before touching a new VM (R2-01): while any contained
/// group from a prior attempt is still live, every new VM run stays refused;
/// once the exact identities are proven gone, retained guards drop, the
/// quarantined per-run directories delete, and the durable record clears.
fn recover_or_refuse(stage_root: &Path) -> crate::Result<()> {
    let mut retained: Vec<Contained> = Vec::new();
    {
        let mut reg = contained_registry();
        std::mem::swap(&mut *reg, &mut retained);
    }
    let mut live_in_process = 0usize;
    for guard in retained.into_iter() {
        if prepare::group_members(guard.record.pgid as i32, guard.record.bound_ticks).is_empty() {
            // Confirmed gone: dropping the guards releases pins and deletes
            // the per-run control/result directories through their owners.
            continue;
        }
        live_in_process += 1;
        // Still live: re-retain (never drop while contained).
        contained_registry().push(guard);
    }
    if live_in_process > 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "a previous micro-VM's process group is still contained ({live_in_process}); VM jobs stay refused until containment recovers"
        )));
    }
    // Cross-process recovery from the durable record.
    let path = stage_root.join(CONTAINMENT_FILE);
    if !path.exists() {
        return Ok(());
    }
    let bytes = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .and_then(|f| {
            let mut b = Vec::new();
            let mut limited = f.take(MAX_CONTAINMENT_BYTES + 1);
            limited.read_to_end(&mut b)?;
            Ok::<Vec<u8>, std::io::Error>(b)
        })
        .map_err(|e| {
            crate::Error::integrity(format!(
                "read VM containment record {}: {e}",
                path.display()
            ))
        })?;
    let file: QuarantineFile = serde_json::from_slice(&bytes).map_err(|e| {
        crate::Error::integrity(format!(
            "VM containment record is corrupt ({e}); resolve the contained process group and remove {}",
            path.display()
        ))
    })?;
    let mut all_dead = true;
    for record in &file.records {
        if !prepare::group_members(record.pgid as i32, record.bound_ticks).is_empty() {
            all_dead = false;
        }
    }
    if !all_dead {
        return Err(crate::Error::isolation_unavailable(format!(
            "a previously contained micro-VM process group is still live; VM jobs stay refused until it exits (see {})",
            path.display()
        )));
    }
    for record in &file.records {
        for dir in [record.control_dir.as_deref(), record.result_dir.as_deref()] {
            let Some(dir) = dir else { continue };
            let p = Path::new(dir);
            // Only remove per-run temp directories, never a symlink target.
            let Ok(md) = fs::symlink_metadata(p) else {
                continue;
            };
            if md.is_dir() && !md.file_type().is_symlink() {
                let _ = fs::remove_dir_all(p);
            }
        }
    }
    fs::remove_file(&path)?;
    Ok(())
}

fn run_job(host: &ReadyHost, job: &JobSpec) -> crate::Result<JobOutcome> {
    let stage_root = crate::paths::TrustedPaths::resolve()?
        .cache_dir
        .join("sandbox-stage");
    // R2-01: refuse while any previous run's group remains contained; recover
    // the quarantine once its exact identity is proven gone.
    recover_or_refuse(&stage_root)?;
    let validated = ValidatedPaths::new(job, &stage_root)?;
    if validated.read_only.len() > host.state.max_inputs {
        return Err(crate::Error::isolation_unavailable(format!(
            "job needs {} input shares but the prepared micro-VM allows {}",
            validated.read_only.len(),
            host.state.max_inputs
        )));
    }
    let mut id = [0u8; 16];
    getrandom::fill(&mut id)
        .map_err(|e| crate::Error::isolation_unavailable(format!("create VM job identity: {e}")))?;
    let job_id = hex::encode(id);
    let guest_stage = PathBuf::from(GUEST_ROOT).join("jobs").join(&job_id);
    let guest_work = guest_stage.join("work");

    let control_dir = tempfile::Builder::new()
        .prefix("f2c-vm-control-")
        .tempdir_in(&stage_root)
        .map_err(|e| {
            crate::Error::isolation_unavailable(format!("create VM control stage: {e}"))
        })?;
    let result_dir = tempfile::Builder::new()
        .prefix("f2c-vm-result-")
        .tempdir_in(&stage_root)
        .map_err(|e| crate::Error::isolation_unavailable(format!("create VM result stage: {e}")))?;

    let mut entries = Vec::new();
    for (index, input) in validated.read_only.iter().enumerate() {
        entries.push((input.clone(), guest_stage.join(format!("input-{index}"))));
    }
    entries.push((validated.work_dir.clone(), guest_work.clone()));
    let mappings = HostMappings {
        guest_work: guest_work.clone(),
        entries,
    };

    let guest_job = remap_job(job, &validated, &mappings)?;
    let encoded = protocol::encode_job(&guest_job)?;
    write_new_file(&control_dir.path().join("job.json"), &encoded)?;

    // Build the share list: read-only system trees, then the job's trees and
    // the separate immutable request / result authorities.
    let mut shares = Vec::new();
    for dir in &host.state.system_shares {
        shares.push(Share {
            host: PathBuf::from(dir),
            tag: prepare::system_share_tag(dir),
            read_only: true,
            fd: None,
        });
    }
    for (index, input) in validated.read_only.iter().enumerate() {
        shares.push(Share {
            host: input.clone(),
            tag: format!("f2cin{index}"),
            read_only: true,
            fd: None,
        });
    }
    shares.push(Share {
        host: validated.work_dir.clone(),
        tag: "f2cwork".into(),
        read_only: false,
        fd: None,
    });
    shares.push(Share {
        host: control_dir.path().to_path_buf(),
        tag: "f2cctl".into(),
        read_only: true,
        fd: None,
    });
    shares.push(Share {
        host: result_dir.path().to_path_buf(),
        tag: "f2cres".into(),
        read_only: false,
        fd: None,
    });
    if shares.len() + 1 > MICROVM_MAX_DEVICES {
        return Err(crate::Error::isolation_unavailable(
            "job shares exceed the microvm virtio-mmio device limit",
        ));
    }

    // SAFETY: geteuid/getgid have no preconditions.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };

    // Re-walk identities to detect any change since validation.
    let revalidated = ValidatedPaths::new(job, &stage_root)?;
    if revalidated.identities != validated.identities {
        return Err(crate::Error::integrity(
            "staged paths changed while preparing the micro-VM",
        ));
    }
    // LV-05: pin each share anchor with an O_PATH descriptor and map it via a
    // fixed child slot /proc/self/fd/N, so a pathname swap after this point
    // cannot redirect a share. The pins stay open until the group is dead.
    // R2-03: the parent descriptors stay close-on-exec; only this QEMU spawn
    // installs the slot allowlist.
    let pins = pin_shares(&mut shares, &revalidated.identities)?;
    let inherit: Vec<(RawFd, RawFd)> = pins.iter().map(|p| (p.file.as_raw_fd(), p.slot)).collect();

    let args = render_qemu_args(
        &host.state,
        &shares,
        job,
        &job_id,
        uid,
        gid,
        validated.read_only.len(),
    )?;

    // LV-03: compute the checked absolute deadline before any spawn, so a
    // representability failure can never leave a live VM with dropped guards.
    let deadline = boot_deadline(job.limits.timeout)?;

    let mut cmd = Command::new(&host.state.qemu);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    add_slot_inheritance(&mut cmd, inherit);
    let mut child = cmd
        .spawn()
        .map_err(|e| crate::Error::isolation_unavailable(format!("start QEMU: {e}")))?;
    let pgid = child.id() as i32;
    // R2-01: hand every mapped guard to the retained containment owner if
    // group death cannot be confirmed. Never drops guards, never spawns past
    // a refusal, and persists the exact identity for cross-process recovery.
    let quarantined = |reason: String,
                       pins: Vec<PinnedShare>,
                       control: tempfile::TempDir,
                       result: tempfile::TempDir,
                       child: Option<Child>| {
        let record = QuarantineRecord {
            reason,
            pgid: pgid as u32,
            bound_ticks: prepare::group_bound_ticks_now(),
            control_dir: Some(control.path().to_string_lossy().into_owned()),
            result_dir: Some(result.path().to_string_lossy().into_owned()),
            created_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        retain_containment(
            &stage_root,
            Contained {
                record,
                _pins: pins,
                _control: control,
                _result: result,
                _child: child,
            },
        )
    };
    // Every post-spawn path confirms the whole process group is dead before
    // the control/result guards and mount pins are released.
    let exit = match wait_child(&mut child, deadline) {
        Ok(status) => status,
        Err(WaitError::TimedOut) => {
            let cleanup =
                prepare::contain_group(Some(&mut child), pgid, Instant::now() + CLEANUP_GRACE);
            match cleanup {
                prepare::Containment::Confirmed => {
                    let outcome_path = result_dir.path().join("outcome.json");
                    return match read_expected_outcome(&outcome_path, &job_id) {
                        Ok(_) => Err(crate::Error::isolation_unavailable(
                            "the micro-VM wrote an outcome but did not shut down before its deadline",
                        )),
                        Err(_) => Ok(timeout_outcome()),
                    };
                }
                prepare::Containment::Unconfirmed { live } => {
                    return Err(quarantined(
                        format!(
                            "the micro-VM outlived its deadline and its group survived (live pids {live:?})"
                        ),
                        pins,
                        control_dir,
                        result_dir,
                        Some(child),
                    ));
                }
            }
        }
        Err(WaitError::Failed(error)) => {
            match prepare::contain_group(Some(&mut child), pgid, Instant::now() + CLEANUP_GRACE) {
                prepare::Containment::Confirmed => {
                    return Err(crate::Error::isolation_unavailable(format!(
                        "wait for QEMU: {error}"
                    )));
                }
                prepare::Containment::Unconfirmed { live } => {
                    return Err(quarantined(
                        format!(
                            "the QEMU wait failed ({error}) and the group survived (live pids {live:?})"
                        ),
                        pins,
                        control_dir,
                        result_dir,
                        Some(child),
                    ));
                }
            }
        }
    };
    // The leader was reaped by wait_child; containment now uses exact-pid
    // kills only, because a group id may be reused after the leader is gone.
    match prepare::contain_group(None, pgid, Instant::now() + CLEANUP_GRACE) {
        prepare::Containment::Confirmed => {}
        prepare::Containment::Unconfirmed { live } => {
            return Err(quarantined(
                format!("the exited micro-VM left group members alive (live pids {live:?})"),
                pins,
                control_dir,
                result_dir,
                None,
            ));
        }
    }
    if !exit.success() {
        return Err(crate::Error::isolation_unavailable(format!(
            "QEMU exited unsuccessfully: {exit}"
        )));
    }
    read_expected_outcome(&result_dir.path().join("outcome.json"), &job_id)
}

/// LV-03: the checked absolute deadline is computed before any spawn. A
/// representability failure returns before QEMU exists, so no live VM is ever
/// left with dropped stage/control/result guards (the Windows VW-02 class).
fn boot_deadline(timeout: Duration) -> crate::Result<Instant> {
    let total = timeout.checked_add(BOOT_GRACE).ok_or_else(|| {
        crate::Error::isolation_unavailable("job timeout plus boot grace cannot be represented")
    })?;
    Instant::now()
        .checked_add(total)
        .ok_or_else(|| crate::Error::isolation_unavailable("job deadline cannot be represented"))
}

/// Render the QEMU command line with explicit MMIO devices (CR-025). Paths are
/// separate arguments (no shell) and each share path is comma-escaped (LV-04);
/// the command line otherwise carries only validated hex/numeric identity.
fn render_qemu_args(
    state: &VmState,
    shares: &[Share],
    job: &JobSpec,
    job_id: &str,
    uid: u32,
    gid: u32,
    inputs: usize,
) -> crate::Result<Vec<OsString>> {
    if !valid_job_id(job_id) {
        return Err(crate::Error::integrity("invalid VM job identity"));
    }
    let memory = job.limits.memory_bytes.unwrap_or(512 * 1024 * 1024);
    let mib = memory
        .saturating_add(512 * 1024 * 1024)
        .div_ceil(1024 * 1024);
    let mib = u32::try_from(mib)
        .map_err(|_| crate::Error::isolation_unavailable("VM memory limit is out of range"))?;
    let restrict = if job.network == crate::isolation::NetworkMode::Internet {
        "off"
    } else {
        "on"
    };
    // LV-01: the required input share count travels to init so it mounts
    // exactly the supplied slots and fails closed on a required mount error.
    let append = format!(
        "console=ttyS0 quiet f2c_job_id={job_id} f2c_uid={uid} f2c_gid={gid} f2c_inputs={inputs}"
    );
    let mut a: Vec<OsString> = Vec::new();
    let mut push = |items: &[&str]| a.extend(items.iter().map(OsString::from));
    push(&["-M", "microvm,accel=kvm", "-cpu", "host"]);
    push(&["-kernel", &state.kernel]);
    push(&["-initrd", &state.initramfs]);
    push(&["-append", &append]);
    push(&["-m", &mib.to_string()]);
    push(&["-smp", "2", "-no-reboot", "-nographic", "-nodefaults"]);
    for share in shares {
        // LV-05: a pinned share is mapped through its inherited fd, which always
        // resolves to the pinned inode regardless of any later pathname swap.
        // LV-04: an unpinned path must be UTF-8 and comma-escaped per QEMU's
        // option syntax so it cannot redirect the share or inject a suboption.
        let path = match share.fd {
            Some(fd) => format!("/proc/self/fd/{fd}"),
            None => share
                .host
                .to_str()
                .ok_or_else(|| {
                    crate::Error::isolation_unavailable("VM share path is not valid UTF-8")
                })?
                .to_owned(),
        };
        let mut fsdev = format!(
            "local,id={},path={},security_model=passthrough",
            share.tag,
            escape_qemu_option_value(&path)
        );
        if share.read_only {
            fsdev.push_str(",readonly=on");
        }
        let device = format!(
            "virtio-9p-device,fsdev={},mount_tag={}",
            share.tag, share.tag
        );
        push(&["-fsdev", &fsdev]);
        push(&["-device", &device]);
    }
    let netdev = format!("user,id=n,restrict={restrict}");
    push(&["-netdev", &netdev]);
    push(&["-device", "virtio-net-device,netdev=n"]);
    Ok(a)
}

/// QEMU parses commas as suboption separators; its invocation reference
/// requires doubling a literal comma inside an option value (LV-04). Without
/// this, a stage path containing a comma — or a segment resembling another
/// `-fsdev` suboption — could point the share elsewhere or alter parsed options.
fn escape_qemu_option_value(value: &str) -> String {
    value.replace(',', ",,")
}

fn remap_job(
    job: &JobSpec,
    paths: &ValidatedPaths,
    mappings: &HostMappings,
) -> crate::Result<JobSpec> {
    let guest_path = |path: &Path| -> crate::Result<PathBuf> {
        let source = path.canonicalize().map_err(|e| {
            crate::Error::isolation_unavailable(format!("canonicalize job path: {e}"))
        })?;
        for (host, guest) in &mappings.entries {
            if path_under(&source, host) {
                let relative = source.strip_prefix(host).map_err(|_| {
                    crate::Error::integrity("canonical job path prefix changed during VM staging")
                })?;
                return Ok(guest.join(relative));
            }
        }
        // A system tool stays at its shared host path inside the guest.
        if SYSTEM_DIRS
            .iter()
            .any(|d| path_under(&source, Path::new(d)))
        {
            return Ok(source);
        }
        Err(crate::Error::isolation_unavailable(format!(
            "job path is outside its assigned VM mounts: {}",
            path.display()
        )))
    };
    let translate_text = |value: &std::ffi::OsStr| -> crate::Result<OsString> {
        let mut text = value
            .to_str()
            .ok_or_else(|| {
                crate::Error::isolation_unavailable(
                    "VM job has a non-UTF-8 argument or environment value",
                )
            })?
            .to_owned();
        for (host, guest) in &mappings.entries {
            let new = guest.to_string_lossy();
            text = replace_path_text(&text, &host.to_string_lossy(), &new);
        }
        Ok(text.into())
    };
    let env = job
        .env
        .iter()
        .map(|(k, v)| Ok((translate_text(k)?, translate_text(v)?)))
        .collect::<crate::Result<Vec<_>>>()?;
    Ok(JobSpec {
        program: guest_path(&paths.program)?,
        args: job
            .args
            .iter()
            .map(|a| translate_text(a))
            .collect::<crate::Result<_>>()?,
        cwd: guest_path(&paths.cwd)?,
        env,
        read_only: paths
            .read_only
            .iter()
            .map(|p| guest_path(p))
            .collect::<crate::Result<_>>()?,
        work_dir: mappings.guest_work.clone(),
        exports: job.exports.clone(),
        export_to: None,
        limits: job.limits.clone(),
        network: job.network,
        bait: job.bait,
    })
}

/// Case-sensitive, boundary-aware path replacement (Linux paths are
/// case-sensitive). Only whole path segments are rewritten.
fn replace_path_text(value: &str, source: &str, replacement: &str) -> String {
    if source.is_empty() {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while cursor < value.len() {
        let found = value[cursor..]
            .match_indices(source)
            .find_map(|(relative, _)| {
                let start = cursor + relative;
                let end = start + source.len();
                let before_ok = start == 0
                    || value[..start].chars().next_back().is_some_and(|c| {
                        c.is_whitespace() || matches!(c, '=' | ':' | '\'' | '"' | ',')
                    });
                let after = value[end..].chars().next();
                let after_ok = after.is_none_or(|c| {
                    c.is_whitespace() || matches!(c, '/' | ';' | '\'' | '"' | ',' | ')' | ']' | '=')
                });
                (before_ok && after_ok).then_some((start, end))
            });
        let Some((start, end)) = found else {
            out.push_str(&value[cursor..]);
            break;
        };
        out.push_str(&value[cursor..start]);
        out.push_str(replacement);
        cursor = end;
    }
    out
}

fn write_new_file(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| crate::Error::isolation_unavailable(format!("create VM job file: {e}")))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Read only a bounded, identity-bound outcome from this run's result share.
fn read_expected_outcome(path: &Path, job_id: &str) -> crate::Result<JobOutcome> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            crate::Error::isolation_unavailable(format!("VM outcome is missing or unreadable: {e}"))
        })?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.nlink() != 1
        || meta.len() > MAX_VM_OUTCOME_BYTES as u64
    {
        return Err(crate::Error::integrity(
            "VM outcome is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_VM_OUTCOME_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| crate::Error::integrity(format!("read VM outcome: {e}")))?;
    if bytes.len() as u64 != meta.len() {
        return Err(crate::Error::integrity(
            "VM outcome changed during bounded read",
        ));
    }
    protocol::decode_vm_outcome(job_id, &bytes)
}

enum WaitError {
    TimedOut,
    Failed(String),
}

fn wait_child(child: &mut Child, deadline: Instant) -> Result<std::process::ExitStatus, WaitError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => return Err(WaitError::TimedOut),
            Err(e) => return Err(WaitError::Failed(e.to_string())),
        }
    }
}

fn timeout_outcome() -> JobOutcome {
    JobOutcome {
        status: JobStatus::TimedOut,
        stdout: vec![],
        stderr: b"the micro-VM job exceeded its deadline and the VM was terminated".to_vec(),
        truncated: false,
        exported: vec![],
        report: ActivityReport::default(),
    }
}

fn valid_job_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn path_under(child: &Path, parent: &Path) -> bool {
    let mut child = child.components();
    let mut parent = parent.components();
    loop {
        match (child.next(), parent.next()) {
            (_, None) => return true,
            (Some(a), Some(b)) if a.as_os_str() == b.as_os_str() => {}
            _ => return false,
        }
    }
}

/// Linux staged-path validation mirroring the AppContainer common-stage rules:
/// one fail2commit-owned job stage, no link escapes, resolved identities.
struct ValidatedPaths {
    program: PathBuf,
    cwd: PathBuf,
    read_only: Vec<PathBuf>,
    work_dir: PathBuf,
    identities: Vec<(PathBuf, (u64, u64))>,
}

impl ValidatedPaths {
    fn new(job: &JobSpec, stage_root: &Path) -> crate::Result<Self> {
        let work_dir = canonical_dir(&job.work_dir, "work_dir")?;
        let cwd = canonical_dir(&job.cwd, "cwd")?;
        let program = canonical_file(&job.program, "program")?;
        let read_only = job
            .read_only
            .iter()
            .map(|p| canonical_dir(p, "read_only"))
            .collect::<crate::Result<Vec<_>>>()?;
        if read_only.is_empty() {
            return Err(crate::Error::isolation_unavailable(
                "at least one staged read-only root is required",
            ));
        }
        if !path_under(&cwd, &work_dir) {
            return Err(crate::Error::isolation_unavailable(
                "cwd is outside the writable work_dir",
            ));
        }
        let program_ok = read_only.iter().any(|p| path_under(&program, p))
            || SYSTEM_DIRS
                .iter()
                .any(|d| path_under(&program, Path::new(d)));
        if !program_ok {
            return Err(crate::Error::isolation_unavailable(
                "program is outside staged read_only roots and system tools",
            ));
        }
        if read_only
            .iter()
            .any(|p| path_under(p, &work_dir) || path_under(&work_dir, p))
        {
            return Err(crate::Error::isolation_unavailable(
                "read_only and work_dir must not overlap",
            ));
        }
        let stage_root = stage_root.canonicalize().map_err(|e| {
            crate::Error::isolation_unavailable(format!("canonicalize stage root: {e}"))
        })?;
        if !path_under(&work_dir, &stage_root) {
            return Err(crate::Error::isolation_unavailable(
                "work_dir is outside the fail2commit sandbox stage root",
            ));
        }
        let stage = first_child_under(&stage_root, &work_dir).ok_or_else(|| {
            crate::Error::isolation_unavailable("work_dir must be inside a job stage")
        })?;
        if stage == stage_root {
            return Err(crate::Error::isolation_unavailable(
                "work_dir must be inside a job stage, not the stage root itself",
            ));
        }
        if !read_only.iter().all(|p| path_under(p, &stage)) {
            return Err(crate::Error::isolation_unavailable(
                "all granted paths must share one fail2commit job stage",
            ));
        }
        let mut identities = Vec::new();
        identities.push((stage_root.clone(), identity(&stage_root)?));
        identities.push((work_dir.clone(), identity(&work_dir)?));
        for root in &read_only {
            walk_plain(root, &mut identities)?;
        }
        identities.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Self {
            program,
            cwd,
            read_only,
            work_dir,
            identities,
        })
    }
}

/// A pinned share anchor: the parent descriptor (kept close-on-exec, R2-03)
/// and the fixed child-side slot number QEMU will see.
struct PinnedShare {
    file: File,
    slot: RawFd,
}

/// First fixed child-side descriptor slot for share pins. 0/1/2 are stdio and
/// QEMU's own low descriptors; high fixed slots avoid collision with anything
/// QEMU opens after exec (the kernel allocates lowest-free, so it never takes
/// 64+ while lower numbers are available).
const PIN_SLOT_BASE: RawFd = 64;

/// Pin each share's mount anchor with an O_PATH descriptor and assign it a
/// fixed child-side slot so QEMU maps `/proc/self/fd/<slot>` (LV-05).
///
/// `O_PATH` alone does NOT block pathname replacement: `rename(2)` leaves open
/// descriptors untouched, so the pinned inode and a later pathname can diverge.
/// The fd-backed slot resolves to the pinned inode no matter what happens to
/// the pathname afterwards. R2-03: the parent descriptor stays FD_CLOEXEC —
/// unrelated children never inherit it — and only the QEMU spawn installs the
/// slot allowlist via `add_slot_inheritance`. Job anchors are checked against
/// the re-walked identity; control/result are fresh per-run dirs and system
/// shares are root-owned. Pins stay open until the process group is dead.
fn pin_shares(
    shares: &mut [Share],
    identities: &[(PathBuf, (u64, u64))],
) -> crate::Result<Vec<PinnedShare>> {
    let mut held = Vec::new();
    for (index, share) in shares.iter_mut().enumerate() {
        let path = &share.host;
        let md = fs::symlink_metadata(path)?;
        if !md.is_dir() {
            return Err(crate::Error::integrity(format!(
                "VM share anchor is not a directory: {}",
                path.display()
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| {
                crate::Error::integrity(format!("pin VM share {}: {e}", path.display()))
            })?;
        let actual = identity_of(&file)?;
        if let Some((_, expected)) = identities.iter().find(|(p, _)| p == path) {
            if actual != *expected {
                return Err(crate::Error::integrity(format!(
                    "staged object identity changed before VM mapping: {}",
                    path.display()
                )));
            }
        }
        // R2-03: the parent keeps FD_CLOEXEC (std sets it on every open); the
        // slot is duplicated into place only inside the QEMU child pre_exec.
        // SAFETY: F_GETFD on a live fd we own only reads descriptor flags.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
            return Err(crate::Error::integrity(
                "VM share pin must stay close-on-exec in the parent",
            ));
        }
        let slot = PIN_SLOT_BASE + index as RawFd;
        share.fd = Some(slot);
        held.push(PinnedShare { file, slot });
    }
    Ok(held)
}

/// Register the QEMU-only descriptor allowlist on the command: in the forked
/// child before exec, duplicate each pinned source fd onto its fixed slot and
/// clear close-on-exec on the slot, so exactly these descriptors survive exec.
/// The parent's source descriptors keep FD_CLOEXEC and are never handed to any
/// other spawn (R2-03).
fn add_slot_inheritance(cmd: &mut Command, pairs: Vec<(RawFd, RawFd)>) {
    // SAFETY: the pre_exec hook runs in the child between fork and exec, so it
    // only calls async-signal-safe functions (dup2, fcntl) and reads a slice
    // allocated before the fork; no allocation, lock, or other libc state is
    // touched. Failures abort the spawn, which is fail closed.
    unsafe {
        cmd.pre_exec(move || {
            for (src, slot) in pairs.iter() {
                loop {
                    // SAFETY: dup2/fcntl as above on descriptor numbers we own.
                    let dup = unsafe { libc::dup2(*src, *slot) };
                    if dup >= 0 {
                        break;
                    }
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(err);
                }
                if unsafe { libc::fcntl(*slot, libc::F_SETFD, 0) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        })
    };
}

fn identity(path: &Path) -> crate::Result<(u64, u64)> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Err(crate::Error::integrity(format!(
            "staged path is a symlink: {}",
            path.display()
        )));
    }
    Ok((md.dev(), md.ino()))
}

fn identity_of(file: &File) -> crate::Result<(u64, u64)> {
    // SAFETY: stat is a correctly sized writable buffer for this live fd.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(crate::Error::integrity("fstat of pinned VM mount failed"));
    }
    Ok((stat.st_dev, stat.st_ino))
}

use std::os::fd::{AsRawFd, RawFd};

fn walk_plain(root: &Path, identities: &mut Vec<(PathBuf, (u64, u64))>) -> crate::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        if identities.len() > MAX_STAGE_OBJECTS {
            return Err(crate::Error::isolation_unavailable(
                "staged read-only tree is too large",
            ));
        }
        let md = fs::symlink_metadata(&path)?;
        if md.file_type().is_symlink() {
            return Err(crate::Error::rejected(format!(
                "staged read-only object is a symlink: {}",
                path.display()
            )));
        }
        if md.is_file() && md.nlink() > 1 {
            return Err(crate::Error::rejected(format!(
                "staged read-only object is hard-linked: {}",
                path.display()
            )));
        }
        identities.push((path.clone(), (md.dev(), md.ino())));
        if md.is_dir() {
            for entry in fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        }
    }
    Ok(())
}

fn canonical_dir(path: &Path, label: &str) -> crate::Result<PathBuf> {
    let p = canonical_existing(path, label)?;
    if !p.is_dir() {
        return Err(crate::Error::isolation_unavailable(format!(
            "{label} is not a directory"
        )));
    }
    Ok(p)
}

fn canonical_file(path: &Path, label: &str) -> crate::Result<PathBuf> {
    let p = canonical_existing(path, label)?;
    if !p.is_file() {
        return Err(crate::Error::isolation_unavailable(format!(
            "{label} is not a file"
        )));
    }
    Ok(p)
}

fn canonical_existing(path: &Path, label: &str) -> crate::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(crate::Error::isolation_unavailable(format!(
            "{label} must be absolute"
        )));
    }
    path.canonicalize().map_err(|e| {
        crate::Error::isolation_unavailable(format!("canonicalize {label} {}: {e}", path.display()))
    })
}

fn first_child_under(parent: &Path, path: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(parent).ok()?;
    let first = relative.components().next()?;
    Some(parent.join(first.as_os_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::JobLimits;
    use std::os::unix::fs::PermissionsExt;

    fn job() -> JobSpec {
        JobSpec {
            program: PathBuf::from("/stage/job/input-0/tool"),
            args: vec!["--ok".into()],
            cwd: PathBuf::from("/stage/job/work"),
            env: vec![],
            read_only: vec![PathBuf::from("/stage/job/input-0")],
            work_dir: PathBuf::from("/stage/job/work"),
            exports: vec![],
            export_to: None,
            limits: JobLimits {
                timeout: Duration::from_secs(10),
                memory_bytes: Some(256 * 1024 * 1024),
                max_processes: Some(8),
                max_output_bytes: 4096,
                disk_bytes: Some(1024 * 1024),
            },
            network: crate::isolation::NetworkMode::None,
            bait: true,
        }
    }

    fn state() -> VmState {
        VmState {
            version: 1,
            kernel_release: "6.12.0".into(),
            kernel: "/boot/vmlinuz-6.12.0".into(),
            kernel_sha256: "k".into(),
            initramfs: "/var/lib/fail2commit-vm/initramfs.cpio".into(),
            initramfs_sha256: "i".into(),
            qemu: "/usr/bin/qemu-system-x86_64".into(),
            qemu_sha256: "q".into(),
            qemu_version: "QEMU 9.0".into(),
            system_shares: vec!["/usr".into()],
            module_names: vec![],
            max_inputs: 3,
            created_unix: 0,
        }
    }

    fn shares() -> Vec<Share> {
        vec![
            Share {
                host: "/usr".into(),
                tag: "f2cusr".into(),
                read_only: true,
                fd: None,
            },
            Share {
                host: "/stage/job/input-0".into(),
                tag: "f2cin0".into(),
                read_only: true,
                fd: None,
            },
            Share {
                host: "/stage/job/work".into(),
                tag: "f2cwork".into(),
                read_only: false,
                fd: None,
            },
            Share {
                host: "/stage/control".into(),
                tag: "f2cctl".into(),
                read_only: true,
                fd: None,
            },
            Share {
                host: "/stage/result".into(),
                tag: "f2cres".into(),
                read_only: false,
                fd: None,
            },
        ]
    }

    #[test]
    fn qemu_uses_explicit_mmio_devices_and_no_pci_shorthand() {
        let id = "0123456789abcdef0123456789abcdef";
        let args = render_qemu_args(&state(), &shares(), &job(), id, 1000, 1000, 1).unwrap();
        let text: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = text.join(" ");
        assert!(joined.contains("-M microvm,accel=kvm"));
        assert!(joined.contains("virtio-9p-device,fsdev=f2cusr,mount_tag=f2cusr"));
        assert!(joined.contains("virtio-net-device,netdev=n"));
        assert!(!joined.contains("-virtfs"));
        assert!(!joined.contains("virtio-net-pci"));
        assert!(joined.contains("readonly=on"));
        assert!(joined.contains("restrict=on"));
        assert!(joined.contains(&format!("f2c_job_id={id}")));
        assert!(joined.contains("f2c_uid=1000"));
        assert!(joined.contains("f2c_inputs=1"));
        // The writable work share is not marked readonly.
        let work_fsdev = text.iter().find(|a| a.contains("id=f2cwork,")).unwrap();
        assert!(!work_fsdev.contains("readonly=on"));
    }

    #[test]
    fn internet_mode_opens_slirp_and_identity_is_validated() {
        let id = "0123456789abcdef0123456789abcdef";
        let mut j = job();
        j.network = crate::isolation::NetworkMode::Internet;
        let args = render_qemu_args(&state(), &shares(), &j, id, 1000, 1000, 1).unwrap();
        let joined: String = args
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("restrict=off"));
        assert!(render_qemu_args(&state(), &shares(), &j, "bad/id", 1000, 1000, 1).is_err());
    }

    /// QEMU's documented suboption grammar: options are separated by single
    /// commas and a doubled comma is a literal comma inside a value. Mirrors
    /// qemu-option.c splitting so the escaping is checked without QEMU; the
    /// real-parser check is a boot gate.
    fn qemu_split_options(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == ',' {
                if chars.peek() == Some(&',') {
                    cur.push(',');
                    chars.next();
                } else {
                    out.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(c);
            }
        }
        out.push(cur);
        out
    }

    #[test]
    fn fsdev_paths_escape_commas_and_option_looking_segments() {
        let id = "0123456789abcdef0123456789abcdef";
        let mut sh = shares();
        // A comma-bearing stage path whose segment resembles another suboption.
        sh[1].host = PathBuf::from("/stage/a,b/input,readonly=on");
        let args = render_qemu_args(&state(), &sh, &job(), id, 1000, 1000, 1).unwrap();
        let text: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let fsdev = text.iter().find(|a| a.contains("id=f2cin0,")).unwrap();
        // The raw argument doubles every literal comma.
        assert!(fsdev.contains("path=/stage/a,,b/input,,readonly=on"));
        // Parsed with QEMU's grammar the path round-trips exactly and no extra
        // suboption is injected.
        let opts = qemu_split_options(fsdev);
        let path_opt = opts.iter().find(|o| o.starts_with("path=")).unwrap();
        assert_eq!(path_opt, "path=/stage/a,b/input,readonly=on");
        let keys: Vec<&str> = opts.iter().map(|o| o.split('=').next().unwrap()).collect();
        assert_eq!(keys, ["local", "id", "path", "security_model", "readonly"]);
    }

    #[test]
    fn non_utf8_share_paths_are_rejected_not_lossily_converted() {
        use std::os::unix::ffi::OsStringExt;
        let id = "0123456789abcdef0123456789abcdef";
        let mut sh = shares();
        sh[1].host = PathBuf::from(std::ffi::OsString::from_vec(b"/stage/\xff\xfe".to_vec()));
        assert!(render_qemu_args(&state(), &sh, &job(), id, 1000, 1000, 1).is_err());
    }

    #[test]
    fn device_limit_is_enforced() {
        let mut many = shares();
        for i in 0..6 {
            many.push(Share {
                host: format!("/x{i}").into(),
                tag: format!("t{i}"),
                read_only: true,
                fd: None,
            });
        }
        // 11 shares + 1 network exceeds the 8-device microvm limit.
        assert!(many.len() + 1 > MICROVM_MAX_DEVICES);
    }

    #[test]
    fn outcome_reader_rejects_missing_oversized_and_forged_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outcome.json");
        let id = "0123456789abcdef0123456789abcdef";
        assert!(read_expected_outcome(&path, id).is_err());
        let outcome = JobOutcome {
            status: JobStatus::Exited(0),
            stdout: b"ok".to_vec(),
            stderr: vec![],
            truncated: false,
            exported: vec![],
            report: ActivityReport::default(),
        };
        fs::write(&path, protocol::encode_vm_outcome(id, &outcome).unwrap()).unwrap();
        assert_eq!(read_expected_outcome(&path, id).unwrap(), outcome);
        // A different run identity is refused.
        assert!(read_expected_outcome(&path, "1123456789abcdef0123456789abcdef").is_err());
        fs::write(&path, vec![b'x'; MAX_VM_OUTCOME_BYTES + 1]).unwrap();
        assert!(read_expected_outcome(&path, id).is_err());
    }

    #[test]
    fn path_replacement_is_case_sensitive_and_boundary_aware() {
        let out = replace_path_text("--src=/stage/job/work/x", "/stage/job/work", "/g/work");
        assert_eq!(out, "--src=/g/work/x");
        // A prefix that is not a whole segment is left alone.
        let out = replace_path_text("/stage/job/workextra", "/stage/job/work", "/g/work");
        assert_eq!(out, "/stage/job/workextra");
        // Case-sensitive: uppercase host path is not rewritten.
        let out = replace_path_text("/STAGE/job/work", "/stage/job/work", "/g/work");
        assert_eq!(out, "/STAGE/job/work");
    }

    #[test]
    fn kvm_absence_classification_distinguishes_feature_from_permission() {
        // Pure classification helpers used by preflight; the device itself is
        // exercised only in the VM gate.
        assert!(valid_job_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_job_id("ABC"));
        assert!(path_under(Path::new("/usr/bin/bash"), Path::new("/usr")));
        assert!(!path_under(Path::new("/usrlocal/bin"), Path::new("/usr")));
    }

    #[test]
    fn boot_deadline_is_checked_before_any_spawn() {
        // LV-03: the representability check that used to run after spawn now
        // runs before it; an overflowing timeout yields an error, not a VM.
        assert!(boot_deadline(Duration::MAX).is_err());
        assert!(boot_deadline(Duration::from_secs(u64::MAX)).is_err());
        assert!(boot_deadline(Duration::from_secs(10)).is_ok());
    }

    #[test]
    fn contain_group_confirms_descendant_death() {
        // A group leader that backgrounds a long-lived descendant: the cleanup
        // must kill and confirm the whole group, not just reap the leader.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("desc.pid");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "sleep 30 & echo $! > '{}'; wait",
                pidfile.display()
            ))
            .process_group(0)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pidfile.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let desc_pid: i32 = fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: a zero signal only probes existence of the descendant.
        assert_eq!(
            unsafe { libc::kill(desc_pid, 0) },
            0,
            "descendant must be alive"
        );
        let pgid = child.id() as i32;
        let containment = prepare::contain_group(
            Some(&mut child),
            pgid,
            Instant::now() + Duration::from_secs(10),
        );
        assert!(
            matches!(containment, prepare::Containment::Confirmed),
            "{containment:?}"
        );
        let until = Instant::now() + Duration::from_secs(2);
        // SAFETY: a zero signal only probes existence of the descendant.
        while unsafe { libc::kill(desc_pid, 0) } == 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: final zero-signal probe of the descendant.
        assert_eq!(
            unsafe { libc::kill(desc_pid, 0) },
            -1,
            "descendant reaped and gone"
        );
    }

    /// Restores FAIL2COMMIT_HOME even if a sentinel assertion panics.
    struct HomeEnvGuard {
        prev: Option<OsString>,
    }
    impl Drop for HomeEnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("FAIL2COMMIT_HOME", v),
                None => std::env::remove_var("FAIL2COMMIT_HOME"),
            }
        }
    }

    /// Serializes tests that relocate FAIL2COMMIT_HOME and drive run_job.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// A minimal fake QEMU: records its sentinel marker and exits cleanly.
    fn plain_fake_qemu(home: &Path, tag: &str) -> (PathBuf, PathBuf) {
        let sentinel = home.join(format!("sentinel-{tag}"));
        let qemu = home.join(format!("fake-qemu-{tag}"));
        fs::write(
            &qemu,
            format!(
                "#!/bin/sh\necho spawned > '{}'\nexit 0\n",
                sentinel.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&qemu, fs::Permissions::from_mode(0o755)).unwrap();
        (qemu, sentinel)
    }

    fn run_job_retry_txtbsy(host: &ReadyHost, job: &JobSpec) -> crate::Result<JobOutcome> {
        // The just-written-script fork race can surface ETXTBSY in tests;
        // production keeps the single bounded spawn failure.
        let mut attempts = 0;
        loop {
            let result = run_job(host, job);
            let busy = result
                .as_ref()
                .err()
                .is_some_and(|e| e.message.contains("Text file busy"));
            if busy && attempts < 10 {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            return result;
        }
    }

    #[test]
    fn overflow_timeout_never_spawns_qemu() {
        // LV-03 spawn sentinel: a fake QEMU records a marker when launched. An
        // unrepresentable timeout must refuse before any spawn (marker absent);
        // a representable timeout spawns and then reports the missing outcome.
        let _g = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("FAIL2COMMIT_HOME");
        std::env::set_var("FAIL2COMMIT_HOME", home.path());
        let _restore = HomeEnvGuard { prev };

        let stage_root = home.path().join("cache").join("sandbox-stage");
        let stage = stage_root.join("job-sentinel");
        let work = stage.join("work");
        let input = stage.join("input-0");
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&input).unwrap();
        fs::write(input.join("tool"), b"#!/bin/sh\n").unwrap();
        let (qemu, sentinel) = plain_fake_qemu(home.path(), "sentinel");

        let mut st = state();
        st.qemu = qemu.to_string_lossy().into_owned();
        st.system_shares = vec![];
        let host = ReadyHost { state: st };
        let mut j = job();
        j.program = input.join("tool");
        j.cwd = work.clone();
        j.work_dir = work.clone();
        j.read_only = vec![input.clone()];

        // Overflow: refused before spawn, so the sentinel never appears.
        j.limits.timeout = Duration::MAX;
        let err = run_job(&host, &j).expect_err("overflow timeout must be refused");
        assert!(err.message.contains("represented"), "{}", err.message);
        assert!(!sentinel.exists(), "QEMU must not spawn on overflow");

        // Control: a representable timeout spawns (sentinel appears), the fake
        // QEMU exits cleanly, and the missing outcome is reported after the
        // process group is confirmed dead.
        j.limits.timeout = Duration::from_secs(2);
        let err2 = run_job_retry_txtbsy(&host, &j).expect_err("no outcome was written");
        assert!(sentinel.exists(), "control case must spawn QEMU");
        assert!(err2.message.contains("outcome"), "{}", err2.message);
    }

    #[test]
    fn unconfirmed_containment_retains_guards_and_recovers() {
        // R2-01 production resource-guard path. A fake QEMU leaves a group
        // member that containment provably cannot confirm dead: the member
        // (Z) stays in QEMU's process group; its parent (H) moves itself out
        // of that group and never reaps. SIGKILL to Z therefore leaves an
        // unreaped zombie member forever, so contain_group expires
        // Unconfirmed and run_job must retain every mapped guard, persist a
        // durable quarantine, refuse later VM runs while the identity is
        // live, and recover only after it is gone.
        let _g = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("FAIL2COMMIT_HOME");
        std::env::set_var("FAIL2COMMIT_HOME", home.path());
        let _restore = HomeEnvGuard { prev };

        let stage_root = home.path().join("cache").join("sandbox-stage");
        let stage = stage_root.join("job-contain");
        let work = stage.join("work");
        let input = stage.join("input-0");
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&input).unwrap();
        fs::write(input.join("tool"), b"#!/bin/sh\n").unwrap();
        let zfile = home.path().join("z.pid");
        let moved = home.path().join("h.moved");
        let hfile = home.path().join("h.pid");
        let qemu = home.path().join("fake-qemu-contain");
        fs::write(
            &qemu,
            format!(
                "#!/bin/sh\necho spawned > '@SENTINEL@'\nperl -e 'my $z=fork; exit 1 unless defined $z; if($z==0){{ sleep 60; exit }} open(F,\">\",\"{zfile}\") or exit 1; print F \"$z\\n\"; close F; syscall(109,0,0); open(G,\">\",\"{moved}\") or exit 1; close G; sleep 600;' &\nhp=$!\necho $hp > '{hfile}'\ni=0; while [ ! -s '{moved}' ] && [ $i -lt 200 ]; do i=$((i+1)); sleep 0.05; done\nexit 0\n",
                zfile = zfile.display(),
                moved = moved.display(),
                hfile = hfile.display(),
            )
            .replace("@SENTINEL@", &home.join("sentinel-contain").display().to_string()),
        )
        .unwrap();
        fs::set_permissions(&qemu, fs::Permissions::from_mode(0o755)).unwrap();
        let sentinel = home.join("sentinel-contain");

        let mut st = state();
        st.qemu = qemu.to_string_lossy().into_owned();
        st.system_shares = vec![];
        let host = ReadyHost { state: st };
        let mut j = job();
        j.program = input.join("tool");
        j.cwd = work.clone();
        j.work_dir = work.clone();
        j.read_only = vec![input.clone()];
        j.limits.timeout = Duration::from_secs(2);

        let err = run_job_retry_txtbsy(&host, &j)
            .err()
            .expect("unkillable group member must fail containment");
        assert!(
            err.message.contains("containment unconfirmed"),
            "{}",
            err.message
        );
        assert!(sentinel.exists());

        // Durable refusal/recovery state exists and the retained guards are
        // still on disk: containment failure must not delete mapped exchanges.
        let qpath = stage_root.join(CONTAINMENT_FILE);
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&qpath).unwrap()).unwrap();
        let records = doc["records"].as_array().unwrap();
        let rec = records.last().unwrap().clone();
        let control = rec["control_dir"].as_str().unwrap().to_owned();
        let result = rec["result_dir"].as_str().unwrap().to_owned();
        assert!(Path::new(&control).is_dir(), "control guard released");
        assert!(Path::new(&result).is_dir(), "result guard released");

        // While the contained identity is live, later runs refuse before any
        // spawn (production guard at the run_job entry, R2-01).
        let (qemu2, sentinel2) = plain_fake_qemu(home.path(), "refused");
        let mut st2 = state();
        st2.qemu = qemu2.to_string_lossy().into_owned();
        st2.system_shares = vec![];
        let host2 = ReadyHost { state: st2 };
        let err2 = run_job(&host2, &j).expect_err("contained VM must refuse new runs");
        assert!(err2.message.contains("contained"), "{}", err2.message);
        assert!(!sentinel2.exists(), "refusal must not spawn QEMU");

        // Recovery: end H, so the kernel reparents and reaps Z's zombie; the
        // exact group identity disappears and the next run recovers the
        // quarantine (drops retained guards, deletes dirs, clears the file).
        let hpid: i32 = fs::read_to_string(&hfile).unwrap().trim().parse().unwrap();
        // SAFETY: hpid is the H process this test created and tracks.
        unsafe { libc::kill(hpid, libc::SIGKILL) };
        let pgid = rec["pgid"].as_u64().unwrap() as i32;
        let bound = rec["bound_ticks"].as_u64().unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while !prepare::group_members(pgid, bound).is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            prepare::group_members(pgid, bound).is_empty(),
            "contained identity never recovered"
        );

        let (qemu3, sentinel3) = plain_fake_qemu(home.path(), "recovered");
        let mut st3 = state();
        st3.qemu = qemu3.to_string_lossy().into_owned();
        st3.system_shares = vec![];
        let host3 = ReadyHost { state: st3 };
        let err3 = run_job_retry_txtbsy(&host3, &j).expect_err("recovered run proceeds");
        assert!(err3.message.contains("outcome"), "{}", err3.message);
        assert!(sentinel3.exists(), "recovered run must spawn");
        assert!(!qpath.exists(), "quarantine record must clear");
        assert!(
            !Path::new(&control).is_dir() && !Path::new(&result).is_dir(),
            "recovery must release contained directories"
        );
    }

    #[test]
    fn fd_backed_pin_resists_pathname_swap() {
        // LV-05: a same-uid swap between validation and share-open must not
        // redirect the mapping. The pinned descriptor keeps resolving to the
        // original inode even after the pathname is attacker-replaced.
        let dir = tempfile::tempdir().unwrap();
        let anchor = dir.path().join("stage");
        fs::create_dir(&anchor).unwrap();
        fs::write(anchor.join("marker"), b"original").unwrap();
        let mut shares = vec![Share {
            host: anchor.clone(),
            tag: "f2cin0".into(),
            read_only: true,
            fd: None,
        }];
        let identities = vec![(anchor.clone(), identity(&anchor).unwrap())];
        let pins = pin_shares(&mut shares, &identities).unwrap();
        let slot = shares[0].fd.expect("share must be slot-backed");
        assert_eq!(slot, pins[0].slot);
        // R2-03: the parent descriptor stays close-on-exec.
        // SAFETY: F_GETFD reads descriptor flags of a live fd we own.
        let flags = unsafe { libc::fcntl(pins[0].file.as_raw_fd(), libc::F_GETFD) };
        assert!(
            flags >= 0 && flags & libc::FD_CLOEXEC != 0,
            "parent pin must stay close-on-exec"
        );

        // Swap: rename the validated tree away and plant an attacker tree at
        // the same pathname.
        let hidden = dir.path().join("hidden");
        fs::rename(&anchor, &hidden).unwrap();
        fs::create_dir(&anchor).unwrap();
        fs::write(anchor.join("marker"), b"attacker").unwrap();

        // The bare pathname now resolves to the attacker tree...
        assert_eq!(fs::read(anchor.join("marker")).unwrap(), b"attacker");
        // ...but the pinned descriptor still resolves to the original inode.
        let fd_path = PathBuf::from(format!("/proc/self/fd/{}", pins[0].file.as_raw_fd()));
        assert_eq!(fs::read(fd_path.join("marker")).unwrap(), b"original");
        assert_eq!(identity_of(&pins[0].file).unwrap(), identities[0].1);
    }

    #[test]
    fn slot_child_sees_pinned_inode_after_swap() {
        // R2-03: exercise the exact inheritance mechanism QEMU gets. The child
        // receives the share only on its fixed slot through the allowlist, and
        // exec'd children never see the parent source descriptor.
        let dir = tempfile::tempdir().unwrap();
        let anchor = dir.path().join("stage");
        fs::create_dir(&anchor).unwrap();
        fs::write(anchor.join("marker"), b"original").unwrap();
        let mut shares = vec![Share {
            host: anchor.clone(),
            tag: "f2cin0".into(),
            read_only: true,
            fd: None,
        }];
        let identities = vec![(anchor.clone(), identity(&anchor).unwrap())];
        let pins = pin_shares(&mut shares, &identities).unwrap();
        let slot = shares[0].fd.unwrap();
        // Swap the pathname before the child execs, like the attacker case.
        fs::rename(&anchor, dir.path().join("hidden")).unwrap();
        fs::create_dir(&anchor).unwrap();
        fs::write(anchor.join("marker"), b"attacker").unwrap();

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("cat /proc/self/fd/{slot}/marker"))
            .stdout(std::process::Stdio::piped());
        add_slot_inheritance(&mut cmd, vec![(pins[0].file.as_raw_fd(), slot)]);
        let out = cmd.output().unwrap();
        assert_eq!(out.stdout, b"original");

        // The slot survives, but nothing else of the pin leaks: a plain child
        // of the same program sees neither the source fd nor the slot.
        let plain = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "ls -l /proc/self/fd 2>/dev/null; readlink /proc/self/fd/{slot}"
            ))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&plain.stdout);
        assert!(
            !text.contains("stage") && !text.contains("hidden"),
            "unrelated child must not inherit share roots: {text}"
        );
    }

    #[test]
    fn pinned_share_renders_fd_backed_path_and_identity_change_is_refused() {
        let id = "0123456789abcdef0123456789abcdef";
        let mut sh = shares();
        sh[1].fd = Some(7);
        let args = render_qemu_args(&state(), &sh, &job(), id, 1000, 1000, 1).unwrap();
        let text: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let fsdev = text.iter().find(|a| a.contains("id=f2cin0,")).unwrap();
        assert!(fsdev.contains("path=/proc/self/fd/7,"), "{fsdev}");
        assert!(!fsdev.contains("/stage/job/input-0"));

        // A share anchor whose identity changed since the re-walk is refused.
        let dir = tempfile::tempdir().unwrap();
        let anchor = dir.path().join("stage");
        fs::create_dir(&anchor).unwrap();
        let stale = vec![(anchor.clone(), (999_999, 999_999))];
        let mut shares = vec![Share {
            host: anchor.clone(),
            tag: "f2cin0".into(),
            read_only: true,
            fd: None,
        }];
        assert!(pin_shares(&mut shares, &stale).is_err());
    }
}
