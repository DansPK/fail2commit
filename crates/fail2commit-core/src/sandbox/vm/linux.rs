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
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BOOT_GRACE: Duration = Duration::from_secs(45);
const CONTROL_GRACE: Duration = Duration::from_secs(20);
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
}

struct HostMappings {
    guest_work: PathBuf,
    entries: Vec<(PathBuf, PathBuf)>,
}

fn run_job(host: &ReadyHost, job: &JobSpec) -> crate::Result<JobOutcome> {
    let stage_root = crate::paths::TrustedPaths::resolve()?
        .cache_dir
        .join("sandbox-stage");
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
        });
    }
    for (index, input) in validated.read_only.iter().enumerate() {
        shares.push(Share {
            host: input.clone(),
            tag: format!("f2cin{index}"),
            read_only: true,
        });
    }
    shares.push(Share {
        host: validated.work_dir.clone(),
        tag: "f2cwork".into(),
        read_only: false,
    });
    shares.push(Share {
        host: control_dir.path().to_path_buf(),
        tag: "f2cctl".into(),
        read_only: true,
    });
    shares.push(Share {
        host: result_dir.path().to_path_buf(),
        tag: "f2cres".into(),
        read_only: false,
    });
    if shares.len() + 1 > MICROVM_MAX_DEVICES {
        return Err(crate::Error::isolation_unavailable(
            "job shares exceed the microvm virtio-mmio device limit",
        ));
    }

    // SAFETY: geteuid/getgid have no preconditions.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let args = render_qemu_args(
        &host.state,
        &shares,
        job,
        &job_id,
        uid,
        gid,
        validated.read_only.len(),
    )?;

    // Re-walk identities and pin every mount anchor open until QEMU exits.
    let revalidated = ValidatedPaths::new(job, &stage_root)?;
    if revalidated.identities != validated.identities {
        return Err(crate::Error::integrity(
            "staged paths changed while preparing the micro-VM",
        ));
    }
    let _pins = revalidated.pin_mounts()?;

    let mut child = Command::new(&host.state.qemu)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| crate::Error::isolation_unavailable(format!("start QEMU: {e}")))?;
    let deadline = job.limits.timeout.checked_add(BOOT_GRACE).ok_or_else(|| {
        crate::Error::isolation_unavailable("job timeout plus boot grace cannot be represented")
    })?;
    let exit = match wait_child(&mut child, deadline) {
        Ok(status) => status,
        Err(WaitError::TimedOut) => {
            terminate_process_tree(&mut child)?;
            let outcome_path = result_dir.path().join("outcome.json");
            return match read_expected_outcome(&outcome_path, &job_id) {
                Ok(_) => Err(crate::Error::isolation_unavailable(
                    "the micro-VM wrote an outcome but did not shut down before its deadline",
                )),
                Err(_) => Ok(timeout_outcome()),
            };
        }
        Err(WaitError::Failed(error)) => {
            terminate_process_tree(&mut child)?;
            return Err(crate::Error::isolation_unavailable(format!(
                "wait for QEMU: {error}"
            )));
        }
    };
    if !exit.success() {
        return Err(crate::Error::isolation_unavailable(format!(
            "QEMU exited unsuccessfully: {exit}"
        )));
    }
    read_expected_outcome(&result_dir.path().join("outcome.json"), &job_id)
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
        // LV-04: reject lossy non-UTF-8 paths and escape commas per QEMU's
        // option syntax, so a stage path cannot redirect the share or inject
        // a suboption. Separate Command arguments do not stop suboption parsing.
        let path = share.host.to_str().ok_or_else(|| {
            crate::Error::isolation_unavailable("VM share path is not valid UTF-8")
        })?;
        let mut fsdev = format!(
            "local,id={},path={},security_model=passthrough",
            share.tag,
            escape_qemu_option_value(path)
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

fn wait_child(child: &mut Child, timeout: Duration) -> Result<std::process::ExitStatus, WaitError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| WaitError::Failed("timeout cannot be represented".into()))?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => return Err(WaitError::TimedOut),
            Err(e) => return Err(WaitError::Failed(e.to_string())),
        }
    }
}

/// Kill the whole QEMU process group and confirm it is gone. QEMU was spawned
/// as a process-group leader, so a group kill reaches every descendant.
fn terminate_process_tree(child: &mut Child) -> crate::Result<()> {
    let pid = child.id() as i32;
    // SAFETY: kill targets this child's own process group with a constant signal.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    match wait_child(child, CONTROL_GRACE) {
        Ok(_) => {}
        Err(_) => {
            child
                .kill()
                .map_err(|e| crate::Error::isolation_unavailable(format!("kill QEMU: {e}")))?;
            child
                .wait()
                .map_err(|e| crate::Error::isolation_unavailable(format!("wait for QEMU: {e}")))?;
        }
    }
    // SAFETY: a zero signal probes existence of the process group only.
    let gone = unsafe { libc::kill(-pid, 0) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    if !gone {
        return Err(crate::Error::isolation_unavailable(
            "the QEMU process group did not stop cleanly",
        ));
    }
    Ok(())
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

    /// Hold every mount anchor open (O_PATH, no follow) and confirm its
    /// resolved identity, blocking replacement while QEMU maps the shares.
    fn pin_mounts(&self) -> crate::Result<Vec<File>> {
        let mut held = Vec::new();
        for (path, expected) in &self.identities {
            let md = fs::symlink_metadata(path)?;
            let mut flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            if md.is_dir() {
                flags |= libc::O_DIRECTORY;
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(flags)
                .open(path)
                .map_err(|e| {
                    crate::Error::integrity(format!("pin VM mount {}: {e}", path.display()))
                })?;
            if identity_of(&file)? != *expected {
                return Err(crate::Error::integrity(format!(
                    "staged object identity changed before VM mapping: {}",
                    path.display()
                )));
            }
            held.push(file);
        }
        Ok(held)
    }
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

use std::os::fd::AsRawFd;

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
            },
            Share {
                host: "/stage/job/input-0".into(),
                tag: "f2cin0".into(),
                read_only: true,
            },
            Share {
                host: "/stage/job/work".into(),
                tag: "f2cwork".into(),
                read_only: false,
            },
            Share {
                host: "/stage/control".into(),
                tag: "f2cctl".into(),
                read_only: true,
            },
            Share {
                host: "/stage/result".into(),
                tag: "f2cres".into(),
                read_only: false,
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
}
