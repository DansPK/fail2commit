//! Linux QEMU/KVM micro-VM preparation and lifecycle (FR-029, SPEC-019 §4.1).
//!
//! `vm prepare` (root, once) assembles a self-contained initramfs from trusted
//! host binaries, their ELF library closure (parsed, never executed via `ldd`),
//! the running distro kernel and the guest virtio/9p modules, then records
//! protected hashes in `/etc/fail2commit-vm.json`. `vm status` reports the
//! preparation and probe state; `vm remove` deletes only these artifacts,
//! idempotently. Nothing here starts a VM or changes host features.

// geteuid/uname need libc; each block has a SAFETY note.
#![allow(unsafe_code)]

use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Root-owned record of the prepared image and its hashes.
pub(crate) const STATE_FILE: &str = "/etc/fail2commit-vm.json";
/// Root-owned directory holding the prepared initramfs.
pub(crate) const LIB_DIR: &str = "/var/lib/fail2commit-vm";
const INITRAMFS_NAME: &str = "initramfs.cpio";
/// microvm exposes a fixed number of virtio-mmio transports (QEMU
/// hw/i386/microvm.c VIRTIO_NUM_TRANSPORTS). Shares plus network must fit.
const MICROVM_MAX_DEVICES: usize = 8;
/// work + control + result + network are always present.
const FIXED_DEVICES: usize = 4;
const QEMU_PATHS: [&str; 1] = ["/usr/bin/qemu-system-x86_64"];
const BASH_PATHS: [&str; 2] = ["/usr/bin/bash", "/bin/bash"];
const BWRAP_PATHS: [&str; 2] = ["/usr/bin/bwrap", "/usr/local/bin/bwrap"];
const SETPRIV_PATHS: [&str; 2] = ["/usr/bin/setpriv", "/bin/setpriv"];
const BUSYBOX_PATHS: [&str; 2] = ["/usr/bin/busybox", "/bin/busybox"];
const KMOD_PATHS: [&str; 2] = ["/usr/bin/kmod", "/bin/kmod"];
/// Guest modules the micro-VM needs for MMIO virtio and 9p (CR-025).
const GUEST_MODULES: [&str; 4] = ["virtio_mmio", "virtio_net", "9p", "9pnet_virtio"];
/// Read-only system trees shared at their host paths (SPEC-019 §4.1).
const SYSTEM_DIRS: [&str; 7] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32",
];
/// The only /etc entries copied into the initramfs (no secrets, no /etc share).
const ETC_ALLOW: [&str; 11] = [
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/alternatives",
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/ca-certificates",
];
const STANDARD_LIB_DIRS: [&str; 6] = [
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
];
/// Fixed guest location of the launcher and its relay sibling.
const GUEST_BIN_DIR: &str = "/mnt/fail2commit-vm/bin";
/// Fixed outer-guest namespace (shared with the host backend and vm_guest).
const GUEST_ROOT: &str = "/mnt/fail2commit-vm";
const CONTROL_GRACE: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_QUERY_OUTPUT: usize = 1024 * 1024;
const MAX_ETC_BYTES: u64 = 64 * 1024 * 1024;

/// Protected preparation record. Every hash is verified before the probe
/// trusts the image; the file itself must stay root-owned and non-writable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct VmState {
    pub version: u32,
    pub kernel_release: String,
    pub kernel: String,
    pub kernel_sha256: String,
    pub initramfs: String,
    pub initramfs_sha256: String,
    pub qemu: String,
    pub qemu_sha256: String,
    pub qemu_version: String,
    /// Host system directories shared read-only (real dirs, not symlinks).
    pub system_shares: Vec<String>,
    /// Guest modules init loads (empty when all are built into the kernel).
    pub module_names: Vec<String>,
    /// Input shares the device budget allows beyond the fixed devices.
    pub max_inputs: usize,
    pub created_unix: u64,
}

/// Deterministic 9p mount tag for a host system directory.
pub(crate) fn system_share_tag(dir: &str) -> String {
    format!("f2c{}", dir.trim_start_matches('/'))
}

pub fn prepare() -> crate::Result<String> {
    require_root("vm prepare")?;
    prepare_inner(Path::new(STATE_FILE), Path::new(LIB_DIR))
}

pub fn status() -> crate::Result<String> {
    status_inner(Path::new(STATE_FILE))
}

pub fn remove() -> crate::Result<String> {
    require_root("vm remove")?;
    remove_inner(Path::new(STATE_FILE), Path::new(LIB_DIR))
}

fn require_root(command: &str) -> crate::Result<()> {
    // SAFETY: geteuid has no preconditions and returns the effective uid.
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::rejected(format!(
            "{command} must run as root (sudo fail2commit {command})"
        )));
    }
    Ok(())
}

fn prepare_inner(state_path: &Path, lib_dir: &Path) -> crate::Result<String> {
    let release = kernel_release()?;
    let kernel = PathBuf::from(format!("/boot/vmlinuz-{release}"));
    let kernel = trusted_root_file(&kernel, "kernel")?;
    let kernel_sha256 = hash_file(&kernel)?;

    let qemu = QEMU_PATHS
        .iter()
        .find_map(|p| trusted_root_exe(Path::new(p)).ok())
        .ok_or_else(|| {
            Error::isolation_unavailable(
                "qemu-system-x86_64 is not installed as a trusted system executable",
            )
        })?;
    let qemu_version = verify_qemu_support(&qemu)?;
    let qemu_sha256 = hash_file(&qemu)?;

    // System shares: real directories are shared; merged-/usr symlinks are
    // recreated inside the initramfs instead of consuming a device.
    let mut system_shares = Vec::new();
    let mut symlinks = Vec::new();
    for dir in SYSTEM_DIRS {
        let path = Path::new(dir);
        match fs::symlink_metadata(path) {
            Ok(md) if md.file_type().is_symlink() => {
                symlinks.push((dir.to_owned(), fs::read_link(path)?));
            }
            Ok(md) if md.is_dir() => system_shares.push(dir.to_owned()),
            _ => {}
        }
    }
    let max_inputs = MICROVM_MAX_DEVICES
        .checked_sub(FIXED_DEVICES + system_shares.len())
        .filter(|n| *n >= 1)
        .ok_or_else(|| {
            Error::isolation_unavailable(format!(
                "host system layout needs {} shares; microvm allows only {} devices",
                system_shares.len() + FIXED_DEVICES,
                MICROVM_MAX_DEVICES
            ))
        })?;

    // Guest modules: built-in support needs no files; otherwise copy the
    // dependency closure and load it with kmod before any 9p mount.
    let modules = resolve_modules(&release)?;

    // Trusted binaries and their parsed library closure (no ldd execution).
    let install_exe = std::env::current_exe().map_err(|e| {
        Error::isolation_unavailable(format!("resolve fail2commit executable: {e}"))
    })?;
    let install_exe = install_exe.canonicalize()?;
    let relay = install_exe
        .parent()
        .ok_or_else(|| Error::isolation_unavailable("install path has no parent"))?
        .join("f2c-sandbox-relay");
    let relay = trusted_install_file(&relay, "f2c-sandbox-relay")?;
    let install_exe = trusted_install_file(&install_exe, "fail2commit")?;
    let bash = first_trusted(&BASH_PATHS, "bash")?;
    let bwrap = first_trusted(&BWRAP_PATHS, "bwrap")?;
    let setpriv = first_trusted(&SETPRIV_PATHS, "setpriv")?;
    let busybox = first_trusted(&BUSYBOX_PATHS, "busybox")?;
    let kmod = if modules.is_empty() {
        None
    } else {
        Some(first_trusted(&KMOD_PATHS, "kmod")?)
    };

    let mut roots = vec![bash, bwrap, setpriv.clone(), busybox.clone()];
    if let Some(kmod) = &kmod {
        roots.push(kmod.clone());
    }
    let mut closure = library_closure(&roots)?;
    closure.extend(library_closure(&[install_exe.clone(), relay.clone()])?);

    // Assemble the initramfs.
    let mut cpio = Cpio::default();
    let add_file = |cpio: &mut Cpio, guest: &Path, host: &Path| -> crate::Result<()> {
        let data = fs::read(host)?;
        let mode = fs::metadata(host)?.permissions().mode() & 0o7777;
        cpio.file(&guest.to_string_lossy(), 0o100000 | mode, &data);
        Ok(())
    };
    for dir in [
        "/proc",
        "/sys",
        "/dev",
        "/tmp",
        "/etc",
        "/mnt",
        GUEST_BIN_DIR,
        "/mnt/fail2commit-vm/jobs",
        "/mnt/fail2commit-vm/control",
        "/mnt/fail2commit-vm/results",
    ] {
        cpio.dir(dir);
    }
    for (link, target) in &symlinks {
        cpio.symlink(link, &target.to_string_lossy());
    }
    for bin in &roots {
        add_file(&mut cpio, bin, bin)?;
    }
    add_file(
        &mut cpio,
        Path::new(GUEST_BIN_DIR).join("fail2commit").as_path(),
        &install_exe,
    )?;
    add_file(
        &mut cpio,
        Path::new(GUEST_BIN_DIR).join("f2c-sandbox-relay").as_path(),
        &relay,
    )?;
    for lib in &closure {
        add_file(&mut cpio, lib, lib)?;
    }
    copy_etc(&mut cpio)?;
    // LV-02: a root-only capability baked into the image. Only the prepared
    // guest's root init can open it and hand the fd to the launcher, binding
    // dispatch to the prepared guest rather than a readable cmdline id.
    let mut cap_bytes = [0u8; 32];
    getrandom::fill(&mut cap_bytes)
        .map_err(|e| Error::isolation_unavailable(format!("create VM guest capability: {e}")))?;
    cpio.file(
        &format!("{GUEST_ROOT}/.vm-capability"),
        0o100400,
        hex::encode(cap_bytes).as_bytes(),
    );
    for module in &modules {
        let guest = module.guest_path();
        cpio.file(&guest, 0o100000 | 0o644, &fs::read(&module.host)?);
    }
    if !modules.is_empty() {
        let mod_dir = format!("/lib/modules/{release}");
        for name in [
            "modules.dep",
            "modules.dep.bin",
            "modules.builtin",
            "modules.builtin.bin",
        ] {
            let host = Path::new(&mod_dir).join(name);
            if host.is_file() {
                add_file(&mut cpio, &host, &host)?;
            }
        }
    }
    let tools = GuestTools {
        busybox,
        setpriv,
        kmod,
    };
    let init = render_init(
        &system_shares,
        &modules,
        max_inputs,
        &tools,
        Path::new(GUEST_ROOT),
    );
    cpio.file("/init", 0o100000 | 0o755, init.as_bytes());
    let image = cpio.finish();

    fs::create_dir_all(lib_dir)?;
    fs::set_permissions(lib_dir, fs::Permissions::from_mode(0o755))?;
    let initramfs = lib_dir.join(INITRAMFS_NAME);
    write_root_file(&initramfs, &image, 0o644)?;
    let initramfs_sha256 = hash_file(&initramfs)?;

    let state = VmState {
        version: 1,
        kernel_release: release,
        kernel: kernel.to_string_lossy().into_owned(),
        kernel_sha256,
        initramfs: initramfs.to_string_lossy().into_owned(),
        initramfs_sha256,
        qemu: qemu.to_string_lossy().into_owned(),
        qemu_sha256,
        qemu_version,
        system_shares,
        module_names: modules.iter().map(|m| m.name.clone()).collect(),
        max_inputs,
        created_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let json = serde_json::to_vec_pretty(&state)
        .map_err(|e| Error::internal(format!("serialize VM state: {e}")))?;
    write_root_file(state_path, &json, 0o644)?;
    Ok(format!(
        "prepared Linux VM image: kernel {}, initramfs {} ({} system shares, {} input slots)",
        state.kernel,
        state.initramfs,
        state.system_shares.len(),
        state.max_inputs
    ))
}

fn status_inner(state_path: &Path) -> crate::Result<String> {
    let state = match load_state(state_path) {
        Ok(state) => state,
        Err(_) => {
            return Ok("Linux VM image is not prepared; run: sudo fail2commit vm prepare".into());
        }
    };
    let mut text = format!(
        "Linux VM preparation:\n  kernel: {}\n  initramfs: {}\n  qemu: {} ({})\n  system shares: {}\n  input slots: {}",
        state.kernel,
        state.initramfs,
        state.qemu,
        state.qemu_version,
        state.system_shares.join(", "),
        state.max_inputs
    );
    match verify_hashes(&state) {
        Ok(()) => text.push_str("\n  hashes: ok"),
        Err(e) => text.push_str(&format!(
            "\n  hashes: MISMATCH ({}) — run: sudo fail2commit vm prepare",
            e.message
        )),
    }
    Ok(text)
}

fn remove_inner(state_path: &Path, lib_dir: &Path) -> crate::Result<String> {
    // Only delete the exact root-owned artifacts this feature created; never
    // follow a symlink planted in their place.
    if let Ok(md) = fs::symlink_metadata(lib_dir) {
        if md.file_type().is_symlink() || md.uid() != 0 || !md.is_dir() {
            return Err(Error::integrity(
                "VM library directory is not the root-owned prepared directory",
            ));
        }
        fs::remove_dir_all(lib_dir)?;
    }
    if let Ok(md) = fs::symlink_metadata(state_path) {
        if md.file_type().is_symlink() || md.uid() != 0 || !md.is_file() {
            return Err(Error::integrity(
                "VM state file is not the root-owned prepared record",
            ));
        }
        fs::remove_file(state_path)?;
    }
    Ok("removed Linux VM image and state (idempotent)".into())
}

/// Load the protected state, refusing a non-root-owned or writable record.
pub(crate) fn load_state(state_path: &Path) -> crate::Result<VmState> {
    let md = fs::symlink_metadata(state_path).map_err(|_| {
        Error::isolation_unavailable("VM image is not prepared; run fail2commit vm prepare")
    })?;
    if md.file_type().is_symlink() || !md.is_file() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(Error::integrity(
            "VM state record is not a root-owned, non-writable regular file",
        ));
    }
    let bytes = fs::read(state_path)?;
    if bytes.len() > MAX_QUERY_OUTPUT {
        return Err(Error::integrity("VM state record is oversized"));
    }
    let state: VmState = serde_json::from_slice(&bytes)
        .map_err(|e| Error::integrity(format!("invalid VM state record: {e}")))?;
    if state.version != 1 {
        return Err(Error::integrity("unsupported VM state version"));
    }
    Ok(state)
}

/// Verify the recorded kernel, initramfs and qemu still hash-match. A kernel
/// update or any corruption makes the preparation stale (fail closed).
pub(crate) fn verify_hashes(state: &VmState) -> crate::Result<()> {
    for (path, expected, what) in [
        (&state.kernel, &state.kernel_sha256, "kernel"),
        (&state.initramfs, &state.initramfs_sha256, "initramfs"),
        (&state.qemu, &state.qemu_sha256, "qemu"),
    ] {
        let actual = hash_file(Path::new(path)).map_err(|_| {
            Error::isolation_unavailable(format!(
                "prepared {what} is missing; run fail2commit vm prepare"
            ))
        })?;
        if !crate::digest::ct_eq(actual.as_bytes(), expected.as_bytes()) {
            return Err(Error::integrity(format!(
                "prepared {what} hash mismatch; run fail2commit vm prepare again"
            )));
        }
    }
    Ok(())
}

fn kernel_release() -> crate::Result<String> {
    // SAFETY: utsname is a correctly sized writable buffer for uname.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err(Error::internal("uname failed"));
    }
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
    let release = release
        .to_str()
        .map_err(|_| Error::internal("kernel release is not UTF-8"))?
        .to_owned();
    if release.is_empty() || release.len() > 128 || !release.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::internal("kernel release is malformed"));
    }
    Ok(release)
}

fn hash_file(path: &Path) -> crate::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn write_root_file(path: &Path, bytes: &[u8], mode: u32) -> crate::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("/"));
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Canonical root-owned executable in a root-owned, non-writable directory.
fn trusted_root_exe(path: &Path) -> crate::Result<PathBuf> {
    let canonical = path.canonicalize()?;
    let md = fs::metadata(&canonical)?;
    let dir = fs::metadata(canonical.parent().unwrap_or(Path::new("/")))?;
    let ok = md.is_file()
        && md.uid() == 0
        && md.mode() & 0o022 == 0
        && md.mode() & 0o111 != 0
        && dir.uid() == 0
        && dir.mode() & 0o022 == 0;
    if ok {
        Ok(canonical)
    } else {
        Err(Error::isolation_unavailable(format!(
            "{} is not a root-owned, non-writable executable",
            canonical.display()
        )))
    }
}

fn trusted_root_file(path: &Path, what: &str) -> crate::Result<PathBuf> {
    let canonical = path.canonicalize()?;
    let md = fs::metadata(&canonical)?;
    if !md.is_file() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(Error::isolation_unavailable(format!(
            "{what} {} is not a root-owned, non-writable regular file",
            canonical.display()
        )));
    }
    Ok(canonical)
}

/// The install binaries may belong to the invoking user, but must not be
/// group/other writable; their hashes are pinned into the protected image.
fn trusted_install_file(path: &Path, what: &str) -> crate::Result<PathBuf> {
    let canonical = path.canonicalize()?;
    let md = fs::metadata(&canonical)?;
    if !md.is_file() || md.mode() & 0o022 != 0 || md.mode() & 0o111 == 0 {
        return Err(Error::isolation_unavailable(format!(
            "{what} {} is not a non-writable executable",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn first_trusted(paths: &[&str], what: &str) -> crate::Result<PathBuf> {
    paths
        .iter()
        .find_map(|p| trusted_root_exe(Path::new(p)).ok())
        .ok_or_else(|| {
            Error::isolation_unavailable(format!(
                "no root-owned, non-writable {what} in the trusted system paths"
            ))
        })
}

/// Verify QEMU offers the microvm machine and the explicit MMIO devices
/// (CR-025) without starting a VM. Bounded output and deadline.
fn verify_qemu_support(qemu: &Path) -> crate::Result<String> {
    let version = run_bounded(qemu, &["--version"])?;
    let version = version
        .lines()
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_owned();
    let machines = run_bounded(qemu, &["-M", "help"])?;
    if !machines.split_whitespace().any(|w| w == "microvm") {
        return Err(Error::isolation_unavailable(
            "qemu-system-x86_64 does not support the microvm machine",
        ));
    }
    let devices = run_bounded(qemu, &["-device", "help"])?;
    for device in ["virtio-9p-device", "virtio-net-device"] {
        if !devices
            .lines()
            .any(|l| l.split_whitespace().any(|w| w == device))
        {
            return Err(Error::isolation_unavailable(format!(
                "qemu-system-x86_64 lacks the {device} MMIO device (CR-025)"
            )));
        }
    }
    Ok(version)
}

/// Kill the child's whole process group and confirm the group is gone before
/// the caller releases mapped state (LV-03). Idempotent: safe after the leader
/// already exited and was reaped. Bounded by CONTROL_GRACE; kill/wait failures
/// are surfaced, not ignored. The child must have been spawned as a group
/// leader (`process_group(0)`) so the group kill reaches every descendant.
pub(super) fn stop_process_group(child: &mut Child) -> crate::Result<()> {
    let pid = child.id() as i32;
    // SAFETY: kill targets this child's own process group with a constant signal.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    // Reap the leader if it has not been reaped yet (bounded).
    let deadline = Instant::now().checked_add(CONTROL_GRACE);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            // ECHILD: already reaped; the group probe below decides.
            Err(_) => break,
            Ok(None) => {
                if deadline.is_none_or(|d| Instant::now() >= d) {
                    child.wait().map_err(|e| {
                        Error::isolation_unavailable(format!("wait for process group leader: {e}"))
                    })?;
                    break;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
    // Confirm the whole group is gone. A killed descendant can linger as a
    // zombie until it is reaped, so retry the probe within the grace instead
    // of failing on the first look.
    let probe_deadline = Instant::now().checked_add(CONTROL_GRACE);
    loop {
        // SAFETY: a zero signal probes existence of the process group only.
        let gone = unsafe { libc::kill(-pid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        if gone {
            return Ok(());
        }
        if probe_deadline.is_none_or(|d| Instant::now() >= d) {
            return Err(Error::isolation_unavailable(
                "the process group did not stop cleanly",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn run_bounded(exe: &Path, args: &[&str]) -> crate::Result<String> {
    run_bounded_with_grace(exe, args, CONTROL_GRACE)
}

/// Bounded QEMU capability query (LV-06). The whole owned process group is
/// deadline-bound, stdout is cap-drained concurrently (a full pipe must never
/// block the child), and reader completion is bounded too (a descendant may
/// hold the pipe after the leader exits). Kill/wait failures are surfaced, not
/// ignored. The output cap alone is not a time bound; the deadlines are.
fn run_bounded_with_grace(exe: &Path, args: &[&str], grace: Duration) -> crate::Result<String> {
    let deadline = Instant::now()
        .checked_add(grace)
        .ok_or_else(|| Error::isolation_unavailable("qemu query deadline cannot be represented"))?;
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| Error::isolation_unavailable(format!("start {}: {e}", exe.display())))?;
    let stdout = child.stdout.take().expect("piped stdout");
    // Cap-drain on a thread so a verbose response cannot fill the pipe and
    // block the child, and keep counting past the cap to detect oversize.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut total = 0usize;
        let mut buf = [0u8; 16 * 1024];
        let mut r = stdout;
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total = total.saturating_add(n);
                    if out.len() <= MAX_QUERY_OUTPUT {
                        let keep = n.min(MAX_QUERY_OUTPUT + 1 - out.len());
                        out.extend_from_slice(&buf[..keep]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = tx.send((out, total));
    });
    // Wait for the leader within the deadline.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let cleanup = stop_process_group(&mut child);
                return Err(Error::isolation_unavailable(format!(
                    "qemu query timed out{}",
                    cleanup_suffix(cleanup)
                )));
            }
            Err(e) => {
                let cleanup = stop_process_group(&mut child);
                return Err(Error::isolation_unavailable(format!(
                    "wait for qemu query: {e}{}",
                    cleanup_suffix(cleanup)
                )));
            }
        }
    };
    // The leader exited; descendants may still hold stdout. Stop the whole
    // group so the reader gets EOF, then bound reader completion and surface
    // any cleanup uncertainty.
    let cleanup = stop_process_group(&mut child);
    let received = rx.recv_timeout(grace);
    cleanup?;
    let (out, total) = received.map_err(|_| {
        Error::isolation_unavailable(
            "qemu query output reader did not finish after the process group was stopped",
        )
    })?;
    if !status.success() {
        return Err(Error::isolation_unavailable(format!(
            "{} {:?} exited unsuccessfully",
            exe.display(),
            args
        )));
    }
    if total > MAX_QUERY_OUTPUT {
        return Err(Error::isolation_unavailable(
            "qemu query output is oversized",
        ));
    }
    String::from_utf8(out)
        .map_err(|_| Error::isolation_unavailable("qemu query output is not UTF-8"))
}

fn cleanup_suffix(cleanup: crate::Result<()>) -> String {
    match cleanup {
        Ok(()) => String::new(),
        Err(e) => format!("; cleanup uncertain: {}", e.message),
    }
}

#[derive(Debug)]
struct GuestModule {
    name: String,
    host: PathBuf,
}

impl GuestModule {
    fn guest_path(&self) -> String {
        self.host.to_string_lossy().into_owned()
    }
}

/// Resolve the guest module closure from the trusted modules.dep. Built-in
/// modules need no file; a missing required module fails preparation closed.
fn resolve_modules(release: &str) -> crate::Result<Vec<GuestModule>> {
    resolve_modules_in(&PathBuf::from(format!("/lib/modules/{release}")))
}

/// modules.dep names may carry a compression suffix (.ko.xz, .ko.zst);
/// normalize to the bare module name so required modules and the dependency
/// closure match (LV-07). The copied file keeps its real compressed name.
fn module_base_name(rel: &str) -> String {
    let file = rel.rsplit('/').next().unwrap_or("");
    let file = file
        .strip_suffix(".xz")
        .or_else(|| file.strip_suffix(".zst"))
        .unwrap_or(file);
    file.strip_suffix(".ko").unwrap_or(file).to_owned()
}

fn resolve_modules_in(mod_dir: &Path) -> crate::Result<Vec<GuestModule>> {
    let builtin = fs::read_to_string(mod_dir.join("modules.builtin")).unwrap_or_default();
    let builtin: BTreeSet<String> = builtin
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(module_base_name)
        .collect();
    let dep = fs::read_to_string(mod_dir.join("modules.dep")).map_err(|_| {
        Error::isolation_unavailable("kernel modules.dep is missing; cannot prepare guest modules")
    })?;
    // name -> (relative module path, dependency names)
    let mut deps: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for line in dep.lines() {
        let Some((target, rest)) = line.split_once(':') else {
            continue;
        };
        let rel = target.trim().to_owned();
        let name = module_base_name(&rel);
        let needs: Vec<String> = rest.split_whitespace().map(module_base_name).collect();
        deps.insert(name, (rel, needs));
    }
    let mut ordered: Vec<GuestModule> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for name in GUEST_MODULES {
        visit_module(name, &deps, &builtin, mod_dir, &mut ordered, &mut seen)?;
    }
    Ok(ordered)
}

fn visit_module(
    name: &str,
    deps: &BTreeMap<String, (String, Vec<String>)>,
    builtin: &BTreeSet<String>,
    mod_dir: &Path,
    ordered: &mut Vec<GuestModule>,
    seen: &mut BTreeSet<String>,
) -> crate::Result<()> {
    if builtin.contains(name) || !seen.insert(name.to_owned()) {
        return Ok(());
    }
    let (rel, needs) = deps.get(name).ok_or_else(|| {
        Error::isolation_unavailable(format!(
            "guest module {name} is neither built in nor present in modules.dep"
        ))
    })?;
    for need in needs {
        visit_module(need, deps, builtin, mod_dir, ordered, seen)?;
    }
    let host = mod_dir.join(rel);
    if !host.is_file() {
        return Err(Error::isolation_unavailable(format!(
            "guest module file {} is missing",
            host.display()
        )));
    }
    ordered.push(GuestModule {
        name: name.to_owned(),
        host,
    });
    Ok(())
}

#[derive(Default)]
struct ElfInfo {
    needed: Vec<String>,
    interpreter: Option<String>,
    runpath: Vec<String>,
}

/// Parse an ELF64 little-endian binary's dynamic dependencies without running
/// it (no `ldd`, which can execute untrusted code). Only the dynamic section,
/// string table and interpreter are read.
fn elf_dependencies(bytes: &[u8]) -> crate::Result<ElfInfo> {
    let bad = || Error::isolation_unavailable("unsupported ELF binary for VM preparation");
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err(bad());
    }
    let u16_at = |o: usize| -> crate::Result<u16> {
        Ok(u16::from_le_bytes(
            bytes.get(o..o + 2).ok_or_else(bad)?.try_into().unwrap(),
        ))
    };
    let u32_at = |o: usize| -> crate::Result<u32> {
        Ok(u32::from_le_bytes(
            bytes.get(o..o + 4).ok_or_else(bad)?.try_into().unwrap(),
        ))
    };
    let u64_at = |o: usize| -> crate::Result<u64> {
        Ok(u64::from_le_bytes(
            bytes.get(o..o + 8).ok_or_else(bad)?.try_into().unwrap(),
        ))
    };
    let phoff = u64_at(32)? as usize;
    let phentsize = u16_at(54)? as usize;
    let phnum = u16_at(56)? as usize;
    if phentsize < 56 {
        return Err(bad());
    }
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut interp = None;
    let mut dynamic: Option<(usize, usize)> = None;
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        let p_type = u32_at(base)?;
        let p_offset = u64_at(base + 8)?;
        let p_vaddr = u64_at(base + 16)?;
        let p_filesz = u64_at(base + 32)?;
        match p_type {
            1 => loads.push((p_vaddr, p_filesz, p_offset)),
            3 => {
                let end = (p_offset + p_filesz) as usize;
                let slice = bytes.get(p_offset as usize..end).ok_or_else(bad)?;
                let s = slice.split(|b| *b == 0).next().unwrap_or(&[]);
                interp = Some(String::from_utf8_lossy(s).into_owned());
            }
            2 => dynamic = Some((p_offset as usize, p_filesz as usize)),
            _ => {}
        }
    }
    let mut info = ElfInfo {
        interpreter: interp,
        ..Default::default()
    };
    let Some((doff, dsize)) = dynamic else {
        return Ok(info); // static binary
    };
    let mut needed_offsets = Vec::new();
    let mut strtab_vaddr = 0u64;
    let mut strsz = 0u64;
    let mut path_offsets = Vec::new();
    let mut cursor = doff;
    while cursor + 16 <= doff + dsize {
        let tag = i64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        let val = u64::from_le_bytes(bytes[cursor + 8..cursor + 16].try_into().unwrap());
        cursor += 16;
        match tag {
            0 => break,
            1 => needed_offsets.push(val),
            5 => strtab_vaddr = val,
            10 => strsz = val,
            15 | 29 => path_offsets.push(val),
            _ => {}
        }
    }
    let vaddr_to_offset = |vaddr: u64| -> Option<usize> {
        for (base, filesz, offset) in &loads {
            if vaddr >= *base && vaddr < base + filesz {
                return Some((offset + (vaddr - base)) as usize);
            }
        }
        None
    };
    let strtab_off = vaddr_to_offset(strtab_vaddr).ok_or_else(bad)?;
    let strtab = bytes
        .get(strtab_off..strtab_off + strsz as usize)
        .ok_or_else(bad)?;
    let string_at = |off: u64| -> String {
        let off = off as usize;
        if off >= strtab.len() {
            return String::new();
        }
        let s = strtab[off..].split(|b| *b == 0).next().unwrap_or(&[]);
        String::from_utf8_lossy(s).into_owned()
    };
    info.needed = needed_offsets
        .iter()
        .map(|o| string_at(*o))
        .filter(|s| !s.is_empty())
        .collect();
    for off in path_offsets {
        for part in string_at(off).split(':') {
            if !part.is_empty() {
                info.runpath.push(part.to_owned());
            }
        }
    }
    Ok(info)
}

/// Transitive library closure of the given binaries, resolved through their
/// runpath and the standard multiarch directories. Every file is canonical.
fn library_closure(roots: &[PathBuf]) -> crate::Result<BTreeSet<PathBuf>> {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut queue: Vec<PathBuf> = Vec::new();
    let mut deps: BTreeSet<PathBuf> = BTreeSet::new();
    for root in roots {
        queue.push(root.canonicalize()?);
    }
    while let Some(bin) = queue.pop() {
        if !seen.insert(bin.clone()) {
            continue;
        }
        let bytes = fs::read(&bin)?;
        let info = elf_dependencies(&bytes)?;
        if let Some(interp) = info.interpreter {
            let path = PathBuf::from(interp);
            if path.is_file() {
                deps.insert(path.canonicalize()?);
                queue.push(path);
            }
        }
        let mut search: Vec<PathBuf> = info.runpath.iter().map(PathBuf::from).collect();
        search.extend(STANDARD_LIB_DIRS.iter().map(PathBuf::from));
        for name in info.needed {
            let resolved = search
                .iter()
                .map(|dir| dir.join(&name))
                .find(|p| p.is_file())
                .ok_or_else(|| {
                    Error::isolation_unavailable(format!(
                        "cannot resolve library {name} needed by {}",
                        bin.display()
                    ))
                })?;
            let resolved = resolved.canonicalize()?;
            deps.insert(resolved.clone());
            queue.push(resolved);
        }
    }
    Ok(deps)
}

fn copy_etc(cpio: &mut Cpio) -> crate::Result<()> {
    let mut budget = MAX_ETC_BYTES;
    for entry in ETC_ALLOW {
        let path = Path::new(entry);
        if !path.exists() {
            continue;
        }
        copy_etc_path(cpio, path, &mut budget)?;
    }
    Ok(())
}

fn copy_etc_path(cpio: &mut Cpio, path: &Path, budget: &mut u64) -> crate::Result<()> {
    let md = fs::metadata(path)?; // follow symlinks: copy resolved content
    if md.is_dir() {
        cpio.dir(&path.to_string_lossy());
        let mut names: Vec<_> = fs::read_dir(path)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        names.sort();
        for child in names {
            copy_etc_path(cpio, &child, budget)?;
        }
    } else if md.is_file() {
        let len = md.len();
        if len > *budget {
            return Err(Error::isolation_unavailable(
                "VM /etc copy exceeds size budget",
            ));
        }
        *budget -= len;
        let data = fs::read(path)?;
        cpio.file(
            &path.to_string_lossy(),
            0o100000 | (md.permissions().mode() & 0o7777),
            &data,
        );
    }
    Ok(())
}

/// Trusted guest tool paths selected at prepare time. Non-merged hosts keep
/// these in /bin, so init must render the actual selected paths (LV-07).
struct GuestTools {
    busybox: PathBuf,
    setpriv: PathBuf,
    kmod: Option<PathBuf>,
}

/// Generate the guest init. System shares and module loading are fixed at
/// prepare time; the fresh job id and uid/gid arrive on the kernel command
/// line. Every mandatory mount fails closed (poweroff without an outcome).
fn render_init(
    system_shares: &[String],
    modules: &[GuestModule],
    max_inputs: usize,
    tools: &GuestTools,
    root: &Path,
) -> String {
    let busybox = tools.busybox.display();
    let setpriv = tools.setpriv.display();
    let root = root.display();
    let mut s = format!("#!{busybox} sh\n");
    s.push_str("# fail2commit guest init (FR-029). Generated by vm prepare.\n");
    s.push_str("export PATH=/usr/bin:/usr/sbin:/bin:/sbin\n");
    s.push_str(&format!("BB={busybox}\n"));
    s.push_str("$BB mkdir -p /proc /sys /dev /tmp\n");
    s.push_str("$BB chmod 1777 /tmp\n");
    s.push_str("$BB mount -t proc proc /proc || $BB poweroff -f\n");
    s.push_str("$BB mount -t sysfs sysfs /sys || $BB poweroff -f\n");
    s.push_str("$BB mount -t devtmpfs devtmpfs /dev || $BB poweroff -f\n");
    for module in modules {
        if let Some(kmod) = &tools.kmod {
            s.push_str(&format!(
                "{} modprobe {} || $BB poweroff -f\n",
                kmod.display(),
                module.name
            ));
        }
    }
    for dir in system_shares {
        let tag = system_share_tag(dir);
        s.push_str(&format!("$BB mkdir -p {dir}\n"));
        s.push_str(&format!(
            "$BB mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 {tag} {dir} || $BB poweroff -f\n"
        ));
    }
    s.push_str("id=; uid=; gid=; inputs=\n");
    s.push_str("for a in $($BB cat /proc/cmdline); do case $a in f2c_job_id=*) id=${a#f2c_job_id=};; f2c_uid=*) uid=${a#f2c_uid=};; f2c_gid=*) gid=${a#f2c_gid=};; f2c_inputs=*) inputs=${a#f2c_inputs=};; esac; done\n");
    s.push_str("case \"$id\" in *[!0-9a-f]*|\"\") $BB poweroff -f;; esac\n");
    s.push_str("[ ${#id} -eq 32 ] || $BB poweroff -f\n");
    s.push_str("case \"$uid$gid\" in *[!0-9]*|\"\") $BB poweroff -f;; esac\n");
    // LV-01: the host encodes how many input shares it actually supplied.
    // Every configured slot gets a mount point; only the required ones are
    // mounted, and a failed required mount fails closed before dispatch.
    s.push_str("case \"$inputs\" in *[!0-9]*|\"\") $BB poweroff -f;; esac\n");
    s.push_str(&format!(
        "[ \"$inputs\" -ge 1 ] && [ \"$inputs\" -le {max_inputs} ] || $BB poweroff -f\n"
    ));
    s.push_str(&format!("R={root}\n"));
    s.push_str("$BB mkdir -p $R/jobs/$id/work $R/control/$id $R/results/$id\n");
    s.push_str(&format!(
        "i=0\nwhile [ $i -lt {max_inputs} ]; do $BB mkdir -p $R/jobs/$id/input-$i; i=$((i+1)); done\n"
    ));
    s.push_str("$BB mount -t 9p -o trans=virtio,version=9p2000.L,msize=524288 f2cwork $R/jobs/$id/work || $BB poweroff -f\n");
    s.push_str("i=0\nwhile [ $i -lt \"$inputs\" ]; do $BB mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 f2cin$i $R/jobs/$id/input-$i || $BB poweroff -f; i=$((i+1)); done\n");
    s.push_str("$BB mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 f2cctl $R/control/$id || $BB poweroff -f\n");
    s.push_str("$BB mount -t 9p -o trans=virtio,version=9p2000.L,msize=524288 f2cres $R/results/$id || $BB poweroff -f\n");
    s.push_str("export HOME=/tmp\n");
    // LV-02: hand the launcher the root-only prepared capability on fd 3. The
    // launcher verifies the fd refers to this file, proving it was dispatched
    // by the prepared guest's init rather than started elsewhere.
    s.push_str("[ -f $R/.vm-capability ] || $BB poweroff -f\n");
    s.push_str("exec 3<$R/.vm-capability\n");
    s.push_str(&format!(
        "{setpriv} --reuid=$uid --regid=$gid --clear-groups $R/bin/fail2commit sandbox launch $R/control/$id/job.json --vm-guest\n"
    ));
    s.push_str("$BB poweroff -f\n");
    s
}

/// Minimal newc cpio writer (uncompressed; the kernel expands it as initramfs).
#[derive(Default)]
struct Cpio {
    bytes: Vec<u8>,
    ino: u32,
    entries: BTreeMap<String, (u32, Vec<u8>)>,
}

impl Cpio {
    fn dir(&mut self, name: &str) {
        self.entries
            .insert(name.to_owned(), (0o040000 | 0o755, Vec::new()));
        self.ensure_parents(name);
    }
    fn symlink(&mut self, name: &str, target: &str) {
        self.entries.insert(
            name.to_owned(),
            (0o120000 | 0o777, target.as_bytes().to_vec()),
        );
        self.ensure_parents(name);
    }
    fn file(&mut self, name: &str, mode: u32, data: &[u8]) {
        self.entries.insert(name.to_owned(), (mode, data.to_vec()));
        self.ensure_parents(name);
    }
    fn ensure_parents(&mut self, name: &str) {
        let path = Path::new(name);
        let mut ancestors: Vec<String> = Vec::new();
        let mut cur = path.parent();
        while let Some(parent) = cur {
            let s = parent.to_string_lossy().into_owned();
            if s.is_empty() || s == "/" {
                break;
            }
            ancestors.push(s);
            cur = parent.parent();
        }
        for dir in ancestors {
            self.entries
                .entry(dir)
                .or_insert((0o040000 | 0o755, Vec::new()));
        }
    }
    fn finish(mut self) -> Vec<u8> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (name, (mode, data)) in entries {
            self.write_entry(&name, mode, &data);
        }
        self.write_entry("TRAILER!!!", 0, &[]);
        self.bytes
    }
    fn write_entry(&mut self, name: &str, mode: u32, data: &[u8]) {
        self.ino += 1;
        let namesize = name.len() + 1;
        let nlink = if mode & 0o170000 == 0o040000 { 2 } else { 1 };
        let header =
            format!(
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            self.ino, mode, 0, 0, nlink, 0, data.len(), 0, 0, 0, 0, namesize, 0
        );
        self.bytes.extend_from_slice(header.as_bytes());
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        self.pad();
        self.bytes.extend_from_slice(data);
        self.pad();
    }
    fn pad(&mut self) {
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_budget_reserves_fixed_devices_and_inputs() {
        // merged-/usr: one system share leaves three input slots.
        let shares = ["/usr".to_owned()];
        let max = MICROVM_MAX_DEVICES - FIXED_DEVICES - shares.len();
        assert_eq!(max, 3);
        assert!(MICROVM_MAX_DEVICES.saturating_sub(FIXED_DEVICES + 5) < 1);
        assert_eq!(system_share_tag("/usr"), "f2cusr");
        assert_eq!(system_share_tag("/lib64"), "f2clib64");
    }

    fn usr_tools() -> GuestTools {
        GuestTools {
            busybox: PathBuf::from("/usr/bin/busybox"),
            setpriv: PathBuf::from("/usr/bin/setpriv"),
            kmod: Some(PathBuf::from("/usr/bin/kmod")),
        }
    }

    #[test]
    fn init_mounts_mmio_shares_and_fails_closed() {
        let modules = vec![GuestModule {
            name: "9p".into(),
            host: PathBuf::from("/lib/modules/x/9p.ko"),
        }];
        let init = render_init(
            &["/usr".to_owned()],
            &modules,
            2,
            &usr_tools(),
            Path::new(GUEST_ROOT),
        );
        assert!(init
            .contains("mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 f2cusr /usr"));
        assert!(init.contains("kmod modprobe 9p"));
        assert!(init.contains("f2c_job_id="));
        assert!(init.contains("f2c_inputs="));
        assert!(init.contains("[ ${#id} -eq 32 ]"));
        // Every configured slot gets a mount point; required mounts fail closed.
        assert!(init.contains("while [ $i -lt 2 ]; do $BB mkdir -p $R/jobs/$id/input-$i"));
        assert!(init.contains("while [ $i -lt \"$inputs\" ]"));
        assert!(init.contains("f2cin$i $R/jobs/$id/input-$i || $BB poweroff -f"));
        assert!(init.contains("[ \"$inputs\" -le 2 ]"));
        assert!(init.contains("setpriv --reuid=$uid --regid=$gid --clear-groups"));
        assert!(init.contains("$R/control/$id/job.json --vm-guest"));
        assert!(init.contains("R=/mnt/fail2commit-vm"));
        assert!(init.ends_with("$BB poweroff -f\n"));
        assert!(init.contains("f2cwork $R/jobs/$id/work || $BB poweroff -f"));
    }

    #[test]
    fn init_renders_the_selected_tool_paths() {
        let modules = vec![GuestModule {
            name: "9p".into(),
            host: PathBuf::from("/lib/modules/x/9p.ko.zst"),
        }];
        // Non-merged layout: the selected /bin tools must appear, not /usr/bin.
        let tools = GuestTools {
            busybox: PathBuf::from("/bin/busybox"),
            setpriv: PathBuf::from("/bin/setpriv"),
            kmod: Some(PathBuf::from("/bin/kmod")),
        };
        let init = render_init(
            &["/usr".to_owned()],
            &modules,
            2,
            &tools,
            Path::new(GUEST_ROOT),
        );
        assert!(init.starts_with("#!/bin/busybox sh\n"));
        assert!(init.contains("BB=/bin/busybox\n"));
        assert!(init.contains("/bin/kmod modprobe 9p || $BB poweroff -f"));
        assert!(init.contains("/bin/setpriv --reuid=$uid --regid=$gid --clear-groups"));
        assert!(!init.contains("/usr/bin/busybox"));
        assert!(!init.contains("/usr/bin/setpriv"));
        assert!(!init.contains("/usr/bin/kmod"));
        // Merged-/usr selection renders the /usr paths instead.
        let init = render_init(
            &["/usr".to_owned()],
            &modules,
            2,
            &usr_tools(),
            Path::new(GUEST_ROOT),
        );
        assert!(init.starts_with("#!/usr/bin/busybox sh\n"));
        assert!(init.contains("BB=/usr/bin/busybox\n"));
        assert!(init.contains("/usr/bin/kmod modprobe 9p"));
        assert!(init.contains("/usr/bin/setpriv --reuid"));
    }

    #[test]
    fn init_mounts_non_merged_system_shares() {
        let shares: Vec<String> = ["/usr", "/bin", "/sbin", "/lib", "/lib64"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let tools = GuestTools {
            busybox: PathBuf::from("/bin/busybox"),
            setpriv: PathBuf::from("/bin/setpriv"),
            kmod: None,
        };
        let init = render_init(&shares, &[], 1, &tools, Path::new(GUEST_ROOT));
        for dir in &shares {
            let tag = system_share_tag(dir);
            assert!(init.contains(&format!(
                "mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 {tag} {dir}"
            )));
        }
        assert!(!init.contains("modprobe"));
    }

    /// Write a fake /lib/modules/<release> tree; every dep target gets a file.
    fn write_module_tree(dir: &Path, dep: &str, builtin: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("modules.dep"), dep).unwrap();
        fs::write(dir.join("modules.builtin"), builtin).unwrap();
        for line in dep.lines() {
            if let Some((target, _)) = line.split_once(':') {
                let p = dir.join(target.trim());
                fs::create_dir_all(p.parent().unwrap()).unwrap();
                fs::write(&p, b"module").unwrap();
            }
        }
    }

    const COMPRESSED_DEP: &str = "\
kernel/drivers/virtio/virtio.ko.xz:
kernel/drivers/virtio/virtio_ring.ko.xz: kernel/drivers/virtio/virtio.ko.xz
kernel/drivers/virtio/virtio_mmio.ko.xz: kernel/drivers/virtio/virtio_ring.ko.xz
kernel/drivers/net/virtio_net.ko.zst: kernel/drivers/virtio/virtio_ring.ko.xz
kernel/net/9p/9pnet.ko.zst:
kernel/net/9p/9p.ko.zst: kernel/net/9p/9pnet.ko.zst
kernel/net/9p/9pnet_virtio.ko.xz: kernel/net/9p/9pnet.ko.zst kernel/drivers/virtio/virtio_ring.ko.xz
";

    #[test]
    fn module_closure_normalizes_compressed_names_and_orders_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        write_module_tree(dir.path(), COMPRESSED_DEP, "");
        let mods = resolve_modules_in(dir.path()).unwrap();
        let names: Vec<&str> = mods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "virtio",
                "virtio_ring",
                "virtio_mmio",
                "virtio_net",
                "9pnet",
                "9p",
                "9pnet_virtio"
            ]
        );
        for m in &mods {
            assert!(m.host.is_file(), "{}", m.host.display());
            let path = m.host.to_string_lossy();
            assert!(path.ends_with(".ko.xz") || path.ends_with(".ko.zst"));
        }
    }

    #[test]
    fn builtin_modules_need_no_files_and_missing_modules_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let builtin = "kernel/drivers/virtio/virtio_mmio.ko\nkernel/drivers/net/virtio_net.ko\nkernel/net/9p/9p.ko\nkernel/net/9p/9pnet_virtio.ko\n";
        write_module_tree(dir.path(), "", builtin);
        assert!(resolve_modules_in(dir.path()).unwrap().is_empty());
        // A required module neither built in nor in modules.dep fails closed.
        let dir2 = tempfile::tempdir().unwrap();
        write_module_tree(
            dir2.path(),
            "kernel/drivers/virtio/virtio_mmio.ko.xz:\n",
            "",
        );
        let err = resolve_modules_in(dir2.path()).expect_err("virtio_net is missing");
        assert!(err.message.contains("virtio_net"), "{}", err.message);
    }

    // ---- Executable init fixture (LV-01) ----
    // Runs the generated init under /bin/sh with fake guest tools that log
    // every command, really create mount points under a fake root, and can
    // simulate mount failures. This verifies actual commands and fail-closed
    // behavior, not string fragments. Needs no root and no real mounts.

    const FIX_ID: &str = "0123456789abcdef0123456789abcdef";

    struct InitFixture {
        /// Owns the fixture directory; kept alive for the test (RAII), not read.
        #[allow(dead_code)]
        dir: tempfile::TempDir,
        root: PathBuf,
        log: PathBuf,
        init: PathBuf,
    }

    fn fixture_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn init_fixture(max_inputs: usize, shares: &[String]) -> InitFixture {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let root = d.join("mnt");
        let log = d.join("log");
        // LV-02: the prepared capability the init hands to the launcher on fd 3.
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".vm-capability"), "ab".repeat(32)).unwrap();
        let busybox = fixture_script(
            d,
            "busybox",
            r#"#!/bin/sh
echo "busybox $*" >> "$F2C_INIT_LOG"
cmd="$1"; shift
case "$cmd" in
  mkdir)
    for a in "$@"; do
      case "$a" in "$F2C_INIT_ROOT"/*) /bin/mkdir -p "$a" ;; esac
    done ;;
  cat)
    if [ "$1" = "/proc/cmdline" ]; then printf '%s\n' "$F2C_INIT_CMDLINE"; else exec /bin/cat "$@"; fi ;;
  mount)
    for t in $F2C_INIT_FAIL_TAGS; do
      for a in "$@"; do
        if [ "$a" = "$t" ]; then exit 1; fi
      done
    done ;;
  poweroff) echo "POWEROFF" >> "$F2C_INIT_LOG"; kill -KILL 0 2>/dev/null; exit 0 ;;
  chmod) ;;
  test) [ "$@" ]; exit $? ;;
  *) ;;
esac
exit 0
"#,
        );
        let setpriv = fixture_script(
            d,
            "setpriv",
            "#!/bin/sh\necho \"setpriv $*\" >> \"$F2C_INIT_LOG\"\nexit 0\n",
        );
        let kmod = fixture_script(
            d,
            "kmod",
            "#!/bin/sh\necho \"kmod $*\" >> \"$F2C_INIT_LOG\"\nexit 0\n",
        );
        let tools = GuestTools {
            busybox,
            setpriv,
            kmod: Some(kmod),
        };
        let modules = vec![GuestModule {
            name: "9p".into(),
            host: PathBuf::from("/lib/modules/x/9p.ko"),
        }];
        let text = render_init(shares, &modules, max_inputs, &tools, &root);
        let init = d.join("init");
        fs::write(&init, text).unwrap();
        InitFixture {
            dir,
            root,
            log,
            init,
        }
    }

    fn run_init(f: &InitFixture, cmdline: &str, fail_tags: &str) {
        let out = Command::new("/bin/sh")
            .arg(&f.init)
            .env("F2C_INIT_LOG", &f.log)
            .env("F2C_INIT_ROOT", &f.root)
            .env("F2C_INIT_CMDLINE", cmdline)
            .env("F2C_INIT_FAIL_TAGS", fail_tags)
            // Own process group: the fake `poweroff -f` kills this group to
            // emulate a halt that never returns, without touching the test.
            .process_group(0)
            .output()
            .unwrap();
        // A poweroff-terminated run is expected, not a crash. Only a shell
        // parse error is a fixture bug.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("syntax error"), "init shell bug: {stderr}");
    }

    fn init_log(f: &InitFixture) -> String {
        fs::read_to_string(&f.log).unwrap_or_default()
    }

    fn fix_cmdline(inputs: &str) -> String {
        format!(
            "console=ttyS0 quiet f2c_job_id={FIX_ID} f2c_uid=1000 f2c_gid=1000 f2c_inputs={inputs}"
        )
    }

    #[test]
    fn init_exec_creates_every_mountpoint_and_mounts_required_inputs() {
        let f = init_fixture(3, &["/usr".to_owned()]);
        run_init(&f, &fix_cmdline("1"), "");
        let log = init_log(&f);
        let jobs = f.root.join("jobs").join(FIX_ID);
        // Every configured input mount point really exists, unused slots too.
        for i in 0..3 {
            let mp = jobs.join(format!("input-{i}"));
            assert!(mp.is_dir(), "input-{i} mount point must exist");
            assert!(log.contains(&format!("mkdir -p {}", mp.display())));
        }
        assert!(jobs.join("work").is_dir());
        assert!(f.root.join("control").join(FIX_ID).is_dir());
        assert!(f.root.join("results").join(FIX_ID).is_dir());
        // The required input is mounted; unused slots are not.
        assert!(log.contains(&format!("f2cin0 {}", jobs.join("input-0").display())));
        assert!(!log.contains("f2cin1 "));
        assert!(!log.contains("f2cin2 "));
        assert!(log.contains(&format!("f2cwork {}", jobs.join("work").display())));
        assert!(log.contains(&format!(
            "f2cctl {}",
            f.root.join("control").join(FIX_ID).display()
        )));
        assert!(log.contains(&format!(
            "f2cres {}",
            f.root.join("results").join(FIX_ID).display()
        )));
        // Modules loaded and dispatch reached with the boot uid/gid.
        assert!(log.contains("kmod modprobe 9p"));
        assert!(log.contains("setpriv --reuid=1000 --regid=1000 --clear-groups"));
        assert!(log.contains(&format!(
            "{}/bin/fail2commit sandbox launch {}/control/{FIX_ID}/job.json --vm-guest",
            f.root.display(),
            f.root.display()
        )));
    }

    #[test]
    fn init_exec_fails_closed_on_required_mount_errors() {
        // A supplied input whose mount fails must poweroff before dispatch.
        let f = init_fixture(3, &[]);
        run_init(&f, &fix_cmdline("2"), "f2cin1");
        let log = init_log(&f);
        assert!(log.contains("POWEROFF"));
        assert!(!log.contains("setpriv"));
        assert!(log.contains("f2cin0 "));
        assert!(!log.contains("f2cctl "));
        // A failed work mount also fails closed, before any input mount.
        let f2 = init_fixture(3, &[]);
        run_init(&f2, &fix_cmdline("1"), "f2cwork");
        let log2 = init_log(&f2);
        assert!(log2.contains("POWEROFF"));
        assert!(!log2.contains("setpriv"));
        assert!(!log2.contains("f2cin0 "));
    }

    #[test]
    fn init_exec_rejects_missing_or_invalid_input_count() {
        for bad in ["", "0", "4", "x", "1x"] {
            let f = init_fixture(3, &[]);
            let cmdline = if bad.is_empty() {
                format!("console=ttyS0 f2c_job_id={FIX_ID} f2c_uid=1000 f2c_gid=1000")
            } else {
                fix_cmdline(bad)
            };
            run_init(&f, &cmdline, "");
            let log = init_log(&f);
            assert!(log.contains("POWEROFF"), "inputs={bad:?}");
            assert!(!log.contains("setpriv"), "inputs={bad:?}");
            assert!(!log.contains("f2cwork "), "inputs={bad:?}");
        }
    }

    #[test]
    fn init_exec_rejects_bad_boot_identity() {
        let f = init_fixture(2, &[]);
        run_init(
            &f,
            "console=ttyS0 f2c_job_id=ZZZ f2c_uid=1000 f2c_gid=1000 f2c_inputs=1",
            "",
        );
        let log = init_log(&f);
        assert!(log.contains("POWEROFF"));
        assert!(!log.contains("setpriv"));
    }

    // ---- Bounded query fixtures (LV-06) ----

    #[test]
    fn bounded_query_drains_pipe_pressure_concurrently() {
        // >64KB pipe buffer: waiting for exit before draining would deadlock.
        let dir = tempfile::tempdir().unwrap();
        let script = fixture_script(
            dir.path(),
            "q",
            "#!/bin/sh\nn=0\nwhile [ $n -lt 200 ]; do printf '%01024d' 0; n=$((n+1)); done\n",
        );
        let out = run_bounded_with_grace(&script, &[], Duration::from_secs(10)).unwrap();
        assert_eq!(out.len(), 200 * 1024);
    }

    #[test]
    fn bounded_query_stops_descendant_held_pipe() {
        // The leader exits but a background descendant keeps stdout open; the
        // group stop must close the pipe so the reader finishes promptly.
        let dir = tempfile::tempdir().unwrap();
        let script = fixture_script(
            dir.path(),
            "q",
            "#!/bin/sh\necho leader-output\n(sleep 30) &\nexit 0\n",
        );
        let start = Instant::now();
        let out = run_bounded_with_grace(&script, &[], Duration::from_secs(5)).unwrap();
        assert!(out.contains("leader-output"));
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "must not wait for the descendant-held pipe"
        );
    }

    #[test]
    fn bounded_query_times_out_and_kills_the_group() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = fixture_script(
            dir.path(),
            "q",
            &format!("#!/bin/sh\necho $$ > '{}'\nsleep 30\n", pidfile.display()),
        );
        let err = run_bounded_with_grace(&script, &[], Duration::from_secs(1)).unwrap_err();
        assert!(err.message.contains("timed out"), "{}", err.message);
        let pid: i32 = fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: a zero signal only probes existence of the killed leader.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "leader must be dead");
    }

    #[test]
    fn bounded_query_rejects_oversized_output() {
        let dir = tempfile::tempdir().unwrap();
        let script = fixture_script(
            dir.path(),
            "q",
            "#!/bin/sh\nn=0\nwhile [ $n -lt 1100 ]; do printf '%01024d' 0; n=$((n+1)); done\n",
        );
        let err = run_bounded_with_grace(&script, &[], Duration::from_secs(10)).unwrap_err();
        assert!(err.message.contains("oversized"), "{}", err.message);
    }

    #[test]
    fn cpio_round_trips_names_modes_and_content() {
        let mut cpio = Cpio::default();
        cpio.dir("/etc");
        cpio.file("/init", 0o100000 | 0o755, b"#!/bin/sh\n");
        cpio.symlink("/bin", "usr/bin");
        let bytes = cpio.finish();
        assert!(bytes.starts_with(b"070701"));
        let parsed = parse_cpio(&bytes);
        assert_eq!(parsed.get("/init").unwrap().1, b"#!/bin/sh\n");
        assert_eq!(parsed.get("/init").unwrap().0 & 0o777, 0o755);
        assert_eq!(parsed.get("/bin").unwrap().1, b"usr/bin");
        assert!(parsed.contains_key("/etc"));
        assert!(bytes.windows(10).any(|w| w == b"TRAILER!!!"));
    }

    /// Tiny newc reader used only to verify the writer in tests.
    fn parse_cpio(bytes: &[u8]) -> BTreeMap<String, (u32, Vec<u8>)> {
        let mut out = BTreeMap::new();
        let mut cursor = 0usize;
        while cursor + 110 <= bytes.len() {
            if &bytes[cursor..cursor + 6] != b"070701" {
                break;
            }
            let field = |i: usize| -> usize {
                let start = cursor + 6 + i * 8;
                usize::from_str_radix(std::str::from_utf8(&bytes[start..start + 8]).unwrap(), 16)
                    .unwrap()
            };
            let mode = field(1);
            let filesize = field(6);
            let namesize = field(11);
            let name_start = cursor + 110;
            let name = std::str::from_utf8(&bytes[name_start..name_start + namesize - 1])
                .unwrap()
                .to_owned();
            let mut data_start = name_start + namesize;
            while !data_start.is_multiple_of(4) {
                data_start += 1;
            }
            if name == "TRAILER!!!" {
                break;
            }
            let data = bytes[data_start..data_start + filesize].to_vec();
            out.insert(name, (mode as u32, data));
            let mut next = data_start + filesize;
            while !next.is_multiple_of(4) {
                next += 1;
            }
            cursor = next;
        }
        out
    }

    #[test]
    fn elf_parser_reads_needed_and_rejects_non_elf() {
        assert!(elf_dependencies(b"not an elf").is_err());
        assert!(elf_dependencies(&[0u8; 64]).is_err());
        let elf = build_test_elf();
        let info = elf_dependencies(&elf).unwrap();
        assert_eq!(info.needed, vec!["libc.so.6".to_owned()]);
        assert_eq!(
            info.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
    }

    /// Hand-assembled ELF64 with PT_INTERP, PT_DYNAMIC (naming libc) and a
    /// PT_LOAD that maps the string table vaddr back to its file offset.
    fn build_test_elf() -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // ELFDATA2LSB
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&3u16.to_le_bytes()); // e_phnum
        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        let strtab = b"libc.so.6\0/lib64/ld-linux-x86-64.so.2\0";
        let interp_off = 64 + 3 * 56; // after the three program headers
        let dyn_off = interp_off + 32;
        let strtab_off = dyn_off + 4 * 16;
        let strtab_vaddr = 0x400000 + strtab_off as u64;
        let phdr = |typ: u32, off: u64, vaddr: u64, filesz: u64| -> Vec<u8> {
            let mut p = vec![0u8; 56];
            p[0..4].copy_from_slice(&typ.to_le_bytes());
            p[8..16].copy_from_slice(&off.to_le_bytes());
            p[16..24].copy_from_slice(&vaddr.to_le_bytes());
            p[32..40].copy_from_slice(&filesz.to_le_bytes());
            p
        };
        b.extend_from_slice(&phdr(
            3,
            interp_off as u64,
            0x400000 + interp_off as u64,
            interp.len() as u64,
        ));
        b.extend_from_slice(&phdr(2, dyn_off as u64, 0x400000 + dyn_off as u64, 4 * 16));
        b.extend_from_slice(&phdr(1, 0, 0x400000, 4096));
        b.resize(interp_off, 0);
        b.extend_from_slice(interp);
        b.resize(dyn_off, 0);
        let mut de = Vec::new();
        let mut entry = |tag: i64, val: u64| {
            de.extend_from_slice(&tag.to_le_bytes());
            de.extend_from_slice(&val.to_le_bytes());
        };
        entry(5, strtab_vaddr); // DT_STRTAB
        entry(10, strtab.len() as u64); // DT_STRSZ
        entry(1, 0); // DT_NEEDED -> "libc.so.6"
        entry(0, 0); // DT_NULL
        b.extend_from_slice(&de);
        b.resize(strtab_off, 0);
        b.extend_from_slice(strtab);
        b.resize(4096, 0);
        b
    }

    #[test]
    fn state_protection_and_idempotent_remove() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("fail2commit-vm.json");
        let lib_dir = dir.path().join("lib");
        // remove before prepare is a no-op success (idempotent).
        assert!(remove_inner(&state_path, &lib_dir).is_ok());
        // load of a missing state is unavailable, not a panic.
        assert!(load_state(&state_path).is_err());
        // A world-writable state record is refused by the probe loader.
        fs::write(&state_path, b"{}").unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_state(&state_path).is_err());
        // remove refuses a record it does not own (non-root in this unit test),
        // never deleting an arbitrary file planted in the state path.
        assert!(remove_inner(&state_path, &lib_dir).is_err());
        assert!(state_path.exists());
    }
}
