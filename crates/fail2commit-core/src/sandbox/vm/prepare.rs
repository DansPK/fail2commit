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
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
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
/// Minimum bounded window in which a just-SIGKILLed group leader is reaped
/// even when the caller's deadline has already expired (R3-04). Prevents
/// retaining an unreaped-but-dead leader that recovery could never clear.
const REAP_FLOOR: Duration = Duration::from_millis(250);
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
    // Create the library dir first so an unconfirmed capability query can
    // persist its containment record durably (R3-04).
    fs::create_dir_all(lib_dir)?;
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
    let version = run_bounded(qemu, &["--version"], Some(Path::new(LIB_DIR)))?;
    let version = version
        .lines()
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_owned();
    let machines = run_bounded(qemu, &["-M", "help"], Some(Path::new(LIB_DIR)))?;
    if !machines.split_whitespace().any(|w| w == "microvm") {
        return Err(Error::isolation_unavailable(
            "qemu-system-x86_64 does not support the microvm machine",
        ));
    }
    let devices = run_bounded(qemu, &["-device", "help"], Some(Path::new(LIB_DIR)))?;
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

/// Outcome of trying to contain an owned process group by the deadline.
#[derive(Debug)]
pub(super) enum Containment {
    /// Every member of the group that was alive at containment start is
    /// proven gone by a complete scan; mapped state may be released.
    Confirmed,
    /// Members persisted, or membership could not be proven complete, at the
    /// deadline; mapped state must NOT be released (the caller retains the
    /// guards and quarantines for recovery, R2-01/R3-01).
    Unconfirmed { live: Vec<i32>, uncertain: bool },
}

/// Parse `(pgrp, starttime_ticks, state)` from a /proc/<pid>/stat line. The
/// comm field can contain spaces and parentheses, so fields after it start
/// past the last `)`. Field 22 of the whole record is starttime.
fn parse_stat_pgrp_start(line: &str) -> Option<(i32, u64, u8)> {
    let close = line.rfind(')')?;
    let mut it = line[close + 1..].split_whitespace();
    let state = *it.next()?.as_bytes().first()?;
    let _ppid: i32 = it.next()?.parse().ok()?;
    let pgrp: i32 = it.next()?.parse().ok()?;
    let _sid: i32 = it.next()?.parse().ok()?;
    // Fields 7 through 21 precede starttime.
    for _ in 7..=21 {
        it.next()?;
    }
    let start: u64 = it.next()?.parse().ok()?;
    Some((pgrp, start, state))
}

/// Boot time in whole seconds (from /proc/stat btime).
fn boot_time_secs() -> Option<u64> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    for line in stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Approximate starttime-tick ceiling for "processes that could belong to a
/// group we are containing now". Kernel ticks run at 100 Hz but btime is
/// whole seconds, so add a 200-tick slack: a genuinely straggling member is
/// always included, and only a group whose leader pid was reused *within*
/// roughly two seconds of now is (fail-closed) treated as still live.
pub(super) fn group_bound_ticks_now() -> u64 {
    let slack = 200u64;
    match (
        boot_time_secs(),
        SystemTime::now().duration_since(UNIX_EPOCH),
    ) {
        (Some(btime), Ok(now)) => now
            .as_secs()
            .saturating_sub(btime)
            .saturating_mul(100)
            .saturating_add(slack),
        _ => u64::MAX,
    }
}

/// Result of one /proc group-membership enumeration (R3-01/R3-04). An
/// incomplete pass is never evidence that a group is dead.
#[derive(Debug)]
pub(super) enum MemberScan {
    /// Every entry was enumerated and readable within the time budget;
    /// the pids are exactly the bound-matching members that exist.
    Complete(Vec<i32>),
    /// Enumeration failed, an entry's stat could not be read (except that
    /// the process vanished mid-walk), a stat could not be parsed while the
    /// entry stayed present, the entry cap was hit, or the deadline expired
    /// mid-walk. Treat as "alive or unknown", never as absent.
    Uncertain,
}

/// Enumerate pids whose process group is `pgid` and whose recorded start is
/// within the containment bound, deadline-aware and error-honest (R3-01).
/// Zombies are included: they still hold their group slot until reaped.
pub(super) fn group_members_checked(pgid: i32, bound_ticks: u64, stop: Instant) -> MemberScan {
    let mut live = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return MemberScan::Uncertain;
    };
    let mut seen = 0usize;
    for entry in entries {
        if Instant::now() >= stop {
            return MemberScan::Uncertain;
        }
        seen += 1;
        if seen > 65_536 {
            return MemberScan::Uncertain;
        }
        let Ok(entry) = entry else {
            return MemberScan::Uncertain;
        };
        let Ok(pid): Result<i32, _> = entry.file_name().to_string_lossy().parse() else {
            continue;
        };
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            // The process vanished mid-walk: fully gone, not a member.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            // Anything else (permission, transient proc state) is unknown.
            Err(_) => return MemberScan::Uncertain,
        };
        match parse_stat_pgrp_start(&stat) {
            Some((pgrp, start, _state)) => {
                if pgrp == pgid && start <= bound_ticks {
                    live.push(pid);
                }
            }
            // Present but unparsable: unknown state, never "absent".
            None => return MemberScan::Uncertain,
        }
    }
    MemberScan::Complete(live)
}

/// Does `pid` still match our exact group identity right now? Used to
/// re-validate immediately before signalling (R3-01).
fn still_group_member(pid: i32, pgid: i32, bound_ticks: u64) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => parse_stat_pgrp_start(&stat)
            .is_some_and(|(pgrp, start, _)| pgrp == pgid && start <= bound_ticks),
        Err(_) => false,
    }
}

/// Kernel-backed existence probe of a numeric process group id: a zero
/// signal never delivers but reports whether any process carries the id.
#[derive(Debug, PartialEq, Eq)]
enum GroupProbe {
    Present,
    Gone,
    Unknown,
}

fn probe_group(pgid: i32) -> GroupProbe {
    // SAFETY: a zero signal probes existence only; nothing is delivered.
    if unsafe { libc::kill(-pgid, 0) } == 0 {
        return GroupProbe::Present;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => GroupProbe::Gone,
        // EPERM and anything else: a group exists that we cannot judge.
        _ => GroupProbe::Unknown,
    }
}

/// Bounded, exact-identity containment of an owned process group (R2-01).
/// There is no blocking wait anywhere: the leader is reaped with polled
/// `try_wait`, and surviving members are enumerated from /proc with a
/// starttime bound (so a recycled group id cannot be signalled or counted)
/// and killed by exact pid, re-probed until the deadline. `child` is `None`
/// when the caller already reaped the leader; then a group kill by pgid is
/// never attempted because the id may be reused.
pub(super) fn contain_group(
    child: Option<&mut Child>,
    pgid: i32,
    deadline: Instant,
) -> Containment {
    let bound_ticks = group_bound_ticks_now();
    if let Some(child) = child {
        // The leader is unreaped, so its pid (the group id) cannot be reused:
        // one exact group kill reaches every current member. The owned leader
        // stays as evidence in the caller's Child until this loop reaps it or
        // the deadline proves it unkillable (then the caller retains it).
        // SAFETY: kill targets this child's own process group with a signal.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
        // R3-04: a SIGKILLed leader is normally reaped in microseconds;
        // allow a small bounded floor past a nearly-expired deadline so a
        // dead leader is never left as an unreaped (and therefore
        // permanently "live") zombie in the caller's retained guard.
        let reap_deadline = deadline.max(Instant::now() + REAP_FLOOR);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                // ECHILD: already reaped; proceed to the member scan.
                Err(_) => break,
                Ok(None) => {
                    if Instant::now() >= reap_deadline {
                        return Containment::Unconfirmed {
                            live: vec![pgid],
                            uncertain: false,
                        };
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
        }
    }
    // Survivors: killed individually by exact pid after immediate identity
    // re-validation, never by -pgid once the leader is reaped. Their parent
    // reaps them after death; a parent that never reaps leaves a zombie in
    // the group, which correctly counts as not-contained until the deadline.
    let mut killed = std::collections::BTreeSet::new();
    loop {
        let mut members = match group_members_checked(pgid, bound_ticks, deadline) {
            MemberScan::Complete(members) => members,
            MemberScan::Uncertain => {
                if Instant::now() >= deadline {
                    return Containment::Unconfirmed {
                        live: Vec::new(),
                        uncertain: true,
                    };
                }
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
        };
        for pid in members.iter().copied() {
            if killed.contains(&pid) {
                continue;
            }
            // Re-validate the exact identity immediately before signalling
            // (R3-01): a pid recycled since enumeration must not be touched.
            if !still_group_member(pid, pgid, bound_ticks) {
                continue;
            }
            // SAFETY: pid passed immediate pgrp+starttime revalidation and
            // is signalled with a constant kill signal.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            killed.insert(pid);
        }
        if members.is_empty() {
            // Kernel-backed absence evidence. Present/Unknown after a
            // complete empty identity scan means the numeric id is owned by
            // something else (or not judgeable): re-scan to prove it, and
            // never confirm from a probe we cannot trust.
            match probe_group(pgid) {
                GroupProbe::Gone => return Containment::Confirmed,
                GroupProbe::Present => {
                    if let MemberScan::Complete(second) =
                        group_members_checked(pgid, bound_ticks, deadline)
                    {
                        if second.is_empty() {
                            // Group id exists but carries none of our
                            // identity-bound members: reused, not ours.
                            return Containment::Confirmed;
                        }
                        // Bound-matching members are live; carry them so the
                        // deadline report is truthful and kill them next pass.
                        members = second;
                    }
                }
                GroupProbe::Unknown => {
                    if Instant::now() >= deadline {
                        return Containment::Unconfirmed {
                            live: Vec::new(),
                            uncertain: true,
                        };
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Containment::Unconfirmed {
                live: members,
                uncertain: false,
            };
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn run_bounded(exe: &Path, args: &[&str], quarantine: Option<&Path>) -> crate::Result<String> {
    run_bounded_with_grace(exe, args, CONTROL_GRACE, quarantine)
}

/// R3-04: when a query's group containment cannot be confirmed, retain the
/// owned process (with a durable record when a quarantine directory exists)
/// instead of dropping the Child and pretending cleanup happened — the same
/// discipline VM runs use.
fn query_containment_retained(
    quarantine: Option<&Path>,
    pgid: i32,
    containment: Containment,
    context: &str,
    child: Option<Child>,
) -> crate::Error {
    let (live, uncertain) = match containment {
        Containment::Unconfirmed { live, uncertain } => (live, uncertain),
        Containment::Confirmed => (Vec::new(), false),
    };
    retain_containment(
        quarantine,
        Contained {
            record: QuarantineRecord {
                reason: format!(
                    "qemu query containment unconfirmed ({context}; live pids {live:?}{}) while the owned query process and its resources were retained",
                    if uncertain { ", membership scan incomplete" } else { "" }
                ),
                pgid: pgid as u32,
                bound_ticks: group_bound_ticks_now(),
                control_dir: None,
                result_dir: None,
                created_unix: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
            _pins: Vec::new(),
            _control: None,
            _result: None,
            _child: child,
        },
    )
}

/// Bounded QEMU capability query (LV-06, R2-02). One absolute whole-query
/// deadline bounds the leader wait, the output drain, and group cleanup:
/// stdout is set nonblocking and drained by the owning loop itself in bounded
/// chunks with a deadline check every iteration, so no detached reader can
/// be left blocked on a descendant-held pipe. The last quarter of the budget
/// (minimum 50 ms) is reserved so cleanup still completes inside the
/// advertised bound even when the leader exits near the deadline. Cleanup
/// uncertainty is surfaced, and every path is bounded by that one deadline.
fn run_bounded_with_grace(
    exe: &Path,
    args: &[&str],
    grace: Duration,
    quarantine: Option<&Path>,
) -> crate::Result<String> {
    let deadline = Instant::now()
        .checked_add(grace)
        .ok_or_else(|| Error::isolation_unavailable("qemu query deadline cannot be represented"))?;
    let reserve = (grace / 4).max(Duration::from_millis(50));
    let leader_deadline = deadline.checked_sub(reserve).ok_or_else(|| {
        Error::isolation_unavailable("qemu query cleanup reserve cannot be represented")
    })?;
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| Error::isolation_unavailable(format!("start {}: {e}", exe.display())))?;
    let pgid = child.id() as i32;
    let mut stdout = child.stdout.take().expect("piped stdout");
    // Caller-owned nonblocking drain (R2-02): the loop reads continuously so
    // a full pipe never blocks the child, and a retained descendant cannot
    // block the caller because reads return only what is ready.
    // SAFETY: F_GETFL/F_SETFL on the read end of our own pipe; only
    // O_NONBLOCK is added.
    let fl = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if fl < 0
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0
    {
        let containment = contain_group(Some(&mut child), pgid, deadline);
        return Err(match containment {
            Containment::Confirmed => {
                Error::isolation_unavailable("cannot set nonblocking qemu query pipe")
            }
            other => query_containment_retained(
                quarantine,
                pgid,
                other,
                "cannot set nonblocking qemu query pipe",
                Some(child),
            ),
        });
    }
    let mut out: Vec<u8> = Vec::new();
    let mut total = 0usize;
    let mut eof = false;
    let mut buf = [0u8; 16 * 1024];

    fn drain(
        stdout: &mut impl Read,
        buf: &mut [u8],
        out: &mut Vec<u8>,
        total: &mut usize,
        eof: &mut bool,
        stop_at: Instant,
    ) {
        while !*eof {
            match stdout.read(buf) {
                Ok(0) => *eof = true,
                Ok(n) => {
                    *total = total.saturating_add(n);
                    if out.len() <= MAX_QUERY_OUTPUT {
                        let keep = n.min(MAX_QUERY_OUTPUT + 1 - out.len());
                        out.extend_from_slice(&buf[..keep]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => *eof = true,
            }
            if Instant::now() >= stop_at {
                break;
            }
        }
    }

    let status = loop {
        drain(
            &mut stdout,
            &mut buf,
            &mut out,
            &mut total,
            &mut eof,
            deadline,
        );
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                let containment = contain_group(Some(&mut child), pgid, deadline);
                return Err(match containment {
                    Containment::Confirmed => {
                        Error::isolation_unavailable(format!("wait for qemu query: {e}"))
                    }
                    other => query_containment_retained(
                        quarantine,
                        pgid,
                        other,
                        &format!("wait for qemu query: {e}"),
                        Some(child),
                    ),
                });
            }
        }
        if Instant::now() >= leader_deadline {
            // Stop the still-running leader now so containment and the final
            // drain complete within the single advertised deadline.
            let containment = contain_group(Some(&mut child), pgid, deadline);
            if !matches!(containment, Containment::Confirmed) {
                // R3-04: an unconfirmed query keeps its owned process and
                // resources with durable recovery, not a silent drop.
                return Err(query_containment_retained(
                    quarantine,
                    pgid,
                    containment,
                    "qemu query timed out",
                    Some(child),
                ));
            }
            drain(
                &mut stdout,
                &mut buf,
                &mut out,
                &mut total,
                &mut eof,
                deadline,
            );
            return Err(Error::isolation_unavailable("qemu query timed out"));
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    // The leader exited and was reaped by try_wait, so only exact-pid kills
    // are safe from here. Containment and the final drain share the deadline.
    let containment = contain_group(None, pgid, deadline);
    while !eof && Instant::now() < deadline {
        drain(
            &mut stdout,
            &mut buf,
            &mut out,
            &mut total,
            &mut eof,
            deadline,
        );
        if !eof && Instant::now() < deadline {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    if let Containment::Unconfirmed { .. } = containment {
        // R3-04: unconfirmed membership after the leader exited still keeps
        // owned recovery rather than silently dropping resources. The leader
        // itself was reaped by try_wait, so no child needs retaining.
        return Err(query_containment_retained(
            quarantine,
            pgid,
            containment,
            "qemu query exited with retained members",
            None,
        ));
    }
    if !eof {
        return Err(Error::isolation_unavailable(
            "qemu query output did not end before the deadline",
        ));
    }
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
/// line. R2-04: every failure branch calls `f2c_fail`, which requests the
/// shutdown and then exits nonzero regardless of whether `poweroff` returns,
/// so init can never fall through to launcher dispatch after a failed module
/// load, mount, validation, or capability check.
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
    // R2-04: poweroff is best effort; the exit is the guarantee.
    s.push_str("f2c_fail() { $BB poweroff -f; exit 1; }\n");
    s.push_str("$BB mkdir -p /proc /sys /dev /tmp\n");
    s.push_str("$BB chmod 1777 /tmp\n");
    s.push_str("$BB mount -t proc proc /proc || f2c_fail\n");
    s.push_str("$BB mount -t sysfs sysfs /sys || f2c_fail\n");
    s.push_str("$BB mount -t devtmpfs devtmpfs /dev || f2c_fail\n");
    for module in modules {
        if let Some(kmod) = &tools.kmod {
            s.push_str(&format!(
                "{} modprobe {} || f2c_fail\n",
                kmod.display(),
                module.name
            ));
        }
    }
    for dir in system_shares {
        let tag = system_share_tag(dir);
        s.push_str(&format!("$BB mkdir -p {dir}\n"));
        s.push_str(&format!(
            "$BB mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 {tag} {dir} || f2c_fail\n"
        ));
    }
    s.push_str("id=; uid=; gid=; inputs=\n");
    s.push_str("for a in $($BB cat /proc/cmdline); do case $a in f2c_job_id=*) id=${a#f2c_job_id=};; f2c_uid=*) uid=${a#f2c_uid=};; f2c_gid=*) gid=${a#f2c_gid=};; f2c_inputs=*) inputs=${a#f2c_inputs=};; esac; done\n");
    s.push_str("case \"$id\" in *[!0-9a-f]*|\"\") f2c_fail;; esac\n");
    s.push_str("[ ${#id} -eq 32 ] || f2c_fail\n");
    s.push_str("case \"$uid$gid\" in *[!0-9]*|\"\") f2c_fail;; esac\n");
    // LV-01: the host encodes how many input shares it actually supplied.
    // Every configured slot gets a mount point; only the required ones are
    // mounted, and a failed required mount fails closed before dispatch.
    s.push_str("case \"$inputs\" in *[!0-9]*|\"\") f2c_fail;; esac\n");
    s.push_str(&format!(
        "[ \"$inputs\" -ge 1 ] && [ \"$inputs\" -le {max_inputs} ] || f2c_fail\n"
    ));
    s.push_str(&format!("R={root}\n"));
    s.push_str("$BB mkdir -p $R/jobs/$id/work $R/control/$id $R/results/$id\n");
    s.push_str(&format!(
        "i=0\nwhile [ $i -lt {max_inputs} ]; do $BB mkdir -p $R/jobs/$id/input-$i; i=$((i+1)); done\n"
    ));
    s.push_str("$BB mount -t 9p -o trans=virtio,version=9p2000.L,msize=524288 f2cwork $R/jobs/$id/work || f2c_fail\n");
    s.push_str("i=0\nwhile [ $i -lt \"$inputs\" ]; do $BB mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 f2cin$i $R/jobs/$id/input-$i || f2c_fail; i=$((i+1)); done\n");
    s.push_str("$BB mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 f2cctl $R/control/$id || f2c_fail\n");
    s.push_str("$BB mount -t 9p -o trans=virtio,version=9p2000.L,msize=524288 f2cres $R/results/$id || f2c_fail\n");
    s.push_str("export HOME=/tmp\n");
    // LV-02: hand the launcher the root-only prepared capability on fd 3. The
    // launcher verifies the fd refers to this file, proving it was dispatched
    // by the prepared guest's init rather than started elsewhere.
    s.push_str("[ -r \"$R/.vm-capability\" ] || f2c_fail\n");
    s.push_str("exec 3<\"$R/.vm-capability\" || f2c_fail\n");
    s.push_str(&format!(
        "{setpriv} --reuid=$uid --regid=$gid --clear-groups $R/bin/fail2commit sandbox launch $R/control/$id/job.json --vm-guest\n"
    ));
    // Normal end of the job: shut down. The host's bounded containment is the
    // backstop if shutdown itself fails (R2-01).
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

// ---- Bounded containment ownership and durable quarantine ----
// (R2-01, R3-03, R3-04.) These protect every owned process — VM runs and
// root-owned capability queries alike — whose termination cannot be
// confirmed within its bound: guards never drop while the exact identity is
// possibly live, and the refusal survives process restart durably.

/// Durable quarantine record under the stage/containment directory.
pub(super) const CONTAINMENT_FILE: &str = "f2c-vm-containment.json";
const MAX_CONTAINMENT_BYTES: u64 = 64 * 1024;
/// How many unresolved contained identities the durable record holds before
/// persistence fails closed instead of dropping evidence (R3-03).
pub(super) const MAX_CONTAINMENT_RECORDS: usize = 8;

/// Durable refusal/recovery record for an owned group whose containment
/// could not be confirmed. `pgid` + `bound_ticks` give the exact identity
/// used to decide "still live" (pid reuse cannot resurrect or fake liveness).
#[derive(Serialize, Deserialize)]
pub(super) struct QuarantineRecord {
    pub(super) reason: String,
    pub(super) pgid: u32,
    pub(super) bound_ticks: u64,
    pub(super) control_dir: Option<String>,
    pub(super) result_dir: Option<String>,
    pub(super) created_unix: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct QuarantineFile {
    pub(super) version: u32,
    pub(super) records: Vec<QuarantineRecord>,
}

/// The retained containment owner for one unconfirmed group: the VM guards
/// (share pins, control dir, result dir) plus any unreaped child stay held
/// here for the process lifetime, so a live QEMU can never observe released
/// or recycled exchanges (R2-01). A query guard retains only the owned
/// process (R3-04). Recovery drops entries only after the group's exact
/// identity is proven gone.
pub(super) struct Contained {
    pub(super) record: QuarantineRecord,
    pub(super) _pins: Vec<File>,
    pub(super) _control: Option<tempfile::TempDir>,
    pub(super) _result: Option<tempfile::TempDir>,
    pub(super) _child: Option<Child>,
}

/// Process-lifetime registry of retained containment owners. A mutex poison
/// only means a quarantining path panicked; the inner Vec is still valid.
static CONTAINED: Mutex<Vec<Contained>> = Mutex::new(Vec::new());

pub(super) fn contained_registry() -> std::sync::MutexGuard<'static, Vec<Contained>> {
    CONTAINED
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Persist the durable quarantine record. Written 0600 with create+rename
/// and a parent-directory fsync so a crash cannot lose an unresolved
/// identity whose inherited pins still live in the child (R3-03).
pub(super) fn persist_quarantine(
    quarantine_dir: &Path,
    record: &QuarantineRecord,
) -> crate::Result<()> {
    let path = quarantine_dir.join(CONTAINMENT_FILE);
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
                Error::integrity(format!(
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
    // R3-03: never evict an unresolved identity. When the cap is reached,
    // persistence fails closed and the caller keeps the in-memory refusal.
    if file.records.len() >= MAX_CONTAINMENT_RECORDS {
        return Err(Error::isolation_unavailable(format!(
            "VM containment quarantine is full ({MAX_CONTAINMENT_RECORDS} unresolved identities); refusing to evict live containment evidence"
        )));
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
        .map_err(|e| Error::internal(format!("serialize containment record: {e}")))?;
    let tmp = quarantine_dir.join(format!("{CONTAINMENT_FILE}.tmp"));
    write_new_file_force(&tmp, &json)?;
    fs::rename(&tmp, &path)?;
    // Crash safety: the rename itself must be durable before we treat the
    // identity as recorded across a restart (R3-03).
    sync_dir(quarantine_dir)
}

/// fsync a directory so entry creation/removal survives process or machine
/// crash (R3-03).
fn sync_dir(path: &Path) -> crate::Result<()> {
    let dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            Error::isolation_unavailable(format!("open containment dir {}: {e}", path.display()))
        })?;
    // SAFETY: fsync on a live directory descriptor this function just opened.
    if unsafe { libc::fsync(dir.as_raw_fd()) } != 0 {
        return Err(Error::isolation_unavailable(format!(
            "sync containment dir {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Replaces-or-creates writer for the containment record tmp.
fn write_new_file_force(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::isolation_unavailable(format!("create VM containment tmp: {e}")))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Hand the mapped guards (or the owned query process) to the retained
/// containment owner and produce the fail-closed error (R2-01, R3-04).
/// Guards stay retained in memory even when durable persistence fails or is
/// unavailable.
pub(super) fn retain_containment(quarantine_dir: Option<&Path>, guards: Contained) -> crate::Error {
    let record = QuarantineRecord {
        reason: guards.record.reason.clone(),
        pgid: guards.record.pgid,
        bound_ticks: guards.record.bound_ticks,
        control_dir: guards.record.control_dir.clone(),
        result_dir: guards.record.result_dir.clone(),
        created_unix: guards.record.created_unix,
    };
    let persist = match quarantine_dir {
        Some(dir) => persist_quarantine(dir, &record),
        None => Err(Error::isolation_unavailable(
            "no durable containment directory was provided",
        )),
    };
    contained_registry().push(guards);
    match (persist, quarantine_dir) {
        (Ok(()), Some(dir)) => Error::isolation_unavailable(format!(
            "micro-VM containment unconfirmed; mapped state is quarantined in memory and {} for recovery",
            dir.join(CONTAINMENT_FILE).display()
        )),
        _ => Error::isolation_unavailable(
            "micro-VM containment unconfirmed and the durable quarantine record failed to persist; mapped state stays quarantined in memory",
        ),
    }
}

/// True only when a complete, deadline-bounded identity scan proves the
/// contained group has no bound-matching members. An uncertain scan is
/// never "gone" (R3-01): recovery refuses while membership is unproven.
pub(super) fn group_proven_gone(pgid: i32, bound: u64) -> bool {
    matches!(
        group_members_checked(pgid, bound, Instant::now() + Duration::from_secs(2)),
        MemberScan::Complete(members) if members.is_empty()
    )
}

/// Refuse or recover before touching a new VM or query (R2-01): while any
/// contained group from a prior attempt is still live, work stays refused;
/// once the exact identities are proven gone, retained guards drop, the
/// quarantined per-run directories delete, and the durable record clears.
pub(super) fn recover_or_refuse(stage_root: &Path) -> crate::Result<()> {
    let mut retained: Vec<Contained> = Vec::new();
    {
        let mut reg = contained_registry();
        std::mem::swap(&mut *reg, &mut retained);
    }
    let mut live_in_process = 0usize;
    for guard in retained.into_iter() {
        if group_proven_gone(guard.record.pgid as i32, guard.record.bound_ticks) {
            // Confirmed gone: dropping the guards releases pins and deletes
            // the per-run control/result directories through their owners.
            continue;
        }
        live_in_process += 1;
        // Still live (or unproven): re-retain (never drop while contained).
        contained_registry().push(guard);
    }
    if live_in_process > 0 {
        return Err(Error::isolation_unavailable(format!(
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
            Error::integrity(format!(
                "read VM containment record {}: {e}",
                path.display()
            ))
        })?;
    let file: QuarantineFile = serde_json::from_slice(&bytes).map_err(|e| {
        Error::integrity(format!(
            "VM containment record is corrupt ({e}); resolve the contained process group and remove {}",
            path.display()
        ))
    })?;
    let mut live_records = Vec::new();
    let mut dead_records = Vec::new();
    for record in file.records {
        if group_proven_gone(record.pgid as i32, record.bound_ticks) {
            dead_records.push(record);
        } else {
            live_records.push(record);
        }
    }
    // Proven-dead exchanges release now, so the cap only ever holds
    // genuinely unresolved identities (R3-03).
    for record in &dead_records {
        release_record_dirs(record);
    }
    if !live_records.is_empty() {
        // Keep every unresolved identity durably — never evict — and refuse
        // BEFORE launching any additional job (R3-03).
        let pruned = QuarantineFile {
            version: 1,
            records: live_records,
        };
        let json = serde_json::to_vec_pretty(&pruned)
            .map_err(|e| Error::internal(format!("serialize containment record: {e}")))?;
        let tmp = stage_root.join(format!("{CONTAINMENT_FILE}.tmp"));
        write_new_file_force(&tmp, &json)?;
        fs::rename(&tmp, &path)?;
        sync_dir(stage_root)?;
        return Err(Error::isolation_unavailable(format!(
            "a previously contained micro-VM process group is still live; VM jobs stay refused until it exits (see {})",
            path.display()
        )));
    }
    fs::remove_file(&path)?;
    sync_dir(stage_root)?;
    Ok(())
}

/// Delete a recovered record's per-run exchange directories; only plain
/// directories this feature created, never a symlink target.
fn release_record_dirs(record: &QuarantineRecord) {
    for dir in [record.control_dir.as_deref(), record.result_dir.as_deref()] {
        let Some(dir) = dir else { continue };
        let p = Path::new(dir);
        let Ok(md) = fs::symlink_metadata(p) else {
            continue;
        };
        if md.is_dir() {
            let _ = fs::remove_dir_all(p);
        }
    }
}

/// Serializes tests that touch the process-global containment registry or
/// FAIL2COMMIT_HOME (the registry is production state; tests that retain,
/// refuse, or recover must not interleave with each other).
#[cfg(test)]
pub(super) static VM_TEST_LOCK: Mutex<()> = Mutex::new(());

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
        // R2-04: a named fail path powers off and then exits nonzero.
        assert!(init.contains("f2c_fail() { $BB poweroff -f; exit 1; }"));
        // Every configured slot gets a mount point; required mounts fail closed.
        assert!(init.contains("while [ $i -lt 2 ]; do $BB mkdir -p $R/jobs/$id/input-$i"));
        assert!(init.contains("while [ $i -lt \"$inputs\" ]"));
        assert!(init.contains("f2cin$i $R/jobs/$id/input-$i || f2c_fail"));
        assert!(init.contains("[ \"$inputs\" -le 2 ]"));
        assert!(init.contains("setpriv --reuid=$uid --regid=$gid --clear-groups"));
        assert!(init.contains("$R/control/$id/job.json --vm-guest"));
        assert!(init.contains("R=/mnt/fail2commit-vm"));
        assert!(init.ends_with("$BB poweroff -f\n"));
        assert!(init.contains("f2cwork $R/jobs/$id/work || f2c_fail"));
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
        assert!(init.contains("/bin/kmod modprobe 9p || f2c_fail"));
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
        cap: PathBuf,
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
        let cap = root.join(".vm-capability");
        fs::write(&cap, "ab".repeat(32)).unwrap();
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
  poweroff)
    echo "POWEROFF" >> "$F2C_INIT_LOG"
    if [ "$F2C_INIT_POWEROFF" = fail ]; then exit 1; fi
    kill -KILL 0 2>/dev/null; exit 0 ;;
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
            "#!/bin/sh\necho \"kmod $*\" >> \"$F2C_INIT_LOG\"\nif [ \"$F2C_INIT_KMOD_FAIL\" = 1 ]; then exit 1; fi\nexit 0\n",
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
            cap,
        }
    }

    /// Exec'ing a just-written script can transiently hit ETXTBSY when a
    /// parallel test forks while this writer still holds the file; the forked
    /// child inherits the write fd until it execs. Retry briefly. Production
    /// keeps the single bounded spawn error (fail closed), never a retry.
    fn spawn_txtbsy_retry<T>(
        e: std::io::Error,
        attempts_left: u32,
        retry: impl FnOnce(u32) -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        if e.raw_os_error() == Some(libc::ETXTBSY) && attempts_left > 0 {
            std::thread::sleep(Duration::from_millis(25));
            return retry(attempts_left - 1);
        }
        Err(e)
    }

    fn run_init_full(
        f: &InitFixture,
        cmdline: &str,
        fail_tags: &str,
        poweroff: &str,
        kmod_fail: bool,
    ) -> std::process::Output {
        fn attempt(
            f: &InitFixture,
            cmdline: &str,
            fail_tags: &str,
            poweroff: &str,
            kmod_fail: bool,
            left: u32,
        ) -> std::io::Result<std::process::Output> {
            let cmd = Command::new("/bin/sh")
                .arg(&f.init)
                .env("F2C_INIT_LOG", &f.log)
                .env("F2C_INIT_ROOT", &f.root)
                .env("F2C_INIT_CMDLINE", cmdline)
                .env("F2C_INIT_FAIL_TAGS", fail_tags)
                .env("F2C_INIT_POWEROFF", poweroff)
                .env("F2C_INIT_KMOD_FAIL", if kmod_fail { "1" } else { "" })
                // Own process group: the fake `poweroff -f` kills this group to
                // emulate a halt that never returns, without touching the test.
                .process_group(0)
                .output();
            match cmd {
                Ok(out) => Ok(out),
                Err(e) => spawn_txtbsy_retry(e, left, |l| {
                    attempt(f, cmdline, fail_tags, poweroff, kmod_fail, l)
                }),
            }
        }
        let out = attempt(f, cmdline, fail_tags, poweroff, kmod_fail, 10)
            .expect("init fixture must spawn");
        // A poweroff-terminated run is expected, not a crash. Only a shell
        // parse error is a fixture bug.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("syntax error"), "init shell bug: {stderr}");
        out
    }

    fn run_init(f: &InitFixture, cmdline: &str, fail_tags: &str) {
        run_init_full(f, cmdline, fail_tags, "kill", false);
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

    #[test]
    fn init_exec_fails_even_when_poweroff_returns_failure() {
        // R2-04: every failure branch must terminate init even when
        // `poweroff -f` itself returns unsuccessfully. The launcher must
        // never be reached on any branch.
        let cases: Vec<(&str, Vec<String>, String, String, bool)> = vec![
            ("proc mount", vec![], fix_cmdline("1"), "proc".into(), false),
            (
                "sysfs mount",
                vec![],
                fix_cmdline("1"),
                "sysfs".into(),
                false,
            ),
            (
                "devtmpfs mount",
                vec![],
                fix_cmdline("1"),
                "devtmpfs".into(),
                false,
            ),
            (
                "system share mount",
                vec!["/usr".to_owned()],
                fix_cmdline("1"),
                "f2cusr".into(),
                false,
            ),
            (
                "work mount",
                vec![],
                fix_cmdline("1"),
                "f2cwork".into(),
                false,
            ),
            (
                "input mount",
                vec![],
                fix_cmdline("1"),
                "f2cin0".into(),
                false,
            ),
            (
                "control mount",
                vec![],
                fix_cmdline("1"),
                "f2cctl".into(),
                false,
            ),
            (
                "result mount",
                vec![],
                fix_cmdline("1"),
                "f2cres".into(),
                false,
            ),
            ("module load", vec![], fix_cmdline("1"), "".into(), true),
            (
                "bad id charset",
                vec![],
                "console=ttyS0 f2c_job_id=ZZZ f2c_uid=1 f2c_gid=1 f2c_inputs=1".into(),
                "".into(),
                false,
            ),
            (
                "short id",
                vec![],
                "console=ttyS0 f2c_job_id=abc f2c_uid=1 f2c_gid=1 f2c_inputs=1".into(),
                "".into(),
                false,
            ),
            (
                "bad uid",
                vec![],
                format!("console=f2c_job_id={FIX_ID} f2c_uid=x f2c_gid=1 f2c_inputs=1"),
                "".into(),
                false,
            ),
            (
                "inputs key absent",
                vec![],
                format!("console=f2c_job_id={FIX_ID} f2c_uid=1 f2c_gid=1"),
                "".into(),
                false,
            ),
            ("inputs zero", vec![], fix_cmdline("0"), "".into(), false),
            (
                "inputs over max",
                vec![],
                fix_cmdline("9"),
                "".into(),
                false,
            ),
        ];
        for (what, shares, cmdline, tags, kmod_fail) in cases {
            let f = init_fixture(3, &shares);
            let out = run_init_full(&f, &cmdline, &tags, "fail", kmod_fail);
            let log = init_log(&f);
            assert!(
                !log.contains("setpriv"),
                "{what}: dispatch reached after failed branch"
            );
            assert!(log.contains("POWEROFF"), "{what}: shutdown not requested");
            assert!(
                !out.status.success(),
                "{what}: init did not exit failing after poweroff returned"
            );
        }
        // Missing capability branch.
        let f = init_fixture(2, &[]);
        fs::remove_file(&f.cap).unwrap();
        let out = run_init_full(&f, &fix_cmdline("1"), "", "fail", false);
        assert!(
            !init_log(&f).contains("setpriv"),
            "dispatch reached without capability"
        );
        assert!(!out.status.success());
    }

    // ---- Bounded query fixtures (LV-06) ----

    fn query_retry(
        exe: &Path,
        grace: Duration,
        quarantine: Option<&Path>,
    ) -> crate::Result<String> {
        // Same freshly-written-script ETXTBSY window as the init fixture.
        let mut last = None;
        for _ in 0..10 {
            let result = run_bounded_with_grace(exe, &[], grace, quarantine);
            match result {
                Err(e) if e.message.contains("Text file busy") => {
                    std::thread::sleep(Duration::from_millis(25));
                    last = Some(e);
                }
                other => return other,
            }
        }
        Err(last.expect("looped on Text file busy"))
    }

    #[test]
    fn bounded_query_drains_pipe_pressure_concurrently() {
        // >64KB pipe buffer: waiting for exit before draining would deadlock.
        let dir = tempfile::tempdir().unwrap();
        let script = fixture_script(
            dir.path(),
            "q",
            "#!/bin/sh\nn=0\nwhile [ $n -lt 200 ]; do printf '%01024d' 0; n=$((n+1)); done\n",
        );
        let out = query_retry(&script, Duration::from_secs(10), Some(dir.path())).unwrap();
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
        let out = query_retry(&script, Duration::from_secs(5), Some(dir.path())).unwrap();
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
        let err = query_retry(&script, Duration::from_secs(1), Some(dir.path())).unwrap_err();
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
        let err = query_retry(&script, Duration::from_secs(10), Some(dir.path())).unwrap_err();
        assert!(err.message.contains("oversized"), "{}", err.message);
    }

    #[test]
    fn bounded_query_leader_near_deadline_completes_inside_bound() {
        // R2-02: the leader exits just before the reserved cleanup boundary
        // with a descendant holding the pipe; the single whole-query deadline
        // must still cover containment and the final drain (no fresh grace
        // per phase), completing within roughly grace + one poll slice.
        let dir = tempfile::tempdir().unwrap();
        let script = fixture_script(
            dir.path(),
            "q",
            "#!/bin/sh\nsleep 0.55\necho near-deadline\n(sleep 30) &\nexit 0\n",
        );
        let start = Instant::now();
        let out = query_retry(&script, Duration::from_secs(1), Some(dir.path())).unwrap();
        let elapsed = start.elapsed();
        assert!(out.contains("near-deadline"), "{out}");
        assert!(
            elapsed < Duration::from_millis(1500),
            "whole query exceeded its bound: {elapsed:?}",
        );
    }

    #[test]
    fn bounded_query_budget_exhaustion_retains_and_recovers() {
        // R3-04 production injection: the query leader is still running at
        // the reserve boundary and its group holds a member that can never
        // be reaped inside the bound (its parent moved out of the group and
        // never waits). The query must fail bounded as containment
        // unconfirmed, retain the owned process with a durable record, and
        // clear only once the exact identity is gone.
        let _g = super::VM_TEST_LOCK.lock().unwrap();
        assert!(contained_registry().is_empty(), "clean registry needed");
        let dir = tempfile::tempdir().unwrap();
        let hfile = dir.path().join("h.pid");
        let zfile = dir.path().join("z.pid");
        let moved = dir.path().join("h.moved");
        let script = fixture_script(
            dir.path(),
            "q",
            &format!(
                "#!/bin/sh\nperl -e 'my $z=fork; exit 1 unless defined $z; if($z==0){{ sleep 60; exit }} open(F,\">\",\"{z}\") or exit 1; print F \"$z\\n\"; close F; syscall(109,0,0); open(G,\">\",\"{m}\") or exit 1; close G; sleep 600;' &\nhp=$!\necho $hp > '{h}'\ni=0; while [ ! -s '{m}' ] && [ $i -lt 200 ]; do i=$((i+1)); sleep 0.05; done\nsleep 30\nexit 0\n",
                z = zfile.display(),
                m = moved.display(),
                h = hfile.display(),
            ),
        );
        let start = Instant::now();
        let err = query_retry(&script, Duration::from_millis(400), Some(dir.path())).unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.message.contains("unconfirmed"), "{}", err.message);
        assert!(
            elapsed < Duration::from_millis(1200),
            "retained query blew its bound: {elapsed:?}"
        );
        let text = fs::read_to_string(dir.path().join(CONTAINMENT_FILE)).unwrap();
        assert!(
            text.contains("qemu query containment unconfirmed"),
            "{text}"
        );
        assert_eq!(contained_registry().len(), 1);

        // Recovery: end Z's non-reaping parent so the kernel reaps the
        // killed member; the production recovery helper then drops the
        // guard and clears the durable record.
        let hpid: i32 = fs::read_to_string(&hfile).unwrap().trim().parse().unwrap();
        // SAFETY: hpid is the helper process this fixture created.
        unsafe { libc::kill(hpid, libc::SIGKILL) };
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if recover_or_refuse(dir.path()).is_ok() {
                break;
            }
            assert!(Instant::now() < until, "query containment never recovered");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(contained_registry().is_empty());
        assert!(!dir.path().join(CONTAINMENT_FILE).exists());
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

    #[test]
    fn member_scan_distinguishes_complete_from_uncertain() {
        // R3-01: a complete scan proves membership; an exhausted or failed
        // scan is Uncertain and can never be read as "group gone".
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 5")
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = child.id() as i32;
        let bound = group_bound_ticks_now();
        match group_members_checked(pgid, bound, Instant::now() + Duration::from_secs(2)) {
            MemberScan::Complete(members) => {
                assert!(
                    members.contains(&pgid),
                    "own child must be listed: {members:?}"
                );
                assert!(still_group_member(pgid, pgid, bound));
            }
            MemberScan::Uncertain => panic!("scan of a quiet proc must be complete"),
        }
        // A scan whose budget is already spent is Uncertain, never empty.
        assert!(matches!(
            group_members_checked(pgid, bound, Instant::now()),
            MemberScan::Uncertain
        ));
        // SAFETY: SIGKILL targets the group this test created (pgid == child).
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
        let _ = child.wait();
        match group_members_checked(pgid, u64::MAX, Instant::now() + Duration::from_secs(2)) {
            MemberScan::Complete(members) => assert!(!members.contains(&pgid)),
            // Uncertain remains a legitimate conservative answer.
            MemberScan::Uncertain => {}
        }
    }
}
