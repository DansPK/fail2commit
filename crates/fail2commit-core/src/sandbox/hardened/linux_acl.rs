//! Crash-recoverable per-job Linux ACL grants for the authenticated service.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use crate::isolation::JobSpec;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_ACL_OUTPUT: usize = 128 * 1024;
const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_TARGETS: usize = 50_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    uid: u32,
    scope_unit: Option<String>,
    records: Vec<JournalRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    path: String,
    dev: u64,
    ino: u64,
    uid: u32,
    acl: String,
}

struct Target {
    path: PathBuf,
    file: File,
    record: JournalRecord,
    permissions: String,
}

pub(crate) struct GrantGuard {
    journal_path: PathBuf,
    targets: Vec<Target>,
    uid: u32,
    scope_unit: Option<String>,
    active: bool,
}

impl GrantGuard {
    pub(crate) fn apply(
        job: &JobSpec,
        peer_uid: u32,
        sandbox_uid: u32,
        extra: &[(PathBuf, &'static str)],
        journal_dir: &Path,
        scope_unit: Option<&str>,
    ) -> crate::Result<Self> {
        let getfacl = trusted_tool("getfacl")?;
        let setfacl = trusted_tool("setfacl")?;
        verify_journal_dir(journal_dir)?;
        let requests = collect_requests(job, peer_uid, sandbox_uid, extra)?;
        if requests.len() > MAX_TARGETS {
            return Err(crate::Error::isolation_unavailable(
                "hardened ACL target count exceeds the safety limit",
            ));
        }
        let mut targets = Vec::with_capacity(requests.len());
        let mut records = Vec::with_capacity(requests.len());
        let pid = std::process::id();
        let mut total = 0usize;
        for (path, permissions) in requests {
            let file = open_acl_target(&path, peer_uid)?;
            let meta = file.metadata()?;
            let proc_path = proc_fd_path(pid, file.as_raw_fd());
            let output = Command::new(&getfacl)
                .args([
                    "--absolute-names",
                    "--numeric",
                    "--",
                    proc_path.to_str().unwrap(),
                ])
                .output()?;
            if !output.status.success() || output.stdout.len() > MAX_ACL_OUTPUT {
                return Err(crate::Error::isolation_unavailable(
                    "getfacl failed or returned an oversized ACL record",
                ));
            }
            let mut acl = String::from_utf8(output.stdout)
                .map_err(|_| crate::Error::integrity("getfacl returned a non-UTF-8 ACL record"))?;
            let header_end = acl
                .find('\n')
                .ok_or_else(|| crate::Error::integrity("getfacl record has no header"))?;
            acl.replace_range(..header_end, &format!("# file: {}", path.display()));
            total = total
                .checked_add(acl.len())
                .ok_or_else(|| crate::Error::integrity("ACL journal size overflow"))?;
            if total > MAX_JOURNAL_BYTES {
                return Err(crate::Error::isolation_unavailable(
                    "hardened ACL journal exceeds the size limit",
                ));
            }
            let record = JournalRecord {
                path: path
                    .to_str()
                    .ok_or_else(|| crate::Error::rejected("hardened ACL target path is not UTF-8"))?
                    .to_owned(),
                dev: meta.dev(),
                ino: meta.ino(),
                uid: meta.uid(),
                acl,
            };
            records.push(record.clone());
            targets.push(Target {
                path,
                file,
                record,
                permissions,
            });
        }

        // Validate every pathname again after pinning all targets and before the
        // journal or the first ACL mutation. The handles remain authoritative for
        // applying and restoring the ACLs if an owner replaces a pathname later.
        validate_target_paths(&targets)?;

        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| crate::Error::internal("cannot generate ACL journal identity"))?;
        let journal_path = journal_dir.join(format!("grant-{}.json", hex::encode(random)));
        random.fill(0);
        let journal = Journal {
            version: 1,
            uid: peer_uid,
            scope_unit: scope_unit.map(str::to_owned),
            records,
        };
        write_journal(&journal_path, &journal)?;

        let mut guard = Self {
            journal_path,
            targets,
            uid: peer_uid,
            scope_unit: scope_unit.map(str::to_owned),
            active: true,
        };
        for target in &guard.targets {
            if let Err(error) = set_acl(&setfacl, target, peer_uid, &target.permissions) {
                return match guard.release() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(crate::Error::isolation_unavailable(format!(
                        "ACL grant failed: {}; exact ACL restoration is pending: {}",
                        error.message, cleanup.message
                    ))),
                };
            }
        }
        if let Err(error) = validate_target_paths(&guard.targets) {
            return match guard.release() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(crate::Error::isolation_unavailable(format!(
                    "ACL path changed after grant: {}; exact ACL restoration is pending: {}",
                    error.message, cleanup.message
                ))),
            };
        }
        Ok(guard)
    }

    pub(crate) fn release(&mut self) -> crate::Result<()> {
        if !self.active {
            return Ok(());
        }
        ensure_scope_inactive(self.scope_unit.as_deref())?;
        let setfacl = trusted_tool("setfacl")?;
        restore_targets(&setfacl, self.uid, &self.targets)?;
        remove_journal(&self.journal_path)?;
        self.active = false;
        Ok(())
    }

    /// Keep the root-owned journal for service-start recovery when a launcher
    /// or system scope could not be proven stopped.
    pub(crate) fn defer_recovery(&mut self) {
        self.active = false;
    }
}

impl Drop for GrantGuard {
    fn drop(&mut self) {
        // Restoration is allowed only after the caller proves that the job's
        // system scope is inactive. Any implicit drop keeps the journal so
        // the next service start can kill the recorded scope before recovery.
    }
}

pub(crate) fn recover(journal_dir: &Path) -> crate::Result<()> {
    verify_journal_dir(journal_dir)?;
    let setfacl = trusted_tool("setfacl")?;
    let mut entries = fs::read_dir(journal_dir)?.collect::<std::io::Result<Vec<_>>>()?;
    // Uncommitted pending records are created before any ACL mutation. Remove
    // them first, including a hard-link duplicate left by a crash between the
    // atomic no-replace commit and staging-name cleanup.
    entries.sort_by_key(|entry| {
        let name = entry.file_name();
        !name.to_string_lossy().ends_with(".pending")
    });
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "probe-stages" {
            continue;
        }
        if name.starts_with("grant-") && name.ends_with(".pending") {
            let path = entry.path();
            cleanup_pending(&path, 0)?;
            continue;
        }
        if !name.starts_with("grant-") || !name.ends_with(".json") {
            return Err(crate::Error::integrity(
                "unexpected object in hardened ACL journal directory",
            ));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.len() == 0
            || metadata.len() > MAX_JOURNAL_BYTES as u64
        {
            return Err(crate::Error::integrity(
                "hardened ACL recovery journal is unsafe",
            ));
        }
        let bytes = fs::read(&path)?;
        let journal: Journal = serde_json::from_slice(&bytes)
            .map_err(|_| crate::Error::integrity("hardened ACL recovery journal is malformed"))?;
        if journal.version != 1 || journal.uid == 0 || journal.records.len() > MAX_TARGETS {
            return Err(crate::Error::integrity(
                "hardened ACL recovery journal identity is invalid",
            ));
        }
        ensure_scope_inactive(journal.scope_unit.as_deref())?;
        let mut targets = Vec::with_capacity(journal.records.len());
        for record in journal.records {
            let file = open_recovery_target(&record, journal.uid)?;
            targets.push(Target {
                path: PathBuf::from(&record.path),
                file,
                record,
                permissions: String::new(),
            });
        }
        restore_targets(&setfacl, journal.uid, &targets)?;
        remove_journal(&path)?;
    }
    sweep_probe_stages(journal_dir)?;
    Ok(())
}

fn sweep_probe_stages(journal_dir: &Path) -> crate::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let root = journal_dir.join("probe-stages");
    let metadata = match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err(crate::Error::integrity(
            "Linux service probe staging root is not private and root-owned",
        ));
    }
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("probe-") {
            return Err(crate::Error::integrity(
                "unexpected object in Linux probe staging root",
            ));
        }
        let child = entry.path();
        let child_metadata = fs::symlink_metadata(&child)?;
        if !child_metadata.is_dir() || child_metadata.file_type().is_symlink() {
            return Err(crate::Error::integrity(
                "Linux probe staging object is not a directory",
            ));
        }
        fs::remove_dir_all(&child)?;
    }
    File::open(&root)?.sync_all()?;
    Ok(())
}

pub(crate) fn probe_stage_dir(journal_dir: &Path) -> crate::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    verify_journal_dir(journal_dir)?;
    let root = journal_dir.join("probe-stages");
    match fs::create_dir(&root) {
        Ok(()) => fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&root)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(crate::Error::integrity(
            "Linux service probe staging root has unsafe ownership or mode",
        ));
    }
    Ok(root)
}

fn cleanup_pending(path: &Path, expected_uid: u32) -> crate::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let metadata = fs::symlink_metadata(path)?;
    if !name.starts_with("grant-")
        || !name.ends_with(".json.pending")
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() > 2
        || metadata.len() > MAX_JOURNAL_BYTES as u64
    {
        return Err(crate::Error::integrity(
            "hardened ACL pending journal is unsafe",
        ));
    }
    remove_journal(path)
}

fn ensure_scope_inactive(scope_unit: Option<&str>) -> crate::Result<()> {
    let Some(unit) = scope_unit else {
        return Ok(());
    };
    if !valid_scope_unit(unit) {
        return Err(crate::Error::integrity(
            "ACL journal contains an invalid transient scope identity",
        ));
    }
    let systemctl = trusted_tool("systemctl")?;
    if scope_is_active(&systemctl, unit)? {
        let kill = Command::new(&systemctl)
            .args(["kill", "--kill-whom=all", "--signal=KILL", unit])
            .status()?;
        if !kill.success() {
            return Err(crate::Error::isolation_unavailable(
                "cannot terminate the previous hardened system scope before ACL recovery",
            ));
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if !scope_is_active(&systemctl, unit)? {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(crate::Error::isolation_unavailable(
                "previous hardened system scope remained active during ACL recovery",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

fn valid_scope_unit(unit: &str) -> bool {
    unit.len() == 55
        && unit.starts_with("f2c-hardened-job-")
        && unit.ends_with(".scope")
        && unit.as_bytes()[17..49]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn scope_is_active(systemctl: &Path, unit: &str) -> crate::Result<bool> {
    let load = Command::new(systemctl)
        .args(["show", "--property=LoadState", "--value", unit])
        .output()?;
    if !load.status.success() {
        return Err(crate::Error::isolation_unavailable(
            "cannot read systemd load state before ACL restoration",
        ));
    }
    match String::from_utf8_lossy(&load.stdout).trim() {
        "not-found" => return Ok(false),
        "loaded" | "masked" | "static" => {}
        _ => {
            return Err(crate::Error::integrity(
                "systemd returned an unknown scope load state during ACL recovery",
            ))
        }
    }
    let active = Command::new(systemctl)
        .args(["show", "--property=ActiveState", "--value", unit])
        .output()?;
    if !active.status.success() {
        return Err(crate::Error::isolation_unavailable(
            "cannot read systemd active state before ACL restoration",
        ));
    }
    match String::from_utf8_lossy(&active.stdout).trim() {
        "active" | "activating" | "deactivating" | "reloading" => Ok(true),
        "inactive" | "failed" => Ok(false),
        _ => Err(crate::Error::integrity(
            "systemd returned an unknown scope active state during ACL recovery",
        )),
    }
}

pub(crate) fn recover_if_present(journal_dir: &Path) -> crate::Result<()> {
    match fs::symlink_metadata(journal_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => recover(journal_dir),
    }
}

/// Persist the exact transient unit before a probe can create it. A service
/// crash therefore leaves a recovery journal that prevents the next status
/// check from passing until that scope is confirmed inactive.
pub(crate) fn mark_probe_scope(
    journal_dir: &Path,
    uid: u32,
    scope_unit: &str,
) -> crate::Result<PathBuf> {
    if uid == 0 || !valid_scope_unit(scope_unit) {
        return Err(crate::Error::rejected(
            "probe scope journal identity is invalid",
        ));
    }
    verify_journal_dir(journal_dir)?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| crate::Error::internal("cannot generate probe scope journal identity"))?;
    let path = journal_dir.join(format!("grant-{}.json", hex::encode(random)));
    random.fill(0);
    let marker = Journal {
        version: 1,
        uid,
        scope_unit: Some(scope_unit.to_owned()),
        records: Vec::new(),
    };
    write_journal(&path, &marker)?;
    Ok(path)
}

pub(crate) fn clear_probe_scope_marker(path: &Path, scope_unit: &str) -> crate::Result<()> {
    let bytes = fs::read(path)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(crate::Error::integrity(
            "probe scope journal exceeded its size limit",
        ));
    }
    let marker: Journal = serde_json::from_slice(&bytes)
        .map_err(|_| crate::Error::integrity("probe scope journal is malformed"))?;
    if marker.version != 1
        || marker.uid == 0
        || marker.scope_unit.as_deref() != Some(scope_unit)
        || !marker.records.is_empty()
    {
        return Err(crate::Error::integrity(
            "probe scope journal identity changed",
        ));
    }
    ensure_scope_inactive(Some(scope_unit))?;
    remove_journal(path)
}

fn collect_requests(
    job: &JobSpec,
    peer_uid: u32,
    sandbox_uid: u32,
    extra: &[(PathBuf, &'static str)],
) -> crate::Result<BTreeMap<PathBuf, String>> {
    let mut requests = BTreeMap::<PathBuf, String>::new();
    let mut roots = Vec::new();
    for path in &job.read_only {
        let canonical = canonical_job_dir(path, peer_uid)?;
        roots.push(canonical.clone());
        collect_tree(
            &canonical,
            "r-x",
            peer_uid,
            &mut requests,
            &mut BTreeSet::new(),
        )?;
    }
    let work = canonical_job_dir(&job.work_dir, peer_uid)?;
    roots.push(work.clone());
    collect_tree(&work, "rwX", peer_uid, &mut requests, &mut BTreeSet::new())?;
    let cwd = job.cwd.canonicalize()?;
    if !cwd.starts_with(&work) {
        return Err(crate::Error::rejected(
            "hardened Linux cwd is outside its granted work directory",
        ));
    }
    for root in &roots {
        let mut parent = root.parent();
        while let Some(path) = parent {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.uid() != sandbox_uid {
                merge_permission(&mut requests, path.to_path_buf(), "--x");
            }
            if path == Path::new("/") {
                break;
            }
            parent = path.parent();
        }
    }
    for (path, permissions) in extra {
        let canonical = path.canonicalize().map_err(|error| {
            crate::Error::rejected(format!(
                "hardened service snapshot path is invalid: {error}"
            ))
        })?;
        let mut parent = canonical.parent();
        while let Some(path) = parent {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.uid() != sandbox_uid {
                merge_permission(&mut requests, path.to_path_buf(), "--x");
            }
            if path == Path::new("/") {
                break;
            }
            parent = path.parent();
        }
        merge_permission(&mut requests, canonical, permissions);
    }
    for path in requests.keys() {
        let _ = open_acl_target(path, peer_uid)?;
    }
    Ok(requests)
}

fn canonical_job_dir(path: &Path, peer_uid: u32) -> crate::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(crate::Error::rejected(
            "hardened Linux job paths must be absolute",
        ));
    }
    let canonical = path.canonicalize()?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || !caller_stage_owner_matches(metadata.uid(), peer_uid)
    {
        return Err(crate::Error::rejected(
            "hardened Linux path owner or directory type is invalid",
        ));
    }
    Ok(canonical)
}

fn collect_tree(
    root: &Path,
    permissions: &'static str,
    peer_uid: u32,
    requests: &mut BTreeMap<PathBuf, String>,
    visited: &mut BTreeSet<PathBuf>,
) -> crate::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let canonical = dir.canonicalize()?;
        if !visited.insert(canonical.clone()) {
            continue;
        }
        let metadata = fs::symlink_metadata(&canonical)?;
        if metadata.file_type().is_symlink()
            || !caller_stage_owner_matches(metadata.uid(), peer_uid)
            || !(metadata.is_dir() || metadata.is_file())
        {
            return Err(crate::Error::rejected(
                "hardened Linux staging tree contains a non-peer-owned or unsupported object",
            ));
        }
        merge_permission(requests, canonical.clone(), permissions);
        if metadata.is_dir() {
            for entry in fs::read_dir(&canonical)? {
                let entry = entry?;
                let child = entry.path();
                let child_meta = fs::symlink_metadata(&child)?;
                if child_meta.file_type().is_symlink() {
                    if !caller_stage_owner_matches(child_meta.uid(), peer_uid) {
                        return Err(crate::Error::rejected(
                            "hardened Linux staging symlink is not owned by the authenticated peer",
                        ));
                    }
                    let target = child.canonicalize().map_err(|_| {
                        crate::Error::rejected(
                            "hardened Linux staging tree contains a dangling symlink",
                        )
                    })?;
                    if !target.starts_with(root) {
                        return Err(crate::Error::rejected(
                            "hardened Linux staging symlink escapes its granted root",
                        ));
                    }
                } else {
                    stack.push(child);
                }
            }
        }
        if requests.len() > MAX_TARGETS {
            return Err(crate::Error::isolation_unavailable(
                "hardened Linux staging tree exceeds the ACL entry limit",
            ));
        }
    }
    Ok(())
}

fn caller_stage_owner_matches(owner_uid: u32, peer_uid: u32) -> bool {
    peer_uid != 0 && owner_uid == peer_uid
}

fn validate_target_paths(targets: &[Target]) -> crate::Result<()> {
    use std::os::unix::fs::MetadataExt;
    for target in targets {
        let path_metadata = fs::symlink_metadata(&target.path)?;
        let pinned = target.file.metadata()?;
        if path_metadata.file_type().is_symlink()
            || !(path_metadata.is_dir() || path_metadata.is_file())
            || path_metadata.dev() != target.record.dev
            || path_metadata.ino() != target.record.ino
            || path_metadata.uid() != target.record.uid
            || pinned.dev() != target.record.dev
            || pinned.ino() != target.record.ino
            || pinned.uid() != target.record.uid
        {
            return Err(crate::Error::rejected(format!(
                "hardened Linux stage path changed during ACL preparation: {}",
                target.path.display()
            )));
        }
    }
    Ok(())
}

fn merge_permission(map: &mut BTreeMap<PathBuf, String>, path: PathBuf, permission: &str) {
    let entry = map.entry(path).or_default();
    for bit in permission
        .chars()
        .filter(|bit| matches!(bit, 'r' | 'w' | 'x' | 'X'))
    {
        if !entry.contains(bit) {
            entry.push(bit);
        }
    }
    let execute = if entry.contains('x') {
        Some('x')
    } else if entry.contains('X') {
        Some('X')
    } else {
        None
    };
    let ordered: String = ['r', 'w']
        .into_iter()
        .filter(|bit| entry.contains(*bit))
        .collect();
    *entry = execute.map_or(ordered.clone(), |bit| format!("{ordered}{bit}"));
}

fn open_acl_target(path: &Path, peer_uid: u32) -> crate::Result<File> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(crate::Error::rejected("ACL target must be absolute"));
    }
    let canonical = path.canonicalize()?;
    if canonical != path {
        return Err(crate::Error::rejected("ACL target is not canonical"));
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !(metadata.is_dir() || metadata.is_file())
        || (metadata.uid() != peer_uid && metadata.uid() != 0)
        || (metadata.is_file() && metadata.nlink() != 1)
    {
        return Err(crate::Error::rejected(
            "ACL target identity is not an owned regular file or directory",
        ));
    }
    Ok(file)
}

fn set_acl(tool: &Path, target: &Target, uid: u32, permissions: &str) -> crate::Result<()> {
    let proc_path = proc_fd_path(std::process::id(), target.file.as_raw_fd());
    let metadata = target.file.metadata()?;
    let spec = acl_grant_spec(
        &target.record.acl,
        uid,
        permissions,
        metadata.is_dir(),
        metadata.mode(),
    )?;
    if !spec.is_empty() {
        let output = Command::new(tool)
            .args(["--modify", "--no-mask", &spec, "--"])
            .arg(&proc_path)
            .output()?;
        if !output.status.success() {
            return Err(crate::Error::isolation_unavailable(format!(
                "setfacl grant failed for {}: {}",
                target.path.display(),
                bounded_stderr(&output.stderr)
            )));
        }
    }
    let observed = Command::new(trusted_tool("getfacl")?)
        .args([
            "--absolute-names",
            "--numeric",
            "--",
            proc_path.to_str().unwrap(),
        ])
        .output()?;
    if !observed.status.success()
        || observed.stdout.len() > MAX_ACL_OUTPUT
        || !acl_grant_is_effective(
            &String::from_utf8_lossy(&observed.stdout),
            uid,
            permissions,
            metadata.is_dir(),
            metadata.mode(),
        )?
    {
        return Err(crate::Error::isolation_unavailable(format!(
            "setfacl did not grant the required effective access to {}",
            target.path.display()
        )));
    }
    Ok(())
}

fn acl_grant_spec(
    acl: &str,
    uid: u32,
    request: &str,
    is_dir: bool,
    mode: u32,
) -> crate::Result<String> {
    let entries = parse_acl(acl)?;
    let old_mask = entries
        .get(&("mask".to_owned(), String::new()))
        .or_else(|| entries.get(&("group".to_owned(), String::new())))
        .copied()
        .ok_or_else(|| crate::Error::integrity("getfacl record has no group class entry"))?;
    let required = requested_bits(request, is_dir, mode);
    let new_mask = old_mask | required;
    let uid_text = uid.to_string();
    let mut specs = Vec::new();
    for ((tag, qualifier), bits) in &entries {
        if tag == "user" && qualifier.is_empty() {
            continue;
        }
        if tag == "mask" || tag == "other" {
            continue;
        }
        let value = if tag == "user" && qualifier == &uid_text {
            (*bits & old_mask) | required
        } else {
            *bits & old_mask
        };
        if tag == "group" && qualifier.is_empty() {
            if value != *bits {
                specs.push(format!("g::{}", format_bits(value)));
            }
        } else if tag == "user" || tag == "group" {
            if value != *bits {
                let short = if tag == "user" { 'u' } else { 'g' };
                specs.push(format!("{short}:{qualifier}:{}", format_bits(value)));
            }
        }
    }
    if !entries.contains_key(&("user".to_owned(), uid_text.clone())) {
        specs.push(format!("u:{uid}:{}", format_bits(required)));
    }
    if new_mask != old_mask || !entries.contains_key(&("mask".to_owned(), String::new())) {
        specs.push(format!("m::{}", format_bits(new_mask)));
    }
    if specs.is_empty() {
        return Ok(String::new());
    }
    let joined = specs.join(",");
    if joined.len() > MAX_ACL_OUTPUT {
        return Err(crate::Error::isolation_unavailable(
            "hardened ACL grant specification exceeds its size limit",
        ));
    }
    Ok(joined)
}

fn acl_grant_is_effective(
    acl: &str,
    uid: u32,
    request: &str,
    is_dir: bool,
    mode: u32,
) -> crate::Result<bool> {
    let entries = parse_acl(acl)?;
    let uid_text = uid.to_string();
    let Some(raw) = entries.get(&("user".to_owned(), uid_text)) else {
        return Ok(false);
    };
    let Some(mask) = entries
        .get(&("mask".to_owned(), String::new()))
        .or_else(|| entries.get(&("group".to_owned(), String::new())))
    else {
        return Ok(false);
    };
    let required = requested_bits(request, is_dir, mode);
    Ok(raw & mask & required == required)
}

fn parse_acl(acl: &str) -> crate::Result<BTreeMap<(String, String), u8>> {
    let mut entries = BTreeMap::new();
    for line in acl.lines() {
        let line = line.trim();
        let Some((tag, rest)) = line.split_once(':') else {
            continue;
        };
        if !matches!(tag, "user" | "group" | "mask" | "other") {
            continue;
        }
        let fields: Vec<&str> = rest.split(':').collect();
        let (qualifier, permission) = match (tag, fields.as_slice()) {
            ("user" | "group", [qualifier, permission, ..]) => (*qualifier, *permission),
            ("mask" | "other", ["", permission, ..]) => ("", *permission),
            _ => continue,
        };
        let permission = permission.split_whitespace().next().unwrap_or("");
        let key = (tag.to_owned(), qualifier.to_owned());
        let bits = permission_bits(permission);
        if entries.insert(key, bits).is_some() {
            return Err(crate::Error::integrity(
                "getfacl record contains duplicate entries",
            ));
        }
    }
    Ok(entries)
}

fn permission_bits(value: &str) -> u8 {
    u8::from(value.contains('r'))
        | (u8::from(value.contains('w')) << 1)
        | (u8::from(value.contains('x')) << 2)
}

fn requested_bits(value: &str, is_dir: bool, mode: u32) -> u8 {
    let execute = value.contains('x') || (value.contains('X') && (is_dir || mode & 0o111 != 0));
    u8::from(value.contains('r')) | (u8::from(value.contains('w')) << 1) | (u8::from(execute) << 2)
}

fn format_bits(bits: u8) -> String {
    [
        if bits & 1 != 0 { 'r' } else { '-' },
        if bits & 2 != 0 { 'w' } else { '-' },
        if bits & 4 != 0 { 'x' } else { '-' },
    ]
    .into_iter()
    .collect()
}

fn restore_targets(tool: &Path, uid: u32, targets: &[Target]) -> crate::Result<()> {
    for target in targets.iter().rev() {
        let metadata = target.file.metadata()?;
        if metadata.dev() != target.record.dev
            || metadata.ino() != target.record.ino
            || metadata.uid() != target.record.uid
        {
            return Err(crate::Error::integrity(
                "hardened ACL target identity changed before restoration",
            ));
        }
        restore_acl(tool, target, uid)?;
    }
    Ok(())
}

fn restore_acl(tool: &Path, target: &Target, _uid: u32) -> crate::Result<()> {
    use std::io::Write;
    let proc_path = proc_fd_path(std::process::id(), target.file.as_raw_fd());
    let mut acl = target.record.acl.clone();
    let header_end = acl
        .find('\n')
        .ok_or_else(|| crate::Error::integrity("saved ACL record has no header"))?;
    acl.replace_range(..header_end, &format!("# file: {}", proc_path.display()));
    let mut child = Command::new(tool)
        .args(["--restore", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| crate::Error::internal("setfacl restore stdin is unavailable"))?
        .write_all(acl.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(crate::Error::isolation_unavailable(format!(
            "setfacl exact restoration failed for {}: {}",
            target.path.display(),
            bounded_stderr(&output.stderr)
        )));
    }
    Ok(())
}

fn proc_fd_path(pid: u32, fd: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/fd/{fd}"))
}

fn write_journal(path: &Path, journal: &Journal) -> crate::Result<()> {
    let bytes = serde_json::to_vec(journal)
        .map_err(|_| crate::Error::internal("cannot encode hardened ACL journal"))?;
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return Err(crate::Error::isolation_unavailable(
            "hardened ACL journal exceeds the size limit",
        ));
    }
    write_journal_bytes(path, &bytes, &RealJournalOps)
}

trait JournalOps {
    fn write(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()>;
    fn sync_file(&self, file: &File) -> std::io::Result<()>;
    fn publish(&self, pending: &Path, path: &Path) -> std::io::Result<()>;
    fn sync_parent(&self, parent: &Path) -> std::io::Result<()>;
    fn remove(&self, path: &Path) -> std::io::Result<()>;
}

struct RealJournalOps;

impl JournalOps for RealJournalOps {
    fn write(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        file.write_all(bytes)
    }

    fn sync_file(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }

    fn publish(&self, pending: &Path, path: &Path) -> std::io::Result<()> {
        fs::hard_link(pending, path)
    }

    fn sync_parent(&self, parent: &Path) -> std::io::Result<()> {
        File::open(parent)?.sync_all()
    }

    fn remove(&self, path: &Path) -> std::io::Result<()> {
        fs::remove_file(path)
    }
}

fn write_journal_bytes(path: &Path, bytes: &[u8], ops: &impl JournalOps) -> crate::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| crate::Error::integrity("ACL journal path has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| crate::Error::integrity("ACL journal path has no file name"))?
        .to_string_lossy();
    if !name.starts_with("grant-") || !name.ends_with(".json") {
        return Err(crate::Error::integrity("ACL journal path is not managed"));
    }
    let pending = parent.join(format!("{name}.pending"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&pending)?;
    let staged = (|| -> std::io::Result<()> {
        ops.write(&mut file, bytes)?;
        ops.sync_file(&file)?;
        Ok(())
    })();
    drop(file);
    let mut published = false;
    let result = staged.and_then(|()| {
        // hard_link is atomic and fails if the final record already exists;
        // this prevents a random-name collision from overwriting recovery data.
        ops.publish(&pending, path)?;
        published = true;
        ops.remove(&pending)?;
        ops.sync_parent(parent)
    });
    if let Err(error) = result {
        let mut cleanup_errors = Vec::new();
        let mut cleanup_paths = vec![pending.as_path()];
        if published {
            cleanup_paths.push(path);
        }
        for cleanup in cleanup_paths {
            match ops.remove(cleanup) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => cleanup_errors.push(format!("{}: {e}", cleanup.display())),
            }
        }
        if let Err(sync_error) = ops.sync_parent(parent) {
            cleanup_errors.push(format!("parent sync: {sync_error}"));
        }
        return if cleanup_errors.is_empty() {
            Err(crate::Error::isolation_unavailable(format!(
                "ACL journal commit failed before any ACL mutation: {error}"
            )))
        } else {
            Err(crate::Error::isolation_unavailable(format!(
                "ACL journal commit failed before any ACL mutation: {error}; cleanup is pending for {}",
                cleanup_errors.join("; ")
            )))
        };
    }
    Ok(())
}

fn remove_journal(path: &Path) -> crate::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(crate::Error::isolation_unavailable(format!(
                "cannot remove hardened ACL journal: {error}"
            )))
        }
    }
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn open_recovery_target(record: &JournalRecord, peer_uid: u32) -> crate::Result<File> {
    let path = Path::new(&record.path);
    let file = open_acl_target(path, peer_uid)?;
    let metadata = file.metadata()?;
    if metadata.dev() != record.dev || metadata.ino() != record.ino || metadata.uid() != record.uid
    {
        return Err(crate::Error::integrity(
            "hardened ACL recovery path no longer identifies the journaled object",
        ));
    }
    Ok(file)
}

fn verify_journal_dir(path: &Path) -> crate::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err(crate::Error::integrity(
            "hardened ACL journal directory is not root-owned and private",
        ));
    }
    Ok(())
}

fn trusted_tool(name: &str) -> crate::Result<PathBuf> {
    for candidate in [
        PathBuf::from(format!("/usr/bin/{name}")),
        PathBuf::from(format!("/bin/{name}")),
    ] {
        let Ok(path) = candidate.canonicalize() else {
            continue;
        };
        let metadata = fs::metadata(&path)?;
        let parent = fs::metadata(path.parent().unwrap_or(Path::new("/")))?;
        if metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
            && parent.uid() == 0
            && parent.mode() & 0o022 == 0
        {
            return Ok(path);
        }
    }
    Err(crate::Error::isolation_unavailable(format!(
        "trusted system {name} is unavailable"
    )))
}

pub(crate) fn verify_required_tools() -> crate::Result<()> {
    trusted_tool("getfacl")?;
    trusted_tool("setfacl")?;
    Ok(())
}

fn bounded_stderr(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(240).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::{JobLimits, JobSpec, NetworkMode};
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;

    fn job(work: &Path, read_only: &Path) -> JobSpec {
        JobSpec {
            program: PathBuf::from("/bin/true"),
            args: Vec::new(),
            cwd: work.to_path_buf(),
            env: Vec::new(),
            read_only: vec![read_only.to_path_buf()],
            work_dir: work.to_path_buf(),
            exports: Vec::new(),
            export_to: None,
            limits: JobLimits {
                timeout: Duration::from_secs(1),
                memory_bytes: Some(16 * 1024 * 1024),
                max_processes: Some(2),
                max_output_bytes: 1024,
                disk_bytes: Some(16 * 1024 * 1024),
            },
            network: NetworkMode::None,
            bait: false,
        }
    }

    #[test]
    fn acl_grant_widens_mask_without_widening_existing_group_or_named_user_access() {
        let baseline =
            "# file: /fixture\nuser::rwx\nuser:3000:rwx\ngroup::rwx\nmask::---\nother::---\n";
        let spec = acl_grant_spec(baseline, 2000, "r--", false, 0o600).unwrap();
        let changes: BTreeMap<_, _> = spec
            .split(',')
            .filter_map(|entry| {
                let mut fields = entry.split(':');
                let tag = fields.next()?;
                let qualifier = fields.next()?;
                let perms = fields.next()?;
                Some((
                    (tag.to_owned(), qualifier.to_owned()),
                    permission_bits(perms),
                ))
            })
            .collect();
        assert_eq!(changes.get(&("g".into(), "".into())), Some(&0));
        assert_eq!(changes.get(&("u".into(), "3000".into())), Some(&0));
        assert_eq!(changes.get(&("u".into(), "2000".into())), Some(&1));
        assert_eq!(changes.get(&("m".into(), "".into())), Some(&1));
        let original_group = permission_bits("rwx") & permission_bits("---");
        let granted_group = changes[&(String::from("g"), String::new())]
            & changes[&(String::from("m"), String::new())];
        assert_eq!(original_group, granted_group);
    }

    #[test]
    fn uppercase_execute_is_only_granted_to_directories_or_executable_files() {
        assert_eq!(requested_bits("rwX", false, 0o644), 3);
        assert_eq!(requested_bits("rwX", false, 0o755), 7);
        assert_eq!(requested_bits("rwX", true, 0o700), 7);
    }

    #[test]
    fn recovery_scope_name_is_exact_and_cannot_inject_systemctl_arguments() {
        assert!(valid_scope_unit(
            "f2c-hardened-job-0123456789abcdef0123456789abcdef.scope"
        ));
        for invalid in [
            "--no-block",
            "f2c-hardened-job-0123456789abcdef0123456789abcdeg.scope",
            "f2c-hardened-job-0123456789abcdef0123456789abcdef.scope.extra",
        ] {
            assert!(!valid_scope_unit(invalid), "{invalid}");
        }
    }

    #[test]
    fn staging_grants_reject_a_symlink_that_escapes_the_owned_root() {
        let tree = tempfile::tempdir().unwrap();
        let work = tree.path().join("work");
        let readonly = tree.path().join("readonly");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(&readonly).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret");
        std::fs::write(&outside_file, b"secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_file, work.join("escape")).unwrap();
        let uid = std::fs::metadata(&work).unwrap().uid();
        let spec = job(&work, &readonly);
        assert!(collect_requests(&spec, uid, u32::MAX, &[]).is_err());
    }

    #[test]
    fn caller_stage_owner_policy_never_authorizes_root_owned_objects() {
        assert!(caller_stage_owner_matches(12345, 12345));
        assert!(!caller_stage_owner_matches(0, 12345));
        assert!(!caller_stage_owner_matches(12345, 0));
    }

    #[test]
    fn path_substitution_is_detected_before_acl_grants() {
        let tree = tempfile::tempdir().unwrap();
        let path = tree.path().join("stage-file");
        let replacement = tree.path().join("replacement");
        std::fs::write(&path, b"original").unwrap();
        std::fs::write(&replacement, b"replacement").unwrap();
        let file = File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let target = Target {
            path: path.clone(),
            file,
            record: JournalRecord {
                path: path.to_string_lossy().into_owned(),
                dev: metadata.dev(),
                ino: metadata.ino(),
                uid: metadata.uid(),
                acl: String::new(),
            },
            permissions: "r--".into(),
        };
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(replacement, &path).unwrap();
        assert!(validate_target_paths(&[target]).is_err());
    }

    #[derive(Clone, Copy)]
    enum JournalFailure {
        Write,
        FileSync,
        Publish,
        ParentSync,
        WriteAndRemove,
    }

    struct FaultJournalOps {
        failure: JournalFailure,
    }

    impl JournalOps for FaultJournalOps {
        fn write(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
            use std::io::Write;
            if matches!(
                self.failure,
                JournalFailure::Write | JournalFailure::WriteAndRemove
            ) {
                file.write_all(&bytes[..bytes.len().min(3)])?;
                return Err(std::io::Error::other("injected journal write failure"));
            }
            file.write_all(bytes)
        }

        fn sync_file(&self, file: &File) -> std::io::Result<()> {
            if matches!(self.failure, JournalFailure::FileSync) {
                return Err(std::io::Error::other("injected journal file sync failure"));
            }
            file.sync_all()
        }

        fn publish(&self, pending: &Path, path: &Path) -> std::io::Result<()> {
            if matches!(self.failure, JournalFailure::Publish) {
                return Err(std::io::Error::other("injected journal publish failure"));
            }
            RealJournalOps.publish(pending, path)
        }

        fn sync_parent(&self, parent: &Path) -> std::io::Result<()> {
            if matches!(self.failure, JournalFailure::ParentSync) {
                return Err(std::io::Error::other(
                    "injected journal parent sync failure",
                ));
            }
            RealJournalOps.sync_parent(parent)
        }

        fn remove(&self, path: &Path) -> std::io::Result<()> {
            if matches!(self.failure, JournalFailure::WriteAndRemove) {
                return Err(std::io::Error::other("injected journal cleanup failure"));
            }
            RealJournalOps.remove(path)
        }
    }

    #[test]
    fn journal_faults_cleanup_partials_and_leave_retryable_path_when_delete_fails() {
        let payload = br#"{"version":1,"uid":12345,"scope_unit":null,"records":[]}"#;
        for failure in [
            JournalFailure::Write,
            JournalFailure::FileSync,
            JournalFailure::Publish,
            JournalFailure::ParentSync,
        ] {
            let tree = tempfile::tempdir().unwrap();
            let path = tree.path().join("grant-test.json");
            assert!(write_journal_bytes(&path, payload, &FaultJournalOps { failure }).is_err());
            assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 0);
        }

        let tree = tempfile::tempdir().unwrap();
        let path = tree.path().join("grant-retry.json");
        let error = write_journal_bytes(
            &path,
            payload,
            &FaultJournalOps {
                failure: JournalFailure::WriteAndRemove,
            },
        )
        .unwrap_err();
        let pending = tree.path().join("grant-retry.json.pending");
        assert!(error.message.contains(&pending.display().to_string()));
        assert!(pending.is_file());
        let uid = std::fs::metadata(&pending).unwrap().uid();
        cleanup_pending(&pending, uid).unwrap();
        assert!(!pending.exists());
        assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 0);
    }

    #[test]
    fn journal_name_collision_never_removes_preexisting_recovery_record() {
        let tree = tempfile::tempdir().unwrap();
        let path = tree.path().join("grant-collision.json");
        let existing = br#"{"version":1,"uid":23456,"scope_unit":null,"records":[]}"#;
        std::fs::write(&path, existing).unwrap();
        let payload = br#"{"version":1,"uid":12345,"scope_unit":null,"records":[]}"#;

        assert!(write_journal_bytes(&path, payload, &RealJournalOps).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), existing);
        assert!(!tree.path().join("grant-collision.json.pending").exists());
        assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root to create a peer-owned tree containing a root-owned fixture"]
    fn grant_guard_rejects_inaccessible_root_owned_file_without_acl_or_journal_changes() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let tree = tempfile::tempdir_in("/tmp").unwrap();
        let work = tree.path().join("work");
        let readonly = tree.path().join("readonly");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(&readonly).unwrap();
        let secret = readonly.join("root-only.txt");
        std::fs::write(&secret, b"not peer readable").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let peer_uid = 12345;
        // SAFETY: this root-only ignored test creates the same ownership
        // boundary as an authenticated peer stage and an inaccessible root file.
        let work_name = std::ffi::CString::new(work.as_os_str().as_bytes()).unwrap();
        let read_only_name = std::ffi::CString::new(readonly.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(work_name.as_ptr(), peer_uid, u32::MAX) },
            0
        );
        assert_eq!(
            unsafe { libc::chown(read_only_name.as_ptr(), peer_uid, u32::MAX) },
            0
        );
        let journal = tree.path().join("journal");
        std::fs::create_dir(&journal).unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();
        let acl_tool = trusted_tool("getfacl").unwrap();
        let before = Command::new(&acl_tool)
            .args([
                "--absolute-names",
                "--numeric",
                "--",
                secret.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(before.status.success());
        let result = GrantGuard::apply(
            &job(&work, &readonly),
            peer_uid,
            u32::MAX,
            &[],
            &journal,
            None,
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(&journal).unwrap().count(), 0);
        let after = Command::new(&acl_tool)
            .args([
                "--absolute-names",
                "--numeric",
                "--",
                secret.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(after.status.success());
        assert_eq!(before.stdout, after.stdout);
    }
}
