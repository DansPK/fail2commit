//! Machine installation and lifecycle for the SPEC-018 hardened service.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
const LINUX_STATE: &str = "/etc/fail2commit-hardened.json";
#[cfg(target_os = "linux")]
const LINUX_UNIT_DIR: &str = "/etc/systemd/system";
#[cfg(target_os = "linux")]
const LINUX_BIN_DIR: &str = "/usr/lib/fail2commit-hardened";
#[cfg(target_os = "linux")]
const LINUX_RUN_DIR: &str = "/run/fail2commit-hardened";
#[cfg(target_os = "linux")]
const LINUX_DATA_DIR: &str = "/var/lib/fail2commit-hardened";
#[cfg(target_os = "linux")]
const LINUX_ACL_DIR: &str = "/var/lib/fail2commit-hardened-acl";
#[cfg(target_os = "linux")]
const SANDBOX_USER: &str = "f2c-sandbox";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallState {
    pub version: u32,
    pub installer_uid: u32,
    #[serde(default)]
    pub installer_sid: Option<String>,
    #[serde(default)]
    pub sandbox_sid: Option<String>,
    #[serde(default)]
    pub sandbox_uid: Option<u32>,
    pub executable: String,
    pub account: String,
}

pub fn status() -> serde_json::Value {
    match read_state() {
        Ok(Some(state)) => serde_json::json!({
            "installed": true,
            "installer_uid": state.installer_uid,
            "account": state.account,
            "executable": state.executable,
            "service_running": service_active(),
            "probe_available": false,
            "controls": { "peer_authentication": false, "launcher_watchdog": false, "platform_controls": false },
        }),
        Ok(None) => serde_json::json!({ "installed": false, "probe_available": false }),
        Err(e) => {
            serde_json::json!({ "installed": true, "probe_available": false, "error": e.message })
        }
    }
}

pub fn install() -> crate::Result<serde_json::Value> {
    #[cfg(target_os = "linux")]
    {
        linux::install()
    }
    #[cfg(windows)]
    {
        windows::install()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err(crate::Error::isolation_unavailable(
            "hardened mode is unsupported on this platform",
        ))
    }
}

pub fn uninstall() -> crate::Result<serde_json::Value> {
    #[cfg(target_os = "linux")]
    {
        linux::uninstall()
    }
    #[cfg(windows)]
    {
        windows::uninstall()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err(crate::Error::isolation_unavailable(
            "hardened mode is unsupported on this platform",
        ))
    }
}

#[allow(clippy::needless_return)]
fn read_state() -> crate::Result<Option<InstallState>> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let path = Path::new(LINUX_STATE);
        let md = match std::fs::symlink_metadata(path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !md.is_file() || md.uid() != 0 || md.mode() & 0o077 != 0 {
            return Err(crate::Error::integrity(
                "hardened install state owner or mode is unsafe",
            ));
        }
        let state: InstallState = serde_json::from_slice(&std::fs::read(path)?).map_err(|e| {
            crate::Error::integrity(format!("hardened install state is invalid: {e}"))
        })?;
        if state.version != 1
            || state.account != SANDBOX_USER
            || state.installer_uid == 0
            || state.sandbox_uid == Some(0)
            || state.installer_sid.is_some()
            || state.sandbox_sid.is_some()
        {
            return Err(crate::Error::integrity(
                "hardened install state has unsupported identity fields",
            ));
        }
        return Ok(Some(state));
    }
    #[cfg(windows)]
    {
        windows::read_state()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Ok(None)
    }
}

pub(crate) fn installed_state() -> crate::Result<InstallState> {
    read_state()?
        .ok_or_else(|| crate::Error::isolation_unavailable("hardened mode is not installed"))
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_acl_journal_dir() -> PathBuf {
    PathBuf::from(LINUX_ACL_DIR)
}

fn service_active() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "fail2commit-hardened.socket"])
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(windows)]
    {
        crate::sandbox::hardened::service::service_running()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

#[cfg(any(windows, test))]
fn recorded_executable_matches(recorded: &str, expected: &std::path::Path) -> bool {
    std::path::Path::new(recorded) == expected
}

#[cfg(any(target_os = "linux", test))]
fn cleanup_then_remove_state(
    state_path: &std::path::Path,
    cleanup: impl FnOnce() -> crate::Result<()>,
) -> crate::Result<()> {
    cleanup()?;
    match std::fs::remove_file(state_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(any(windows, test))]
fn owned_service_config(
    binary: &str,
    account: &str,
    service_type: u32,
    start_type: u32,
    expected_binary: &str,
) -> bool {
    binary == expected_binary
        && (account.eq_ignore_ascii_case("LocalSystem")
            || account.eq_ignore_ascii_case(r"NT AUTHORITY\LocalSystem"))
        && service_type == 0x10
        && start_type == 2
}

#[cfg(windows)]
fn recorded_sid_matches(recorded: Option<&str>, current: Option<&str>) -> crate::Result<bool> {
    let recorded = recorded.ok_or_else(|| {
        crate::Error::integrity("legacy hardened state cannot authorize account deletion")
    })?;
    let recorded = crate::ipc::winsec::sid_from_string(recorded)
        .ok_or_else(|| crate::Error::integrity("recorded hardened account SID is invalid"))?;
    let Some(current) = current else {
        return Ok(false);
    };
    let current = crate::ipc::winsec::sid_from_string(current)
        .ok_or_else(|| crate::Error::integrity("current hardened account SID is invalid"))?;
    Ok(recorded == current)
}

#[cfg(any(target_os = "linux", test))]
fn system_uid_range(login_defs: &str) -> crate::Result<(u32, u32)> {
    let mut min = None;
    let mut max = None;
    let mut uid_min: Option<u32> = None;
    for line in login_defs.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("SYS_UID_MIN") => min = fields.next().and_then(|v| v.parse().ok()),
            Some("SYS_UID_MAX") => max = fields.next().and_then(|v| v.parse().ok()),
            Some("UID_MIN") => uid_min = fields.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    // Explicit shadow ranges win. Debian 13 (shadow >= 4.17) ships them only
    // as commented defaults and useradd derives the system range from
    // [101, UID_MIN - 1]; mirror that documented default instead of refusing
    // every install on a stock login.defs.
    if min.is_none() && max.is_none() {
        if let Some(uid_min) = uid_min {
            if uid_min > 101 {
                return Ok((101, uid_min - 1));
            }
        }
    }
    match (min, max) {
        (Some(min), Some(max)) if min <= max => Ok((min, max)),
        _ => Err(crate::Error::integrity(
            "/etc/login.defs has no valid SYS_UID_MIN/SYS_UID_MAX range",
        )),
    }
}

#[cfg(any(target_os = "linux", test))]
fn system_uid_candidate(passwd: &str, min: u32, max: u32) -> crate::Result<u32> {
    if min > max {
        return Err(crate::Error::integrity("invalid system UID range"));
    }
    let used: std::collections::HashSet<u32> = passwd
        .lines()
        .filter_map(|line| line.split(':').nth(2)?.parse().ok())
        .collect();
    (min..=max)
        .find(|uid| !used.contains(uid))
        .ok_or_else(|| crate::Error::isolation_unavailable("no free system UID is available"))
}

#[cfg(any(target_os = "linux", test))]
fn persist_uid_before_create(
    state: &mut InstallState,
    uid: u32,
    persist: impl FnOnce(&InstallState) -> crate::Result<()>,
    create: impl FnOnce(u32) -> crate::Result<()>,
) -> crate::Result<()> {
    state.sandbox_uid = Some(uid);
    persist(state)?;
    create(uid)
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::recorded_sid_matches;
    use super::{
        cleanup_then_remove_state, owned_service_config, persist_uid_before_create,
        recorded_executable_matches, system_uid_candidate, system_uid_range, InstallState,
    };
    use std::path::Path;

    #[test]
    fn uninstall_path_must_match_the_managed_binary_exactly() {
        let managed = Path::new(r"C:\Program Files\fail2commit-hardened\fail2commit.exe");
        assert!(recorded_executable_matches(
            r"C:\Program Files\fail2commit-hardened\fail2commit.exe",
            managed
        ));
        assert!(!recorded_executable_matches(
            r"C:\Users\tester\fail2commit.exe",
            managed
        ));
        assert!(!recorded_executable_matches(
            r"C:\Program Files\fail2commit-hardened\..\other.exe",
            managed
        ));
    }

    #[test]
    fn v1_state_retains_account_sid_for_interrupted_cleanup_and_reads_legacy_records() {
        let legacy = br#"{"version":1,"installer_uid":0,"installer_sid":"S-1-5-21-7-8-9-1000","executable":"C:\\Program Files\\fail2commit-hardened\\fail2commit.exe","account":"f2c-sandbox"}"#;
        let old: InstallState = serde_json::from_slice(legacy).unwrap();
        assert_eq!(old.sandbox_sid, None);
        let current = InstallState {
            version: 1,
            installer_uid: 0,
            installer_sid: Some("S-1-5-21-7-8-9-1000".into()),
            sandbox_sid: Some("S-1-5-21-7-8-9-1001".into()),
            sandbox_uid: None,
            executable: r"C:\Program Files\fail2commit-hardened\fail2commit.exe".into(),
            account: "f2c-sandbox".into(),
        };
        let encoded = serde_json::to_vec(&current).unwrap();
        let decoded: InstallState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.sandbox_sid.as_deref(), Some("S-1-5-21-7-8-9-1001"));
    }

    #[test]
    fn service_ownership_requires_expected_binary_identity_and_start_mode() {
        let binary = r#""C:\Program Files\fail2commit-hardened\fail2commit.exe" sandbox serve"#;
        assert!(owned_service_config(binary, "LocalSystem", 0x10, 2, binary));
        assert!(owned_service_config(
            binary,
            r"NT AUTHORITY\LOCALSYSTEM",
            0x10,
            2,
            binary
        ));
        assert!(!owned_service_config(
            "other.exe",
            "LocalSystem",
            0x10,
            2,
            binary
        ));
        assert!(!owned_service_config(
            binary,
            ".\\f2c-sandbox",
            0x10,
            2,
            binary
        ));
        assert!(!owned_service_config(
            binary,
            "LocalSystem",
            0x10,
            3,
            binary
        ));
    }

    #[test]
    fn uninstall_cleanup_failure_preserves_marker_for_retry() {
        let td = tempfile::tempdir().unwrap();
        let marker = td.path().join("install.json");
        std::fs::write(&marker, b"trusted state").unwrap();
        let failure = cleanup_then_remove_state(&marker, || {
            Err(crate::Error::internal("injected systemctl failure"))
        });
        assert!(failure.is_err());
        assert!(marker.is_file());
        cleanup_then_remove_state(&marker, || Ok(())).unwrap();
        assert!(!marker.exists());
    }

    #[cfg(windows)]
    #[test]
    fn recorded_account_sid_must_match_before_name_based_deletion() {
        assert!(
            recorded_sid_matches(Some("S-1-5-21-7-8-9-1001"), Some("S-1-5-21-7-8-9-1001")).unwrap()
        );
        assert!(
            !recorded_sid_matches(Some("S-1-5-21-7-8-9-1001"), Some("S-1-5-21-7-8-9-1002"))
                .unwrap()
        );
        assert!(!recorded_sid_matches(Some("S-1-5-21-7-8-9-1001"), None).unwrap());
        assert!(recorded_sid_matches(None, Some("S-1-5-21-7-8-9-1002")).is_err());
    }

    #[test]
    fn linux_uid_is_durable_before_account_creation_and_survives_failure() {
        let td = tempfile::tempdir().unwrap();
        let state_path = td.path().join("install.json");
        let mut state = InstallState {
            version: 1,
            installer_uid: 1000,
            installer_sid: None,
            sandbox_sid: None,
            sandbox_uid: None,
            executable: "/usr/lib/fail2commit-hardened/fail2commit".into(),
            account: "f2c-sandbox".into(),
        };
        let result = persist_uid_before_create(
            &mut state,
            998,
            |state| {
                std::fs::write(&state_path, serde_json::to_vec(state).unwrap())?;
                Ok(())
            },
            |uid| {
                let durable: InstallState =
                    serde_json::from_slice(&std::fs::read(&state_path)?).unwrap();
                assert_eq!(durable.sandbox_uid, Some(uid));
                Err(crate::Error::internal("injected id failure after useradd"))
            },
        );
        assert!(result.is_err());
        let durable: InstallState =
            serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
        assert_eq!(durable.sandbox_uid, Some(998));
    }

    #[test]
    fn linux_system_uid_allocation_uses_only_free_configured_system_range() {
        assert_eq!(
            system_uid_range("# SYS_UID_MIN 1\nSYS_UID_MIN 100\nSYS_UID_MAX 999\n").unwrap(),
            (100, 999)
        );
        assert_eq!(
            system_uid_candidate(
                "root:x:0:0::/:/bin/sh\nuser:x:1000:1000::/:/bin/sh",
                100,
                101
            )
            .unwrap(),
            100
        );
        assert!(system_uid_candidate("a:x:100:1::/:/bin/sh", 100, 100).is_err());
        assert!(system_uid_range("SYS_UID_MIN 500\nSYS_UID_MAX 100\n").is_err());
    }

    /// Regression (linux-gates 2026-11-17): Debian 13 ships SYS_UID_MIN/MAX
    /// only as commented defaults; the installer must derive the same system
    /// range useradd uses ([101, UID_MIN - 1]) instead of refusing install.
    #[test]
    fn linux_system_uid_range_falls_back_to_shadow_default() {
        let stock_debian13 = concat!(
            "UID_MIN\t\t\t 1000\n",
            "UID_MAX\t\t\t60000\n",
            "#SYS_UID_MIN\t\t  101\n",
            "#SYS_UID_MAX\t\t  999\n",
            "SUB_UID_MIN\t\t   100000\n",
        );
        assert_eq!(system_uid_range(stock_debian13).unwrap(), (101, 999));
        // Explicit ranges still win over the derived default.
        assert_eq!(
            system_uid_range("UID_MIN 1000\nSYS_UID_MIN 200\nSYS_UID_MAX 400\n").unwrap(),
            (200, 400)
        );
        // A single explicit bound stays strict (no silent half-default).
        assert!(system_uid_range("UID_MIN 1000\nSYS_UID_MIN 200\n").is_err());
        // No usable UID_MIN and no explicit range still fails closed.
        assert!(system_uid_range("# nothing here\n").is_err());
        assert!(system_uid_range("UID_MIN 100\n").is_err());
        assert!(system_uid_range("UID_MIN 101\n").is_err());
    }

    #[test]
    fn linux_service_unit_keeps_system_hardening_and_opens_only_required_job_roots() {
        let unit = include_str!("../../../../../packaging/linux/fail2commit-hardened.service");
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("ProtectHome=read-only"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains(
            "ReadWritePaths=/home /run/fail2commit-hardened /var/lib/fail2commit-hardened /var/lib/fail2commit-hardened-acl"
        ));
        let writable_roots = unit
            .lines()
            .find_map(|line| line.strip_prefix("ReadWritePaths="))
            .unwrap()
            .split_whitespace();
        assert!(!writable_roots.into_iter().any(|path| path == "/"));
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::process::{Command, Output};

    fn run(program: &str, args: &[&str]) -> crate::Result<Output> {
        let out = Command::new(program).args(args).output()?;
        if !out.status.success() {
            return Err(crate::Error::internal(format!(
                "{} {} failed ({}): {}",
                program,
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out)
    }

    #[allow(unsafe_code)]
    fn require_root() -> crate::Result<()> {
        // SAFETY: geteuid has no preconditions and returns the effective uid.
        if unsafe { libc::geteuid() } == 0 {
            Ok(())
        } else {
            Err(crate::Error::rejected(
                "hardened install/uninstall requires root",
            ))
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn install() -> crate::Result<serde_json::Value> {
        require_root()?;
        if read_state()?.is_some() {
            return Ok(status());
        }
        run("systemctl", &["--version"])?;
        if run("getent", &["passwd", SANDBOX_USER]).is_ok() {
            return Err(crate::Error::rejected(
                "f2c-sandbox already exists without a trusted hardened install record",
            ));
        }
        let installer_uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|uid| *uid != 0)
            .unwrap_or_else(|| unsafe { libc::getuid() });
        if installer_uid == 0 {
            return Err(crate::Error::rejected(
                "run the installer through sudo from the installing user's account",
            ));
        }
        let src = std::env::current_exe()?.canonicalize()?;
        let bin_dir = Path::new(LINUX_BIN_DIR);
        let installed_exe = bin_dir.join("fail2commit");
        let relay_src = src
            .parent()
            .ok_or_else(|| crate::Error::integrity("CLI executable has no parent directory"))?
            .join("f2c-sandbox-relay");
        let relay_exe = bin_dir.join("f2c-sandbox-relay");
        let relay_meta = std::fs::symlink_metadata(&relay_src).map_err(|error| {
            crate::Error::isolation_unavailable(format!(
                "hardened Linux install requires the packaged f2c-sandbox-relay beside the CLI: {error}"
            ))
        })?;
        if !relay_meta.is_file()
            || relay_meta.file_type().is_symlink()
            || relay_meta.uid() != 0
            || relay_meta.mode() & 0o022 != 0
            || relay_meta.mode() & 0o111 == 0
        {
            return Err(crate::Error::integrity(
                "hardened Linux relay is not a trusted executable",
            ));
        }
        let state_path = Path::new(LINUX_STATE);
        let state_tmp = state_path.with_extension("json.new");
        let socket_unit = Path::new(LINUX_UNIT_DIR).join("fail2commit-hardened.socket");
        let service_unit = Path::new(LINUX_UNIT_DIR).join("fail2commit-hardened.service");
        for path in [
            state_path,
            state_tmp.as_path(),
            bin_dir,
            socket_unit.as_path(),
            service_unit.as_path(),
            Path::new(LINUX_DATA_DIR),
            Path::new(LINUX_ACL_DIR),
            Path::new(LINUX_RUN_DIR),
        ] {
            match std::fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(crate::Error::rejected(format!(
                        "hardened install target already exists: {}",
                        path.display()
                    )))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut state = InstallState {
            version: 1,
            installer_uid,
            installer_sid: None,
            sandbox_sid: None,
            sandbox_uid: None,
            executable: installed_exe.to_string_lossy().into_owned(),
            account: SANDBOX_USER.into(),
        };
        let uid_range = system_uid_range(&std::fs::read_to_string("/etc/login.defs")?)?;
        let passwd = run("getent", &["passwd"])?;
        let planned_uid = system_uid_candidate(
            &String::from_utf8_lossy(&passwd.stdout),
            uid_range.0,
            uid_range.1,
        )?;
        let result = (|| {
            // Publish ownership before creating any install artifacts so the
            // common idempotent uninstall path can roll them back on failure.
            write_state_at(state_path, &state)?;
            std::fs::create_dir_all(bin_dir)?;
            let tmp = bin_dir.join("fail2commit.new");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            std::io::copy(&mut std::fs::File::open(&src)?, &mut file)?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
            file.sync_all()?;
            std::fs::rename(&tmp, &installed_exe)?;
            let relay_tmp = bin_dir.join("f2c-sandbox-relay.new");
            let mut relay_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&relay_tmp)?;
            std::io::copy(&mut std::fs::File::open(&relay_src)?, &mut relay_file)?;
            std::fs::set_permissions(&relay_tmp, std::fs::Permissions::from_mode(0o755))?;
            relay_file.sync_all()?;
            std::fs::rename(&relay_tmp, &relay_exe)?;
            persist_uid_before_create(
                &mut state,
                planned_uid,
                |state| write_state_at(Path::new(LINUX_STATE), state),
                |uid| {
                    let uid = uid.to_string();
                    run(
                        "useradd",
                        &[
                            "--system",
                            "--uid",
                            &uid,
                            "--no-create-home",
                            "--shell",
                            "/usr/sbin/nologin",
                            SANDBOX_USER,
                        ],
                    )?;
                    let actual = run("id", &["-u", SANDBOX_USER])?;
                    if String::from_utf8_lossy(&actual.stdout).trim() != uid {
                        return Err(crate::Error::integrity(
                            "created sandbox account uid differs from the durably recorded uid",
                        ));
                    }
                    Ok(())
                },
            )?;
            let account_uid = planned_uid.to_string();
            std::fs::create_dir_all(LINUX_DATA_DIR)?;
            run("chown", &[&account_uid, LINUX_DATA_DIR])?;
            std::fs::set_permissions(LINUX_DATA_DIR, std::fs::Permissions::from_mode(0o700))?;
            std::fs::create_dir(LINUX_ACL_DIR)?;
            std::fs::set_permissions(LINUX_ACL_DIR, std::fs::Permissions::from_mode(0o700))?;
            std::fs::create_dir_all(LINUX_RUN_DIR)?;
            std::fs::set_permissions(LINUX_RUN_DIR, std::fs::Permissions::from_mode(0o755))?;
            let socket = include_str!("../../../../../packaging/linux/fail2commit-hardened.socket")
                .replace("@INSTALLER_UID@", &installer_uid.to_string());
            let service =
                include_str!("../../../../../packaging/linux/fail2commit-hardened.service")
                    .replace("@EXECUTABLE@", &installed_exe.to_string_lossy());
            std::fs::write(
                Path::new(LINUX_UNIT_DIR).join("fail2commit-hardened.socket"),
                socket,
            )?;
            std::fs::write(
                Path::new(LINUX_UNIT_DIR).join("fail2commit-hardened.service"),
                service,
            )?;
            run("systemctl", &["daemon-reload"])?;
            run(
                "systemctl",
                &["enable", "--now", "fail2commit-hardened.socket"],
            )?;
            Ok::<(), crate::Error>(())
        })();
        if let Err(e) = result {
            return match uninstall() {
                Ok(_) => Err(e),
                Err(cleanup) => Err(crate::Error::internal(format!(
                    "install failed: {}; rollback incomplete and trusted state retained for retry: {}",
                    e.message, cleanup.message
                ))),
            };
        }
        Ok(status())
    }

    fn write_state_at(path: &Path, state: &InstallState) -> crate::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("json.new");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(
            &serde_json::to_vec(state).map_err(|e| crate::Error::internal(e.to_string()))?,
        )?;
        f.sync_all()?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    pub(super) fn uninstall() -> crate::Result<serde_json::Value> {
        require_root()?;
        let Some(state) = read_state()? else {
            return Ok(serde_json::json!({"installed": false, "removed": true}));
        };
        if state.executable
            != Path::new(LINUX_BIN_DIR)
                .join("fail2commit")
                .to_string_lossy()
                .as_ref()
        {
            return Err(crate::Error::integrity(
                "recorded executable is outside hardened install directory",
            ));
        }
        cleanup_then_remove_state(Path::new(LINUX_STATE), || {
            let units = [
                "fail2commit-hardened.socket",
                "fail2commit-hardened.service",
            ];
            let expected_socket =
                include_str!("../../../../../packaging/linux/fail2commit-hardened.socket")
                    .replace("@INSTALLER_UID@", &state.installer_uid.to_string());
            let expected_service =
                include_str!("../../../../../packaging/linux/fail2commit-hardened.service")
                    .replace("@EXECUTABLE@", &state.executable);
            let unit_paths = [
                Path::new(LINUX_UNIT_DIR).join(units[0]),
                Path::new(LINUX_UNIT_DIR).join(units[1]),
            ];
            verify_unit_file(&unit_paths[0], &expected_socket)?;
            verify_unit_file(&unit_paths[1], &expected_service)?;
            run("systemctl", &["daemon-reload"])?;
            for (unit, unit_path) in units.into_iter().zip(&unit_paths) {
                let loaded = run(
                    "systemctl",
                    &["show", "--property=LoadState", "--value", unit],
                )?;
                match String::from_utf8_lossy(&loaded.stdout).trim() {
                    "loaded" => {
                        let fragment = run(
                            "systemctl",
                            &["show", "--property=FragmentPath", "--value", unit],
                        )?;
                        if Path::new(String::from_utf8_lossy(&fragment.stdout).trim()) != unit_path
                        {
                            return Err(crate::Error::integrity(format!(
                                "systemd unit {unit} is not loaded from its managed path"
                            )));
                        }
                        run("systemctl", &["disable", "--now", unit])?;
                    }
                    "not-found" => {}
                    other => {
                        return Err(crate::Error::integrity(format!(
                            "unexpected systemd LoadState for {unit}: {other}"
                        )))
                    }
                }
            }
            for path in &unit_paths {
                remove_unit_file(path)?;
            }
            run("systemctl", &["daemon-reload"])?;
            super::super::linux_acl::recover_if_present(Path::new(LINUX_ACL_DIR))?;

            let account = Command::new("getent")
                .args(["passwd", SANDBOX_USER])
                .output()?;
            if account.status.success() {
                let line = String::from_utf8_lossy(&account.stdout);
                let uid = line
                    .split(':')
                    .nth(2)
                    .and_then(|s| s.parse::<u32>().ok())
                    .ok_or_else(|| {
                        crate::Error::integrity("cannot parse sandbox account uid during uninstall")
                    })?;
                if state.sandbox_uid != Some(uid) {
                    return Err(crate::Error::integrity(
                        "sandbox account does not match the uid recorded by this installation",
                    ));
                }
                run("userdel", &[SANDBOX_USER])?;
            } else if account.status.code() != Some(2) {
                return Err(crate::Error::internal(format!(
                    "getent failed while checking sandbox account: {}",
                    account.status
                )));
            }
            remove_owned_dir(Path::new(LINUX_DATA_DIR), state.sandbox_uid)?;
            remove_owned_dir(Path::new(LINUX_ACL_DIR), Some(0))?;
            remove_owned_dir(Path::new(LINUX_RUN_DIR), Some(0))?;
            remove_owned_dir(Path::new(LINUX_BIN_DIR), Some(0))?;
            remove_state_temp()?;
            Ok(())
        })?;
        Ok(serde_json::json!({"installed": false, "removed": true, "executable": state.executable}))
    }

    fn remove_unit_file(path: &Path) -> crate::Result<()> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            Ok(md) if md.is_file() && !md.file_type().is_symlink() && md.uid() == 0 => {
                std::fs::remove_file(path)?;
                Ok(())
            }
            Ok(_) => Err(crate::Error::integrity(format!(
                "refusing to remove untrusted hardened unit path {}",
                path.display()
            ))),
        }
    }

    fn verify_unit_file(path: &Path, expected: &str) -> crate::Result<()> {
        use std::os::unix::fs::MetadataExt;
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            Ok(md) if md.is_file() && !md.file_type().is_symlink() && md.uid() == 0 => {
                let actual = std::fs::read_to_string(path)?;
                if actual == expected {
                    Ok(())
                } else {
                    Err(crate::Error::integrity(format!(
                        "managed systemd unit contents changed: {}",
                        path.display()
                    )))
                }
            }
            Ok(_) => Err(crate::Error::integrity(format!(
                "managed systemd unit path is untrusted: {}",
                path.display()
            ))),
        }
    }

    fn remove_owned_dir(path: &Path, owner: Option<u32>) -> crate::Result<()> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            Ok(md)
                if md.is_dir()
                    && !md.file_type().is_symlink()
                    && owner.is_some_and(|uid| md.uid() == uid || md.uid() == 0) =>
            {
                std::fs::remove_dir_all(path)?;
                Ok(())
            }
            Ok(_) => Err(crate::Error::integrity(format!(
                "refusing to remove untrusted hardened directory {}",
                path.display()
            ))),
        }
    }

    fn remove_state_temp() -> crate::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let path = Path::new(LINUX_STATE).with_extension("json.new");
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            Ok(md)
                if md.is_file()
                    && !md.file_type().is_symlink()
                    && md.uid() == 0
                    && md.mode() & 0o077 == 0 =>
            {
                std::fs::remove_file(path)?;
                Ok(())
            }
            Ok(_) => Err(crate::Error::integrity(
                "refusing to remove an untrusted temporary hardened state file",
            )),
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use super::*;
    use std::{ffi::c_void, os::windows::ffi::OsStrExt};
    const SERVICE_NAME: &[u16] = &[
        102, 97, 105, 108, 50, 99, 111, 109, 109, 105, 116, 45, 104, 97, 114, 100, 101, 110, 101,
        100, 0,
    ];
    #[repr(C)]
    struct UserInfo1 {
        name: *mut u16,
        password: *mut u16,
        password_age: u32,
        privilege: u32,
        home: *mut u16,
        comment: *mut u16,
        flags: u32,
        script: *mut u16,
    }
    #[repr(C)]
    struct ServiceStatus {
        kind: u32,
        state: u32,
        accepted: u32,
        win32: u32,
        specific: u32,
        checkpoint: u32,
        hint: u32,
    }
    #[repr(C)]
    struct ServiceConfig {
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: *const u16,
        load_order_group: *const u16,
        tag_id: u32,
        dependencies: *const u16,
        service_start_name: *const u16,
        display_name: *const u16,
    }
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root: *mut c_void,
        name: *mut UnicodeString,
        attributes: u32,
        security: *mut c_void,
        qos: *mut c_void,
    }
    #[link(name = "netapi32")]
    unsafe extern "system" {
        fn NetUserAdd(server: *const u16, level: u32, buf: *const u8, parm_err: *mut u32) -> u32;
        fn NetUserDel(server: *const u16, name: *const u16) -> u32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> *mut c_void;
        fn OpenServiceW(m: *mut c_void, n: *const u16, a: u32) -> *mut c_void;
        fn CreateServiceW(
            m: *mut c_void,
            n: *const u16,
            d: *const u16,
            a: u32,
            t: u32,
            start: u32,
            err: u32,
            b: *const u16,
            g: *const u16,
            tag: *mut u32,
            deps: *const u16,
            account: *const u16,
            password: *const u16,
        ) -> *mut c_void;
        fn StartServiceW(s: *mut c_void, n: u32, args: *const *const u16) -> i32;
        fn ControlService(s: *mut c_void, c: u32, status: *mut ServiceStatus) -> i32;
        fn QueryServiceStatus(s: *mut c_void, status: *mut ServiceStatus) -> i32;
        fn QueryServiceConfigW(
            s: *mut c_void,
            config: *mut c_void,
            size: u32,
            needed: *mut u32,
        ) -> i32;
        fn DeleteService(s: *mut c_void) -> i32;
        fn CloseServiceHandle(s: *mut c_void) -> i32;
    }
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn IsUserAnAdmin() -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn LookupAccountNameW(
            system: *const u16,
            name: *const u16,
            sid: *mut c_void,
            sid_len: *mut u32,
            domain: *mut u16,
            domain_len: *mut u32,
            use_type: *mut u32,
        ) -> i32;
        fn LsaOpenPolicy(
            system: *mut UnicodeString,
            attributes: *mut ObjectAttributes,
            access: u32,
            handle: *mut *mut c_void,
        ) -> i32;
        fn LsaAddAccountRights(
            policy: *mut c_void,
            sid: *mut c_void,
            rights: *mut UnicodeString,
            count: u32,
        ) -> i32;
        fn LsaRemoveAccountRights(
            policy: *mut c_void,
            sid: *mut c_void,
            all_rights: u8,
            rights: *mut UnicodeString,
            count: u32,
        ) -> i32;
        fn LsaClose(policy: *mut c_void) -> i32;
        fn LsaNtStatusToWinError(status: i32) -> u32;
    }
    fn w(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain([0]).collect()
    }
    fn lookup_account_sid() -> crate::Result<Option<(Vec<u64>, String)>> {
        let account = w(std::ffi::OsStr::new("f2c-sandbox"));
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut use_type = 0u32;
        // SAFETY: NULL SID/domain buffers request their required sizes.
        unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                account.as_ptr(),
                std::ptr::null_mut(),
                &mut sid_len,
                std::ptr::null_mut(),
                &mut domain_len,
                &mut use_type,
            );
        }
        let lookup_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if sid_len == 0 && lookup_error == 1332 {
            return Ok(None);
        }
        if sid_len == 0 || sid_len > 4096 || domain_len > 32768 {
            return Err(crate::Error::integrity(
                "cannot resolve hardened account SID",
            ));
        }
        let mut sid = vec![0u64; (sid_len as usize).div_ceil(8)];
        let mut domain = vec![0u16; domain_len as usize];
        // SAFETY: buffers have the lengths reported by LookupAccountNameW.
        if unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                account.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut use_type,
            )
        } == 0
        {
            return Err(crate::Error::internal(
                "cannot resolve hardened account SID",
            ));
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(sid.as_ptr().cast::<u8>(), sid_len as usize) };
        Ok(Some((sid, crate::ipc::winsec::sid_string(bytes))))
    }

    fn account_sid() -> crate::Result<(Vec<u64>, String)> {
        lookup_account_sid()?
            .ok_or_else(|| crate::Error::integrity("hardened sandbox account does not exist"))
    }

    fn sid_words(text: &str) -> crate::Result<Vec<u64>> {
        let bytes = crate::ipc::winsec::sid_from_string(text)
            .ok_or_else(|| crate::Error::integrity("recorded hardened account SID is invalid"))?;
        let mut out = vec![0u64; bytes.len().div_ceil(8)];
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.as_mut_ptr().cast(), bytes.len());
        }
        Ok(out)
    }

    fn set_account_logon_right(add: bool, right_name: &str, sid: &mut [u64]) -> crate::Result<()> {
        let mut attrs = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root: std::ptr::null_mut(),
            name: std::ptr::null_mut(),
            attributes: 0,
            security: std::ptr::null_mut(),
            qos: std::ptr::null_mut(),
        };
        let mut policy = std::ptr::null_mut();
        // POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES.
        let rc = unsafe {
            LsaOpenPolicy(
                std::ptr::null_mut(),
                &mut attrs,
                0x00000010 | 0x00000800,
                &mut policy,
            )
        };
        if rc != 0 {
            return Err(crate::Error::internal(format!(
                "LsaOpenPolicy failed with code {}",
                unsafe { LsaNtStatusToWinError(rc) }
            )));
        }
        let mut right = w(std::ffi::OsStr::new(right_name));
        let mut us = UnicodeString {
            length: ((right.len() - 1) * 2) as u16,
            maximum_length: (right.len() * 2) as u16,
            buffer: right.as_mut_ptr(),
        };
        let rc = if add {
            unsafe { LsaAddAccountRights(policy, sid.as_mut_ptr().cast(), &mut us, 1) }
        } else {
            unsafe { LsaRemoveAccountRights(policy, sid.as_mut_ptr().cast(), 0, &mut us, 1) }
        };
        unsafe {
            LsaClose(policy);
        }
        if rc != 0 {
            // LSA maps an already-absent right/account to these Win32 codes;
            // removal is intentionally idempotent.
            let winerr = unsafe { LsaNtStatusToWinError(rc) };
            if !add && (winerr == 2 || winerr == 1313) {
                return Ok(());
            }
            return Err(crate::Error::internal(format!(
                "LSA account logon right update failed with code {}",
                winerr
            )));
        }
        Ok(())
    }

    fn set_interactive_logon_denied(deny: bool, sid: &mut [u64]) -> crate::Result<()> {
        set_account_logon_right(deny, "SeDenyInteractiveLogonRight", sid)
    }

    fn set_batch_logon_allowed(allowed: bool, sid: &mut [u64]) -> crate::Result<()> {
        set_account_logon_right(allowed, "SeBatchLogonRight", sid)
    }
    fn scm() -> crate::Result<*mut c_void> {
        let h =
            unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), 0x0001 | 0x0002 | 0x0004) };
        if h.is_null() {
            Err(crate::Error::rejected(format!(
                "cannot open Windows Service Control Manager: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(h)
        }
    }
    fn service_config_matches(service: *mut c_void, expected_binary: &str) -> bool {
        let mut needed = 0u32;
        unsafe { QueryServiceConfigW(service, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 || needed > 64 * 1024 {
            return false;
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        if unsafe {
            QueryServiceConfigW(
                service,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                &mut needed,
            )
        } == 0
        {
            return false;
        }
        let config = unsafe { &*buffer.as_ptr().cast::<ServiceConfig>() };
        unsafe fn string(p: *const u16) -> String {
            if p.is_null() {
                return String::new();
            }
            let mut n = 0usize;
            while unsafe { *p.add(n) } != 0 {
                n += 1;
            }
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
        }
        let binary = unsafe { string(config.binary_path) };
        let account = unsafe { string(config.service_start_name) };
        owned_service_config(
            &binary,
            &account,
            config.service_type,
            config.start_type,
            expected_binary,
        )
    }

    pub(super) fn install() -> crate::Result<serde_json::Value> {
        // SAFETY: IsUserAnAdmin takes no arguments and checks the current token.
        if unsafe { IsUserAnAdmin() } == 0 {
            return Err(crate::Error::rejected(
                "hardened install requires an elevated administrator token",
            ));
        }
        if read_state()?.is_some() {
            return Ok(status());
        }
        let manager = scm()?;
        let state_path = crate::sandbox::hardened::machine_state_path()?;
        let data_dir = state_path.parent().unwrap().to_path_buf();
        let bin_dir = std::env::var_os("ProgramFiles")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| crate::Error::isolation_unavailable("ProgramFiles is unavailable"))?
            .join("fail2commit-hardened");
        if data_dir.exists() || bin_dir.exists() {
            unsafe { CloseServiceHandle(manager) };
            return Err(crate::Error::rejected(
                "hardened install target already exists without trusted state",
            ));
        }
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|e| crate::Error::internal(format!("credential generation failed: {e}")))?;
        let password = zeroize::Zeroizing::new(hex::encode(random));
        zeroize::Zeroize::zeroize(&mut random);
        let mut username = w(std::ffi::OsStr::new("f2c-sandbox"));
        let mut pass = w(std::ffi::OsStr::new(&*password));
        let mut comment = w(std::ffi::OsStr::new("Restricted fail2commit identity"));
        let ui = UserInfo1 {
            name: username.as_mut_ptr(),
            password: pass.as_mut_ptr(),
            password_age: 0,
            privilege: 1,
            home: std::ptr::null_mut(),
            comment: comment.as_mut_ptr(),
            flags: 0x0001 | 0x10000 | 0x40,
            script: std::ptr::null_mut(),
        };
        // SAFETY: all USER_INFO_1 backing buffers remain live through NetUserAdd.
        let rc = unsafe {
            NetUserAdd(
                std::ptr::null(),
                1,
                (&ui as *const UserInfo1).cast(),
                std::ptr::null_mut(),
            )
        };
        zeroize::Zeroize::zeroize(&mut pass);
        zeroize::Zeroize::zeroize(&mut username);
        zeroize::Zeroize::zeroize(&mut comment);
        if rc != 0 {
            unsafe { CloseServiceHandle(manager) };
            return Err(crate::Error::internal(format!(
                "NetUserAdd failed with code {rc}"
            )));
        }
        let (mut sandbox_sid, sandbox_sid_text) = match account_sid() {
            Ok(value) => value,
            Err(e) => {
                let user = w(std::ffi::OsStr::new("f2c-sandbox"));
                unsafe {
                    NetUserDel(std::ptr::null(), user.as_ptr());
                    CloseServiceHandle(manager);
                }
                return Err(e);
            }
        };
        let result = (|| {
            std::fs::create_dir_all(&bin_dir)?;
            let installed = bin_dir.join("fail2commit.exe");
            std::fs::copy(std::env::current_exe()?, &installed)?;
            std::fs::create_dir(&data_dir)?;
            let systemroot = std::env::var_os("SystemRoot")
                .map(std::path::PathBuf::from)
                .ok_or_else(|| crate::Error::isolation_unavailable("SystemRoot is unavailable"))?;
            let acl = std::process::Command::new(systemroot.join("System32\\icacls.exe"))
                .arg(&data_dir)
                .args([
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                ])
                .output()?;
            if !acl.status.success() {
                return Err(crate::Error::internal(
                    "failed to set SYSTEM/Administrators state directory ACL",
                ));
            }
            std::fs::write(data_dir.join("sandbox.secret"), password.as_bytes())?;
            let state = InstallState {
                version: 1,
                installer_uid: 0,
                installer_sid: Some(crate::ipc::winsec::sid_string(
                    &crate::ipc::winsec::current_user_sid()?,
                )),
                sandbox_sid: Some(sandbox_sid_text.clone()),
                sandbox_uid: None,
                executable: installed.to_string_lossy().into_owned(),
                account: "f2c-sandbox".into(),
            };
            std::fs::write(
                &state_path,
                serde_json::to_vec(&state).map_err(|e| crate::Error::internal(e.to_string()))?,
            )?;
            // Persist the account SID before changing the local security policy:
            // an interrupted install can then remove precisely this right later.
            set_interactive_logon_denied(true, &mut sandbox_sid)?;
            set_batch_logon_allowed(true, &mut sandbox_sid)?;
            let binary = w(std::ffi::OsStr::new(&format!(
                "\"{}\" sandbox serve",
                installed.display()
            )));
            let display = w(std::ffi::OsStr::new("Fail2Commit Hardened Service"));
            let local = w(std::ffi::OsStr::new("LocalSystem"));
            // SAFETY: all arguments are valid NUL-terminated strings; SCM handle is live.
            let svc = unsafe {
                CreateServiceW(
                    manager,
                    SERVICE_NAME.as_ptr(),
                    display.as_ptr(),
                    0xF01FF,
                    0x10,
                    2,
                    1,
                    binary.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    local.as_ptr(),
                    std::ptr::null(),
                )
            };
            if svc.is_null() {
                return Err(crate::Error::internal(format!(
                    "CreateServiceW failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if unsafe { StartServiceW(svc, 0, std::ptr::null()) } == 0 {
                let e = std::io::Error::last_os_error();
                unsafe { CloseServiceHandle(svc) };
                return Err(crate::Error::internal(format!("StartServiceW failed: {e}")));
            }
            unsafe { CloseServiceHandle(svc) };
            Ok::<(), crate::Error>(())
        })();
        unsafe { CloseServiceHandle(manager) };
        if let Err(e) = result {
            let cleanup = if state_path.exists() {
                uninstall().map(|_| ())
            } else {
                let right = set_interactive_logon_denied(false, &mut sandbox_sid);
                if let Err(clean_error) = right {
                    return Err(crate::Error::internal(format!(
                        "install failed: {}; account-right rollback failed: {}",
                        e.message, clean_error.message
                    )));
                }
                if let Err(clean_error) = set_batch_logon_allowed(false, &mut sandbox_sid) {
                    return Err(crate::Error::internal(format!(
                        "install failed: {}; batch-logon-right rollback failed: {}",
                        e.message, clean_error.message
                    )));
                }
                let user = w(std::ffi::OsStr::new("f2c-sandbox"));
                let user_rc = unsafe { NetUserDel(std::ptr::null(), user.as_ptr()) };
                if user_rc != 0 && user_rc != 2221 {
                    Err(crate::Error::internal(format!(
                        "install failed: {}; rollback NetUserDel failed with code {user_rc}",
                        e.message
                    )))
                } else {
                    match std::fs::remove_dir_all(&bin_dir) {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => {
                            return Err(crate::Error::internal(format!(
                                "install failed: {}; rollback payload removal failed: {err}",
                                e.message
                            )))
                        }
                    }
                    match std::fs::remove_dir_all(&data_dir) {
                        Ok(()) => Ok(()),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(err) => Err(crate::Error::internal(format!(
                            "install failed: {}; rollback data removal failed: {err}",
                            e.message
                        ))),
                    }
                }
            };
            return match cleanup {
                Ok(()) => Err(e),
                Err(clean_error) => Err(crate::Error::internal(format!(
                    "install failed: {}; rollback incomplete and retained trusted state for retry: {}",
                    e.message, clean_error.message
                ))),
            };
        }
        Ok(status())
    }
    pub(super) fn uninstall() -> crate::Result<serde_json::Value> {
        // SAFETY: IsUserAnAdmin takes no arguments and checks the current token.
        if unsafe { IsUserAnAdmin() } == 0 {
            return Err(crate::Error::rejected(
                "hardened uninstall requires an elevated administrator token",
            ));
        }
        ensure_no_active_launch()?;
        let Some(state) = read_state()? else {
            // A service-name collision without our protected install record is
            // not authority to touch SCM or the local account.
            return Ok(serde_json::json!({"installed":false,"removed":true}));
        };
        let recorded_sid = state.sandbox_sid.as_deref().ok_or_else(|| {
            crate::Error::integrity(
                "legacy hardened state cannot authorize deletion of the sandbox account",
            )
        })?;
        let mut sandbox_sid = sid_words(recorded_sid)?;
        let expected = std::env::var_os("ProgramFiles")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| crate::Error::isolation_unavailable("ProgramFiles is unavailable"))?
            .join("fail2commit-hardened")
            .join("fail2commit.exe");
        if !recorded_executable_matches(&state.executable, &expected) {
            return Err(crate::Error::integrity(
                "recorded executable is outside hardened install directory",
            ));
        }
        let manager = scm()?;
        let svc = unsafe {
            OpenServiceW(
                manager,
                SERVICE_NAME.as_ptr(),
                0x0001 | 0x0004 | 0x0020 | 0x00010000,
            )
        };
        if svc.is_null() {
            // ERROR_SERVICE_DOES_NOT_EXIST; a missing service is an expected
            // partial-install/removal state, other SCM failures are not.
            let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            unsafe { CloseServiceHandle(manager) };
            if code != 1060 {
                return Err(crate::Error::internal(format!(
                    "OpenServiceW failed during owned uninstall with code {code}"
                )));
            }
        } else {
            let expected_command = format!("\"{}\" sandbox serve", expected.display());
            if !service_config_matches(svc, &expected_command) {
                unsafe {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(manager);
                }
                return Err(crate::Error::integrity(
                    "SCM service configuration does not match the protected install record",
                ));
            }
            let mut s = ServiceStatus {
                kind: 0,
                state: 0,
                accepted: 0,
                win32: 0,
                specific: 0,
                checkpoint: 0,
                hint: 0,
            };
            if unsafe { QueryServiceStatus(svc, &mut s) } == 0 {
                let e = std::io::Error::last_os_error();
                unsafe {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(manager);
                }
                return Err(crate::Error::internal(format!(
                    "QueryServiceStatus failed: {e}"
                )));
            }
            if s.state == 4 && unsafe { ControlService(svc, 1, &mut s) } == 0 {
                let e = std::io::Error::last_os_error();
                unsafe {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(manager);
                }
                return Err(crate::Error::internal(format!(
                    "ControlService(STOP) failed: {e}"
                )));
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                if unsafe { QueryServiceStatus(svc, &mut s) } == 0 {
                    let e = std::io::Error::last_os_error();
                    unsafe {
                        CloseServiceHandle(svc);
                        CloseServiceHandle(manager);
                    }
                    return Err(crate::Error::internal(format!(
                        "QueryServiceStatus failed while stopping: {e}"
                    )));
                }
                if s.state == 1 {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    unsafe {
                        CloseServiceHandle(svc);
                        CloseServiceHandle(manager);
                    }
                    return Err(crate::Error::internal(
                        "timed out waiting for hardened service to stop",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if let Err(error) = ensure_no_active_launch() {
                unsafe {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(manager);
                }
                return Err(error);
            }
            if unsafe { DeleteService(svc) } == 0 {
                let e = std::io::Error::last_os_error();
                unsafe {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(manager);
                }
                return Err(crate::Error::internal(format!("DeleteService failed: {e}")));
            }
            unsafe {
                CloseServiceHandle(svc);
                CloseServiceHandle(manager);
            }
        }
        set_interactive_logon_denied(false, &mut sandbox_sid)?;
        set_batch_logon_allowed(false, &mut sandbox_sid)?;
        let current_sid = lookup_account_sid()?.map(|(_, sid)| sid);
        if recorded_sid_matches(Some(recorded_sid), current_sid.as_deref())? {
            let user = w(std::ffi::OsStr::new("f2c-sandbox"));
            let rc = unsafe { NetUserDel(std::ptr::null(), user.as_ptr()) };
            if rc != 0 && rc != 2221 {
                return Err(crate::Error::internal(format!(
                    "NetUserDel failed with code {rc}"
                )));
            }
        } else if current_sid.is_some() {
            return Err(crate::Error::integrity(
                "current f2c-sandbox account SID differs from the protected installation SID; refusing account deletion",
            ));
        }
        std::fs::remove_dir_all(expected.parent().unwrap())?;
        let p = crate::sandbox::hardened::machine_state_path()?;
        if p.exists() {
            std::fs::remove_file(&p)?;
        }
        if let Some(d) = p.parent() {
            if d.exists() {
                std::fs::remove_dir(d)?;
            }
        }
        Ok(serde_json::json!({"installed":false,"removed":true}))
    }

    fn ensure_no_active_launch() -> crate::Result<()> {
        let check = crate::sandbox::hardened::service::launch_recovery_pending();
        if !crate::sandbox::hardened::service::marker_blocks_cleanup(&check) {
            return Ok(());
        }
        match check {
            Ok(true) => Err(crate::Error::isolation_unavailable(
                "an unresolved active launch marker prevents uninstall; owned resources were retained",
            )),
            Ok(false) => unreachable!("marker cleanup decision is inconsistent"),
            Err(error) => Err(crate::Error::integrity(format!(
                "active launch marker is invalid or unreadable; uninstall retained owned resources: {}",
                error.message
            ))),
        }
    }
    pub(super) fn read_state() -> crate::Result<Option<InstallState>> {
        use std::os::windows::fs::MetadataExt;
        let path = crate::sandbox::hardened::machine_state_path()?;
        let md = match std::fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if !md.is_file() || md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(crate::Error::integrity(
                "hardened state is not a regular file",
            ));
        }
        let file = std::fs::File::open(&path)?;
        let aces = crate::ipc::winsec::dacl_entries(&file)?;
        let mut has_system = false;
        let mut has_admin = false;
        for (allow, sid, _mask) in aces {
            if allow && sid == "S-1-5-18" {
                has_system = true;
            } else if allow && sid == "S-1-5-32-544" {
                has_admin = true;
            } else if allow {
                return Err(crate::Error::integrity(
                    "hardened state grants access outside SYSTEM/Administrators",
                ));
            }
        }
        if !has_system || !has_admin {
            return Err(crate::Error::integrity("hardened state ACL is incomplete"));
        }
        let state: InstallState = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| crate::Error::integrity(format!("hardened state is invalid: {e}")))?;
        if state.version != 1
            || state.account != "f2c-sandbox"
            || state.sandbox_uid.is_some()
            || state
                .installer_sid
                .as_deref()
                .and_then(crate::ipc::winsec::sid_from_string)
                .is_none()
            || state
                .sandbox_sid
                .as_deref()
                .is_some_and(|sid| crate::ipc::winsec::sid_from_string(sid).is_none())
        {
            return Err(crate::Error::integrity(
                "hardened state identity fields are invalid",
            ));
        }
        Ok(Some(state))
    }
}
