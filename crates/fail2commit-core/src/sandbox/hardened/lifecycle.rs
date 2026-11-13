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
const SANDBOX_USER: &str = "f2c-sandbox";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallState {
    pub version: u32,
    pub installer_uid: u32,
    #[serde(default)]
    pub installer_sid: Option<String>,
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
        if state.version != 1 || state.account != SANDBOX_USER || state.installer_uid == 0 {
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
        std::process::Command::new("sc.exe")
            .args(["query", "fail2commit-hardened"])
            .output()
            .is_ok_and(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).contains("RUNNING")
            })
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
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
        let state = InstallState {
            version: 1,
            installer_uid,
            installer_sid: None,
            executable: installed_exe.to_string_lossy().into_owned(),
            account: SANDBOX_USER.into(),
        };
        write_state(&state)?;
        let result = (|| {
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
            run(
                "useradd",
                &[
                    "--system",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    SANDBOX_USER,
                ],
            )?;
            std::fs::create_dir_all(LINUX_DATA_DIR)?;
            let uid = run("id", &["-u", SANDBOX_USER])?;
            let account_uid = String::from_utf8_lossy(&uid.stdout).trim().to_string();
            run("chown", &[&account_uid, LINUX_DATA_DIR])?;
            std::fs::set_permissions(LINUX_DATA_DIR, std::fs::Permissions::from_mode(0o700))?;
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
            let _ = uninstall();
            return Err(e);
        }
        Ok(status())
    }

    fn write_state(state: &InstallState) -> crate::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = Path::new(LINUX_STATE);
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
        let _ = Command::new("systemctl")
            .args([
                "disable",
                "--now",
                "fail2commit-hardened.socket",
                "fail2commit-hardened.service",
            ])
            .status();
        for path in [
            PathBuf::from(LINUX_UNIT_DIR).join("fail2commit-hardened.socket"),
            PathBuf::from(LINUX_UNIT_DIR).join("fail2commit-hardened.service"),
        ] {
            let _ = std::fs::remove_file(path);
        }
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        let _ = Command::new("userdel").args([SANDBOX_USER]).status();
        let _ = std::fs::remove_dir_all(LINUX_DATA_DIR);
        let _ = std::fs::remove_dir_all(LINUX_RUN_DIR);
        let _ = std::fs::remove_dir_all(LINUX_BIN_DIR);
        std::fs::remove_file(LINUX_STATE)?;
        Ok(serde_json::json!({"installed": false, "removed": true, "executable": state.executable}))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    pub(super) fn install() -> crate::Result<serde_json::Value> {
        Err(crate::Error::isolation_unavailable(
            "Windows hardened lifecycle is not implemented",
        ))
    }
    pub(super) fn uninstall() -> crate::Result<serde_json::Value> {
        Err(crate::Error::isolation_unavailable(
            "Windows hardened lifecycle is not implemented",
        ))
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
            || state
                .installer_sid
                .as_deref()
                .and_then(crate::ipc::winsec::sid_from_string)
                .is_none()
        {
            return Err(crate::Error::integrity(
                "hardened state identity fields are invalid",
            ));
        }
        Ok(Some(state))
    }
}
