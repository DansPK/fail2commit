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
        crate::sandbox::hardened::service::service_running()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

fn recorded_executable_matches(recorded: &str, expected: &std::path::Path) -> bool {
    std::path::Path::new(recorded) == expected
}

#[cfg(test)]
mod tests {
    use super::recorded_executable_matches;
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
    fn set_interactive_logon_denied(deny: bool) -> crate::Result<()> {
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
        let mut right = w(std::ffi::OsStr::new("SeDenyInteractiveLogonRight"));
        let mut us = UnicodeString {
            length: ((right.len() - 1) * 2) as u16,
            maximum_length: (right.len() * 2) as u16,
            buffer: right.as_mut_ptr(),
        };
        let rc = if deny {
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
            if !deny && (winerr == 2 || winerr == 1313) {
                return Ok(());
            }
            return Err(crate::Error::internal(format!(
                "LSA account logon right update failed with code {}",
                winerr
            )));
        }
        Ok(())
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
        if let Err(e) = set_interactive_logon_denied(true) {
            let user = w(std::ffi::OsStr::new("f2c-sandbox"));
            unsafe {
                NetUserDel(std::ptr::null(), user.as_ptr());
                CloseServiceHandle(manager);
            }
            return Err(e);
        }
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
            let state = InstallState {
                version: 1,
                installer_uid: 0,
                installer_sid: Some(crate::ipc::winsec::sid_string(
                    &crate::ipc::winsec::current_user_sid()?,
                )),
                executable: installed.to_string_lossy().into_owned(),
                account: "f2c-sandbox".into(),
            };
            std::fs::write(
                &state_path,
                serde_json::to_vec(&state).map_err(|e| crate::Error::internal(e.to_string()))?,
            )?;
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
                unsafe {
                    DeleteService(svc);
                    CloseServiceHandle(svc)
                };
                return Err(crate::Error::internal(format!("StartServiceW failed: {e}")));
            }
            unsafe { CloseServiceHandle(svc) };
            Ok::<(), crate::Error>(())
        })();
        unsafe { CloseServiceHandle(manager) };
        if let Err(e) = result {
            let _ = std::fs::remove_dir_all(&bin_dir);
            let _ = std::fs::remove_dir_all(&data_dir);
            let user = w(std::ffi::OsStr::new("f2c-sandbox"));
            unsafe { NetUserDel(std::ptr::null(), user.as_ptr()) };
            return Err(e);
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
        let state = read_state()?;
        if let Ok(manager) = scm() {
            let svc = unsafe {
                OpenServiceW(manager, SERVICE_NAME.as_ptr(), 0x0004 | 0x0020 | 0x00010000)
            };
            if !svc.is_null() {
                let mut s = ServiceStatus {
                    kind: 0,
                    state: 0,
                    accepted: 0,
                    win32: 0,
                    specific: 0,
                    checkpoint: 0,
                    hint: 0,
                };
                unsafe {
                    if QueryServiceStatus(svc, &mut s) != 0 && s.state == 4 {
                        ControlService(svc, 1, &mut s);
                    }
                }
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
                loop {
                    if unsafe { QueryServiceStatus(svc, &mut s) } == 0 || s.state == 1 {
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
                }
            }
            unsafe {
                CloseServiceHandle(manager);
            }
        }
        if let Some(state) = state {
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
            set_interactive_logon_denied(false)?;
            let user = w(std::ffi::OsStr::new("f2c-sandbox"));
            let rc = unsafe { NetUserDel(std::ptr::null(), user.as_ptr()) };
            if rc != 0 && rc != 2221 {
                return Err(crate::Error::internal(format!(
                    "NetUserDel failed with code {rc}"
                )));
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
        }
        Ok(serde_json::json!({"installed":false,"removed":true}))
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
