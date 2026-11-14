//! Hardened-mode wire contract and backends (FR-027, SPEC-018).

pub mod lifecycle;
pub mod protocol;
pub mod service;
#[cfg(any(windows, test))]
pub(super) mod windows_proxy;
#[cfg(windows)]
mod windows_wfp;

use crate::isolation::{JobOutcome, JobSpec, ProbeReport, SandboxBackend};
use crate::settings::{BackendChoice, Settings};

/// Select an installed hardened backend in `auto` mode. An installed but
/// unverified backend is represented by a backend whose probe always fails;
/// it must never silently fall back to the platform sandbox.
pub(crate) fn selected(settings: &Settings) -> Option<Box<dyn SandboxBackend>> {
    if should_select_hardened(settings.sandbox.backend, installed()) {
        return Some(Box::new(HardenedBackend));
    }
    None
}

fn should_select_hardened(choice: BackendChoice, installed: bool) -> bool {
    choice == BackendChoice::Auto && installed
}

pub fn install() -> crate::Result<serde_json::Value> {
    lifecycle::install()
}
pub fn uninstall() -> crate::Result<serde_json::Value> {
    lifecycle::uninstall()
}
pub fn status() -> serde_json::Value {
    lifecycle::status()
}

pub fn serve() -> crate::Result<()> {
    #[cfg(target_os = "linux")]
    {
        service::serve_linux()
    }
    #[cfg(windows)]
    {
        service::serve_windows()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err(crate::Error::isolation_unavailable("unsupported platform"))
    }
}

/// Launcher entry point deliberately refuses until all per-job isolation
/// controls, grants, and watchdog handling have been wired and probed.
pub fn launch(jobfile: &std::path::Path, watchdog: Option<u64>) -> crate::Result<()> {
    launch_with_control(jobfile, watchdog, None, None, None)
}

pub fn launch_with_control(
    jobfile: &std::path::Path,
    watchdog: Option<u64>,
    prepare_request: Option<u64>,
    prepare_ack: Option<u64>,
    launch_id: Option<&str>,
) -> crate::Result<()> {
    launch_with_control_mode(
        jobfile,
        watchdog,
        prepare_request,
        prepare_ack,
        launch_id,
        false,
    )
}

#[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
pub fn launch_with_test_diagnostic_control(
    jobfile: &std::path::Path,
    watchdog: Option<u64>,
    prepare_request: Option<u64>,
    prepare_ack: Option<u64>,
    launch_id: Option<&str>,
) -> crate::Result<()> {
    launch_with_control_mode(
        jobfile,
        watchdog,
        prepare_request,
        prepare_ack,
        launch_id,
        true,
    )
}

fn launch_with_control_mode(
    jobfile: &std::path::Path,
    watchdog: Option<u64>,
    prepare_request: Option<u64>,
    prepare_ack: Option<u64>,
    launch_id: Option<&str>,
    test_diagnostic: bool,
) -> crate::Result<()> {
    #[cfg(windows)]
    {
        service::launch_hidden(
            jobfile,
            watchdog,
            prepare_request,
            prepare_ack,
            launch_id,
            test_diagnostic,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (
            jobfile,
            watchdog,
            prepare_request,
            prepare_ack,
            launch_id,
            test_diagnostic,
        );
        Err(crate::Error::isolation_unavailable(
            "hardened launcher controls are not verified; refusing to execute job",
        ))
    }
}

/// Whether the machine-level install marker exists. A malformed marker still
/// counts as installed so a damaged install fails closed rather than falling
/// back to a weaker backend.
pub fn installed() -> bool {
    #[cfg(windows)]
    {
        return match machine_state_path() {
            Ok(p) => match std::fs::symlink_metadata(p) {
                Ok(_) => true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(_) => true,
            },
            Err(_) => true,
        };
    }
    #[cfg(target_os = "linux")]
    {
        let remnants = [
            std::path::PathBuf::from("/etc/systemd/system/fail2commit-hardened.socket"),
            std::path::PathBuf::from("/etc/systemd/system/fail2commit-hardened.service"),
            std::path::PathBuf::from(
                "/etc/systemd/system/sockets.target.wants/fail2commit-hardened.socket",
            ),
            std::path::PathBuf::from("/etc/fail2commit-hardened.json.new"),
            std::path::PathBuf::from("/usr/lib/fail2commit-hardened"),
            std::path::PathBuf::from("/run/fail2commit-hardened"),
            std::path::PathBuf::from("/var/lib/fail2commit-hardened"),
        ];
        let account_present = match std::fs::read_to_string("/etc/passwd") {
            Ok(passwd) => passwd
                .lines()
                .any(|line| line.split(':').next() == Some("f2c-sandbox")),
            Err(_) => true,
        };
        marker_or_remnants(&machine_state_path(), &remnants, account_present)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

#[cfg(any(target_os = "linux", test))]
fn marker_or_remnants(
    marker: &std::path::Path,
    remnants: &[std::path::PathBuf],
    account_present: bool,
) -> bool {
    match std::fs::symlink_metadata(marker) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            account_present
                || remnants.iter().any(|p| match std::fs::symlink_metadata(p) {
                    Ok(_) => true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(_) => true,
                })
        }
        Err(_) => true,
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn machine_state_path() -> crate::Result<std::path::PathBuf> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStringExt;
    #[repr(C)]
    struct Guid {
        d1: u32,
        d2: u16,
        d3: u16,
        d4: [u8; 8],
    }
    const PROGRAM_DATA: Guid = Guid {
        d1: 0x62ab5d82,
        d2: 0xfdc1,
        d3: 0x4dc3,
        d4: [0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97],
    };
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHGetKnownFolderPath(
            id: *const Guid,
            flags: u32,
            token: *mut c_void,
            path: *mut *mut u16,
        ) -> i32;
    }
    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoTaskMemFree(ptr: *mut c_void);
    }
    let mut raw = std::ptr::null_mut();
    // SAFETY: valid known-folder GUID and writable out pointer; NULL selects
    // the current process token and flags=0 requests the default path.
    let hr = unsafe { SHGetKnownFolderPath(&PROGRAM_DATA, 0, std::ptr::null_mut(), &mut raw) };
    if hr < 0 || raw.is_null() {
        return Err(crate::Error::isolation_unavailable(
            "cannot resolve trusted ProgramData known folder",
        ));
    }
    // SAFETY: SHGetKnownFolderPath returned a NUL-terminated CoTaskMem string.
    let path = unsafe {
        let mut n = 0usize;
        while *raw.add(n) != 0 {
            n += 1;
        }
        let s = std::ffi::OsString::from_wide(std::slice::from_raw_parts(raw, n));
        CoTaskMemFree(raw.cast());
        std::path::PathBuf::from(s)
    };
    Ok(path.join("fail2commit-hardened").join("install.json"))
}

#[cfg(target_os = "linux")]
fn machine_state_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/etc/fail2commit-hardened.json")
}

#[cfg(not(any(windows, target_os = "linux")))]
fn machine_state_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/nonexistent/fail2commit-hardened.json")
}

struct HardenedBackend;

impl SandboxBackend for HardenedBackend {
    fn probe(&self) -> ProbeReport {
        #[cfg(target_os = "linux")]
        let (service, peer_auth, detail) = service::probe_linux();
        #[cfg(windows)]
        let (service, peer_auth, detail) = service::probe_windows();
        #[cfg(not(any(target_os = "linux", windows)))]
        let (service, peer_auth, detail) = (
            false,
            false,
            String::from("service transport is not verified"),
        );
        ProbeReport {
            backend: if cfg!(windows) {
                "hardened-appcontainer"
            } else {
                "hardened-bubblewrap"
            },
            available: false,
            detail: format!("{detail}; launcher and platform controls are not verified"),
            controls: vec![
                ("service_running".into(), service),
                ("peer_authentication".into(), peer_auth),
                ("launcher_watchdog".into(), false),
                ("platform_controls".into(), false),
            ],
        }
    }

    fn run(&self, job: &JobSpec) -> crate::Result<JobOutcome> {
        #[cfg(windows)]
        {
            service::run_windows(job)
        }
        #[cfg(not(windows))]
        {
            let _ = job;
            Err(crate::Error::isolation_unavailable(
                "hardened controls are not verified; refusing to launch",
            ))
        }
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use crate::settings::Settings;

    #[test]
    fn an_installed_hardened_backend_never_reports_available_before_controls_pass() {
        let probe = HardenedBackend.probe();
        assert!(!probe.available);
        assert!(probe
            .controls
            .iter()
            .any(|(name, ok)| name == "peer_authentication" && !ok));
    }

    #[test]
    fn vm_choice_remains_platform_fallback_until_vm_backend_exists() {
        let mut settings = Settings::default();
        settings.sandbox.backend = BackendChoice::Vm;
        assert!(selected(&settings).is_none());
    }

    #[test]
    fn only_auto_selects_hardened_when_a_machine_install_exists() {
        assert!(!should_select_hardened(BackendChoice::Auto, false));
        assert!(should_select_hardened(BackendChoice::Auto, true));
        assert!(!should_select_hardened(BackendChoice::Vm, true));
    }

    #[test]
    fn damaged_or_missing_marker_with_linux_remnants_fails_closed() {
        let td = tempfile::tempdir().unwrap();
        let marker = td.path().join("install.json");
        let unit = td.path().join("fail2commit-hardened.socket");
        let remnants = vec![unit.clone()];
        assert!(!marker_or_remnants(&marker, &remnants, false));
        std::fs::write(&unit, b"managed unit").unwrap();
        assert!(marker_or_remnants(&marker, &remnants, false));
        std::fs::remove_file(&unit).unwrap();
        std::fs::create_dir(&marker).unwrap();
        assert!(marker_or_remnants(&marker, &remnants, false));
        std::fs::remove_dir(&marker).unwrap();
        assert!(marker_or_remnants(&marker, &remnants, true));
        assert!(marker_or_remnants(std::path::Path::new("\0"), &[], false));
    }
}
