//! Hardened-mode wire contract and backends (FR-027, SPEC-018).

pub mod lifecycle;
#[cfg(target_os = "linux")]
mod linux_acl;
pub mod protocol;
pub mod service;
#[cfg(windows)]
mod windows_effect_probe;
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
    let mut status = lifecycle::status();
    if status["installed"] != true || status.get("error").is_some() {
        return status;
    }

    #[cfg(target_os = "linux")]
    {
        let (service, peer_auth, platform, network, detail) = service::probe_linux();
        let available = service && peer_auth && platform && network;
        if let Some(fields) = status.as_object_mut() {
            fields.insert("service_running".into(), serde_json::json!(service));
            fields.insert("peer_authenticated".into(), serde_json::json!(peer_auth));
            fields.insert("platform_probe_available".into(), serde_json::json!(platform));
            fields.insert("network_probe_available".into(), serde_json::json!(network));
            fields.insert("probe_available".into(), serde_json::json!(available));
            fields.insert(
                "controls".into(),
                serde_json::json!({
                    "service_running": service,
                    "peer_authentication": peer_auth,
                    "launcher_watchdog_and_platform": platform,
                    "shared_egress_effects": network,
                }),
            );
            fields.insert("detail".into(), serde_json::json!(detail));
        }
        return status;
    }

    #[cfg(windows)]
    {
        let (service, peer_auth, effect_probe, detail) = service::probe_windows();
        let available = service && peer_auth && effect_probe;
        if let Some(fields) = status.as_object_mut() {
            fields.insert("service_running".into(), serde_json::json!(service));
            fields.insert("peer_authenticated".into(), serde_json::json!(peer_auth));
            fields.insert("probe_available".into(), serde_json::json!(available));
            fields.insert("effect_probe_passed".into(), serde_json::json!(effect_probe));
            fields.insert(
                "controls".into(),
                serde_json::json!({
                    "service_running": service,
                    "peer_authentication": peer_auth,
                    "wfp_lpac_traffic_effects": effect_probe,
                }),
            );
            fields.insert("detail".into(), serde_json::json!(detail));
        }
        return status;
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        status["probe_available"] = serde_json::json!(false);
        status
    }
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

/// Fixed hidden payload entry point for the service-owned, authenticated
/// Windows traffic-effect probe. It has no command, URI, or path parameters.
pub fn run_network_effect_probe_child() -> crate::Result<()> {
    #[cfg(windows)]
    {
        let report = windows_effect_probe::run_child()?;
        let bytes = serde_json::to_vec(&report)
            .map_err(|_| crate::Error::internal("cannot encode Windows effect probe result"))?;
        use std::io::Write;
        std::io::stdout().write_all(&bytes)?;
        std::io::stdout().write_all(b"\n")?;
        std::io::stdout().flush()?;
        if report.complete() {
            Ok(())
        } else {
            Err(crate::Error::isolation_unavailable(
                "one or more mandatory LPAC/WFP traffic-effect probes failed",
            ))
        }
    }
    #[cfg(not(windows))]
    {
        Err(crate::Error::rejected(
            "Windows traffic-effect probe is unavailable on this platform",
        ))
    }
}

/// Launcher entry point deliberately refuses until all per-job isolation
/// controls, grants, and watchdog handling have been wired and probed.
pub fn launch(jobfile: &std::path::Path, watchdog: Option<u64>) -> crate::Result<()> {
    launch_with_control(jobfile, watchdog, None, None, None)
}

/// Service-invoked Linux probe: run a short disposable job under the real
/// hardened launcher and require watchdog EOF to kill its sandbox tree.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn run_linux_watchdog_probe(watchdog: Option<u64>) -> crate::Result<()> {
    use crate::isolation::{JobLimits, JobSpec, JobStatus, NetworkMode};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return Err(crate::Error::rejected(
            "hardened Linux watchdog probe must run as the sandbox account",
        ));
    }
    let watchdog_fd = watchdog
        .and_then(|fd| i32::try_from(fd).ok())
        .filter(|fd| *fd >= 0)
        .ok_or_else(|| crate::Error::rejected("hardened Linux watchdog probe requires a fd"))?;
    let state_dir = std::path::Path::new("/var/lib/fail2commit-hardened");
    let state_metadata = std::fs::symlink_metadata(state_dir)?;
    // SAFETY: geteuid has no preconditions.
    if state_metadata.uid() != unsafe { libc::geteuid() }
        || state_metadata.mode() & 0o077 != 0
        || !state_metadata.is_dir()
        || state_metadata.file_type().is_symlink()
    {
        return Err(crate::Error::integrity(
            "hardened Linux watchdog probe work root is not private and sandbox-owned",
        ));
    }
    let work = tempfile::Builder::new()
        .prefix("probe-")
        .tempdir_in(state_dir)?;
    let job = JobSpec {
        program: std::path::PathBuf::from("/bin/sleep"),
        args: vec!["10".into()],
        cwd: work.path().to_path_buf(),
        env: Vec::new(),
        read_only: Vec::new(),
        work_dir: work.path().to_path_buf(),
        exports: Vec::new(),
        export_to: None,
        limits: JobLimits {
            timeout: std::time::Duration::from_secs(15),
            memory_bytes: Some(128 * 1024 * 1024),
            max_processes: Some(8),
            max_output_bytes: 1024,
            disk_bytes: Some(1024 * 1024),
        },
        network: NetworkMode::None,
        bait: false,
    };
    let outcome = crate::sandbox::linux::run_hardened_with_ready(&job, watchdog_fd, || {
        let mut output = std::io::stdout().lock();
        output.write_all(b"F2C-WATCHDOG-READY\n")?;
        output.flush()?;
        Ok(())
    })?;
    let watchdog_cancelled = outcome.status == JobStatus::Killed
        && outcome.report.events.iter().any(|event| {
            event.kind == crate::isolation::ActivityKind::Blocked
                && event.detail.contains("watchdog")
        });
    let result = serde_json::json!({
        "watchdog_cancelled": watchdog_cancelled,
        "status": outcome.status,
    });
    std::io::stdout().write_all(&serde_json::to_vec(&result).map_err(|_| {
        crate::Error::internal("cannot encode hardened Linux watchdog probe result")
    })?)?;
    std::io::stdout().write_all(b"\n")?;
    std::io::stdout().flush()?;
    if watchdog_cancelled {
        Ok(())
    } else {
        Err(crate::Error::isolation_unavailable(
            "hardened Linux watchdog probe did not kill the sandbox process tree",
        ))
    }
}

/// Fixed hidden Linux egress-effect payload invoked only by the root service's
/// authenticated PROBE operation. It accepts an expected uid and a mode, never
/// a caller command, path, URL, or environment override.
#[cfg(target_os = "linux")]
pub fn run_linux_egress_probe_child(
    expected_uid: u32,
    bait_trip: bool,
    platform_only: bool,
) -> crate::Result<()> {
    service::run_linux_egress_probe_child(expected_uid, bait_trip, platform_only)
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
    #[cfg(target_os = "linux")]
    {
        if prepare_request.is_some()
            || prepare_ack.is_some()
            || launch_id.is_some()
            || test_diagnostic
        {
            return Err(crate::Error::rejected(
                "Windows preparation controls are invalid for the Linux hardened launcher",
            ));
        }
        service::launch_linux_hidden(jobfile, watchdog)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
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
        let (service, peer_auth, platform_controls, network_controls, detail) =
            service::probe_linux();
        #[cfg(windows)]
        let (service, peer_auth, effect_probe, detail) = service::probe_windows();
        #[cfg(not(any(target_os = "linux", windows)))]
        let (service, peer_auth, effect_probe, detail) = (
            false,
            false,
            false,
            String::from("service transport is not verified"),
        );
        #[cfg(target_os = "linux")]
        let effect_probe = false;
        #[cfg(target_os = "linux")]
        let launcher_verified = platform_controls;
        #[cfg(windows)]
        let launcher_verified = false;
        #[cfg(not(any(target_os = "linux", windows)))]
        let launcher_verified = false;
        #[cfg(target_os = "linux")]
        let platform_verified = platform_controls;
        #[cfg(windows)]
        let platform_verified = false;
        #[cfg(not(any(target_os = "linux", windows)))]
        let platform_verified = false;
        #[cfg(target_os = "linux")]
        let available = service && peer_auth && platform_controls && network_controls;
        #[cfg(not(target_os = "linux"))]
        let available = false;
        let mut controls = vec![
            ("service_running".into(), service),
            ("peer_authentication".into(), peer_auth),
            ("launcher_watchdog".into(), launcher_verified),
            ("platform_controls".into(), platform_verified),
            ("wfp_lpac_traffic_effects".into(), effect_probe),
        ];
        #[cfg(target_os = "linux")]
        controls.push(("service_egress_effects".into(), network_controls));
        #[cfg(target_os = "linux")]
        let report_detail = format!(
            "{detail}; hardened Linux launcher controls are {}; Internet egress remains disabled until its service effect probes pass",
            if available { "verified" } else { "not verified" }
        );
        #[cfg(not(target_os = "linux"))]
        let report_detail = detail;
        ProbeReport {
            backend: if cfg!(windows) {
                "hardened-appcontainer"
            } else {
                "hardened-bubblewrap"
            },
            available,
            detail: report_detail,
            controls,
        }
    }

    fn run(&self, job: &JobSpec) -> crate::Result<JobOutcome> {
        #[cfg(windows)]
        {
            service::run_windows(job)
        }
        #[cfg(target_os = "linux")]
        {
            service::run_linux(job)
        }
        #[cfg(not(any(windows, target_os = "linux")))]
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
