//! Minimal authenticated service transport for SPEC-018 §4.2.

#[cfg(any(target_os = "linux", windows, test))]
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", windows, test))]
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(any(target_os = "linux", windows))]
use std::path::Path;

#[cfg(any(target_os = "linux", windows, test))]
const MAX_REQUEST: usize = 16 * 1024;
#[cfg(any(target_os = "linux", windows))]
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(any(target_os = "linux", windows, test))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    #[serde(default)]
    job_dir: Option<String>,
}

#[cfg(any(target_os = "linux", windows, test))]
#[derive(Debug, Serialize, Deserialize)]
struct Response {
    ok: bool,
    service_running: bool,
    probe_available: bool,
    detail: String,
}

#[cfg(windows)]
pub(super) fn run_windows(
    job: &crate::isolation::JobSpec,
) -> crate::Result<crate::isolation::JobOutcome> {
    let state = super::lifecycle::installed_state()?;
    let installer_sid = state
        .installer_sid
        .as_deref()
        .ok_or_else(|| crate::Error::integrity("Windows install state has no installer SID"))?;
    let sandbox_sid = state.sandbox_sid.as_deref().ok_or_else(|| {
        crate::Error::integrity("Windows install state has no sandbox account SID")
    })?;
    let pipe_name = format!(r"\\.\pipe\fail2commit-hardened-{installer_sid}");
    let status = service_request(
        &pipe_name,
        &Request {
            op: "STATUS".into(),
            job_dir: None,
        },
    )?;
    if !status.ok {
        return Err(crate::Error::isolation_unavailable(status.detail));
    }
    let paths = crate::paths::TrustedPaths::resolve()?;
    crate::fsutil::ensure_private_dir(&paths.cache_dir)?;
    crate::sandbox::windows::sweep_hardened_job_state(&paths.cache_dir)?;
    let temp = tempfile::Builder::new()
        .prefix("hardened-job-")
        .tempdir_in(&paths.cache_dir)?;
    let jobfile = temp.path().join("job.json");
    let encoded = super::protocol::encode_job(job)?;
    std::fs::write(&jobfile, encoded)?;
    let job_dir = temp.path().to_string_lossy().into_owned();
    let request = Request {
        op: "LAUNCH".into(),
        job_dir: Some(job_dir),
    };
    let mut pipe = open_service_pipe(&pipe_name)?;
    let result = crate::sandbox::windows::with_hardened_job_grants(job, sandbox_sid, || {
        let reply = service_request_on_pipe(&mut pipe, &request)?;
        if !reply.ok {
            return Err(crate::Error::isolation_unavailable(reply.detail));
        }
        let outcome_path = temp.path().join("outcome.json");
        let metadata = std::fs::symlink_metadata(&outcome_path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > super::protocol::MAX_OUTCOME_BYTES as u64
        {
            return Err(crate::Error::integrity(
                "hardened outcome file is unsafe or oversized",
            ));
        }
        super::protocol::decode_outcome(&std::fs::read(outcome_path)?)
    });
    result
}

#[cfg(windows)]
fn open_service_pipe(name: &str) -> crate::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(name)
        .map_err(|e| {
            crate::Error::isolation_unavailable(format!("open hardened service pipe: {e}"))
        })
}

#[cfg(windows)]
fn service_request(name: &str, request: &Request) -> crate::Result<Response> {
    let mut pipe = open_service_pipe(name)?;
    service_request_on_pipe(&mut pipe, request)
}

#[cfg(windows)]
fn service_request_on_pipe(pipe: &mut std::fs::File, request: &Request) -> crate::Result<Response> {
    let encoded = serde_json::to_vec(request)
        .map_err(|e| crate::Error::internal(format!("request serialization failed: {e}")))?;
    pipe.write_all(&encoded)?;
    pipe.write_all(b"\n")?;
    pipe.flush()?;
    let mut reader = BufReader::new(pipe);
    let mut line = Vec::new();
    reader
        .by_ref()
        .take(MAX_REQUEST as u64)
        .read_until(b'\n', &mut line)?;
    decode_response(&line)
}

#[cfg(any(target_os = "linux", windows, test))]
fn decode_response(line: &[u8]) -> crate::Result<Response> {
    if line.len() >= MAX_REQUEST || !line.ends_with(b"\n") {
        return Err(crate::Error::integrity(
            "hardened service response is incomplete or oversized",
        ));
    }
    serde_json::from_slice(line)
        .map_err(|e| crate::Error::integrity(format!("invalid hardened service response: {e}")))
}

#[cfg(any(target_os = "linux", windows, test))]
fn response(ok: bool, detail: impl Into<String>) -> Response {
    Response {
        ok,
        service_running: true,
        probe_available: false,
        detail: detail.into(),
    }
}

#[cfg(any(windows, test))]
fn bounded_error_detail(message: &str) -> String {
    message.chars().take(256).collect()
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessWait {
    Signaled,
    TimedOut,
    Failed(u32),
}

#[cfg(any(windows, test))]
fn termination_confirmation(
    terminate: impl FnOnce() -> std::result::Result<(), u32>,
    wait: impl FnOnce(u32) -> ProcessWait,
) -> std::result::Result<(), String> {
    const TERMINATION_WAIT_MS: u32 = 5_000;
    let terminate_error = terminate().err();
    match wait(TERMINATION_WAIT_MS) {
        ProcessWait::Signaled => Ok(()),
        ProcessWait::TimedOut => Err(match terminate_error {
            Some(code) => format!(
                "TerminateProcess failed with Win32 error {code} and launcher did not exit within {TERMINATION_WAIT_MS} ms"
            ),
            None => format!(
                "launcher did not exit within {TERMINATION_WAIT_MS} ms after TerminateProcess"
            ),
        }),
        ProcessWait::Failed(code) => Err(match terminate_error {
            Some(terminate_code) => format!(
                "TerminateProcess failed with Win32 error {terminate_code}; termination wait failed with Win32 error {code}"
            ),
            None => format!(
                "termination wait failed with Win32 error {code}; launcher exit is unconfirmed"
            ),
        }),
    }
}

#[cfg(any(target_os = "linux", windows, test))]
fn decode_request(line: &[u8]) -> crate::Result<Request> {
    if line.len() >= MAX_REQUEST || !line.ends_with(b"\n") {
        return Err(crate::Error::invalid(
            "request is incomplete or exceeds size limit",
        ));
    }
    serde_json::from_slice::<Request>(line)
        .map_err(|_| crate::Error::invalid("malformed hardened service request"))
}

#[cfg(any(target_os = "linux", test))]
fn dispatch(req: Request, peer_uid: u32, installer_uid: u32, sandbox_uid: u32) -> Response {
    if !peer_uid_allowed(peer_uid, installer_uid, sandbox_uid) {
        return response(false, "peer uid is not authorized");
    }
    match req.op.as_str() {
        "STATUS" if req.job_dir.is_none() => response(true, "controls are not verified"),
        "LAUNCH" => {
            #[cfg(target_os = "linux")]
            {
                let Some(path) = req.job_dir.as_deref() else {
                    return response(false, "job_dir is required");
                };
                match validate_job_dir(Path::new(path), peer_uid) {
                    Ok(()) => response(
                        false,
                        "launcher controls are not verified; job was not started",
                    ),
                    Err(_) => response(false, "job_dir is invalid or not owned by the peer"),
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (req, peer_uid);
                response(
                    false,
                    "launcher controls are not verified; job was not started",
                )
            }
        }
        _ => response(false, "unknown or malformed operation"),
    }
}

#[cfg(any(target_os = "linux", test))]
fn peer_uid_allowed(peer_uid: u32, installer_uid: u32, sandbox_uid: u32) -> bool {
    peer_uid == installer_uid && peer_uid != 0 && peer_uid != sandbox_uid
}

#[cfg(target_os = "linux")]
fn validate_job_dir(path: &Path, peer_uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "not canonical",
        ));
    }
    let md = std::fs::symlink_metadata(path)?;
    if !md.is_dir() || md.uid() != peer_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "wrong owner/type",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn serve_linux() -> crate::Result<()> {
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixListener;
    let state = super::lifecycle::installed_state()?;
    require_root_and_trusted_runtime_dir()?;
    let pid = std::process::id().to_string();
    let fds = std::env::var("LISTEN_FDS").unwrap_or_default();
    if std::env::var("LISTEN_PID").ok().as_deref() != Some(&pid) || fds != "1" {
        return Err(crate::Error::rejected(
            "sandbox serve must be started by the hardened socket unit",
        ));
    }
    // SAFETY: systemd passes the listening Unix stream socket as fd 3 when
    // LISTEN_PID matches and LISTEN_FDS is exactly one; ownership transfers here.
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    let sandbox_uid = std::process::Command::new("id")
        .args(["-u", "f2c-sandbox"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(u32::MAX);
    if !peer_uid_allowed(state.installer_uid, state.installer_uid, sandbox_uid) {
        return Err(crate::Error::integrity(
            "installer uid collides with root or f2c-sandbox",
        ));
    }
    for conn in listener.incoming() {
        let Ok(mut stream) = conn else { continue };
        if stream.set_read_timeout(Some(REQUEST_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(REQUEST_TIMEOUT)).is_err()
        {
            continue;
        }
        let Ok(peer_uid) = peer_uid(&stream) else {
            continue;
        };
        if serve_one(&mut stream, peer_uid, state.installer_uid, sandbox_uid).is_err() {
            let rejected = response(false, "malformed or timed-out service request");
            let _ = serde_json::to_writer(&mut stream, &rejected);
            let _ = stream.write_all(b"\n");
            let _ = stream.flush();
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(super) fn probe_linux() -> (bool, bool, String) {
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let result = (|| -> crate::Result<Response> {
        let mut stream = UnixStream::connect("/run/fail2commit-hardened/sock")?;
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: peer and len are writable buffers for SO_PEERCRED.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() || peer.uid != 0 {
            return Err(crate::Error::integrity(
                "service peer is not verified as root",
            ));
        }
        stream.write_all(b"{\"op\":\"STATUS\"}\n")?;
        let mut line = String::new();
        BufReader::new(stream)
            .take(MAX_REQUEST as u64)
            .read_line(&mut line)?;
        let r = serde_json::from_str::<Response>(&line)
            .map_err(|_| crate::Error::integrity("malformed service status response"))?;
        if !r.ok || !r.service_running {
            return Err(crate::Error::isolation_unavailable(
                "service refused status request",
            ));
        }
        Ok(r)
    })();
    match result {
        Ok(r) => (true, true, r.detail),
        Err(e) => (false, false, e.message),
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(super) fn probe_windows() -> (bool, bool, String) {
    use crate::ipc::winsec;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
    use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};

    let result = (|| -> crate::Result<Response> {
        let sid = winsec::current_user_sid()?;
        let pipe = format!(
            r"\\.\pipe\fail2commit-hardened-{}",
            winsec::sid_string(&sid)
        );
        let wide: Vec<u16> = OsStr::new(&pipe).encode_wide().chain([0]).collect();
        // SAFETY: `wide` is NUL-terminated.
        if unsafe { WaitNamedPipeW(wide.as_ptr(), 250) } == 0 {
            let code = unsafe { GetLastError() };
            let detail = if code == ERROR_PIPE_BUSY {
                "hardened pipe is busy"
            } else if code == ERROR_FILE_NOT_FOUND {
                "hardened service pipe is absent"
            } else {
                "cannot wait for hardened service pipe"
            };
            return Err(crate::Error::isolation_unavailable(detail));
        }
        // SAFETY: open the local service pipe for one bounded request.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(crate::Error::isolation_unavailable(
                "cannot connect to hardened service pipe",
            ));
        }
        // SAFETY: fresh handle is exclusively owned.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let mut server_pid = 0u32;
        // SAFETY: valid pipe handle and writable PID output.
        if unsafe { GetNamedPipeServerProcessId(raw, &mut server_pid) } == 0 {
            return Err(crate::Error::integrity(
                "cannot identify hardened service process",
            ));
        }
        let server = winsec::process_facts(server_pid)?;
        if server.app_container || server.user != winsec::sid_from_string("S-1-5-18").unwrap() {
            return Err(crate::Error::integrity(
                "hardened service is not running as SYSTEM",
            ));
        }
        let mut file = std::fs::File::from(handle);
        file.write_all(b"{\"op\":\"STATUS\"}\n")?;
        let mut line = Vec::new();
        BufReader::new(file)
            .take(MAX_REQUEST as u64)
            .read_until(b'\n', &mut line)?;
        if line.len() >= MAX_REQUEST || !line.ends_with(b"\n") {
            return Err(crate::Error::integrity(
                "hardened service response exceeds size limit",
            ));
        }
        let reply = serde_json::from_slice::<Response>(&line)
            .map_err(|_| crate::Error::integrity("malformed hardened service status response"))?;
        if !reply.ok || !reply.service_running {
            return Err(crate::Error::isolation_unavailable(
                "hardened service status was rejected",
            ));
        }
        Ok(reply)
    })();
    match result {
        Ok(reply) => (true, true, reply.detail),
        Err(e) => (false, false, e.message),
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn require_root_and_trusted_runtime_dir() -> crate::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(crate::Error::rejected("hardened service must run as root"));
    }
    let p = Path::new("/run/fail2commit-hardened");
    let md = std::fs::symlink_metadata(p)?;
    if !md.is_dir() || md.file_type().is_symlink() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(crate::Error::integrity(
            "hardened runtime directory is not root-owned and non-writable by other users",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> crate::Result<u32> {
    use std::os::fd::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid writable buffers; the socket fd is live.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(crate::Error::rejected("cannot authenticate socket peer"));
    }
    Ok(cred.uid)
}

#[cfg(target_os = "linux")]
fn read_request_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
) -> crate::Result<Vec<u8>> {
    use std::io::Read;
    stream.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + timeout;
    let result = (|| {
        let mut line = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(crate::Error::invalid("service request timed out"));
            }
            match stream.read(&mut buf) {
                Ok(0) => {
                    return Err(crate::Error::invalid(
                        "peer closed before request completed",
                    ))
                }
                Ok(n) => {
                    line.extend_from_slice(&buf[..n]);
                    if line.contains(&b'\n') {
                        break;
                    }
                    if line.len() >= MAX_REQUEST {
                        return Err(crate::Error::invalid("service request exceeds size limit"));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(line)
    })();
    let restore = stream.set_nonblocking(false);
    if let Err(e) = restore {
        return Err(e.into());
    }
    result
}

#[cfg(target_os = "linux")]
fn serve_one(
    stream: &mut std::os::unix::net::UnixStream,
    uid: u32,
    installer: u32,
    sandbox: u32,
) -> crate::Result<()> {
    let line = read_request_deadline(stream, REQUEST_TIMEOUT)?;
    let req = decode_request(&line)?;
    let result = dispatch(req, uid, installer, sandbox);
    serde_json::to_writer(&mut *stream, &result)
        .map_err(|e| crate::Error::internal(e.to_string()))?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

#[cfg(windows)]
static SERVICE_STOP_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(windows)]
static LAUNCHER_CONTAINMENT_FAILED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// A durable fail-closed latch for a launch whose process/profile cleanup may
/// have been interrupted by service termination.  The marker is intentionally
/// not auto-recovered: startup cannot prove that no descendant or profile use
/// remains without the recorded process identity and platform recovery path.
#[cfg(any(windows, test))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveLaunchMarker {
    version: u32,
    launch_id: String,
    sandbox_sid: String,
    snapshot_dir: String,
    pid: Option<u32>,
    creation_time_100ns: Option<u64>,
}

#[cfg(any(windows, test))]
const ACTIVE_LAUNCH_MARKER_MAX: usize = 4096;

#[cfg(any(windows, test))]
fn decode_active_launch_marker(bytes: &[u8]) -> Result<ActiveLaunchMarker, &'static str> {
    if bytes.is_empty() || bytes.len() > ACTIVE_LAUNCH_MARKER_MAX {
        return Err("active launch marker has invalid size");
    }
    let marker: ActiveLaunchMarker =
        serde_json::from_slice(bytes).map_err(|_| "active launch marker is malformed")?;
    if marker.version != 1
        || marker.launch_id.len() != 64
        || !marker.launch_id.bytes().all(|b| b.is_ascii_hexdigit())
        || !marker.sandbox_sid.starts_with("S-1-")
        || marker.snapshot_dir.is_empty()
        || marker.pid.is_some() != marker.creation_time_100ns.is_some()
        || marker.pid == Some(0)
    {
        return Err("active launch marker fields are invalid");
    }
    Ok(marker)
}

#[cfg(windows)]
fn active_launch_marker_path() -> crate::Result<std::path::PathBuf> {
    Ok(super::machine_state_path()?
        .parent()
        .ok_or_else(|| crate::Error::integrity("install state has no parent"))?
        .join("active-launch.json"))
}

#[cfg(any(windows, test))]
fn may_sweep_after_marker_check<T>(check: &std::result::Result<bool, T>) -> bool {
    matches!(check, Ok(false))
}

#[cfg(windows)]
fn active_launch_pending() -> crate::Result<bool> {
    use std::os::windows::fs::MetadataExt;
    let path = active_launch_marker_path()?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    let file = open_windows_object(
        &path,
        false,
        windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ,
    )?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        || metadata.len() as usize > ACTIVE_LAUNCH_MARKER_MAX
        || crate::ipc::winsec::owner_sid(&file)? != "S-1-5-18"
    {
        return Err(crate::Error::integrity(
            "active launch marker failed ownership or object checks",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&file)
        .take((ACTIVE_LAUNCH_MARKER_MAX + 1) as u64)
        .read_to_end(&mut bytes)?;
    decode_active_launch_marker(&bytes).map_err(crate::Error::integrity)?;
    Ok(true)
}

#[cfg(windows)]
pub(super) fn launch_recovery_pending() -> crate::Result<bool> {
    active_launch_pending()
}

#[cfg(windows)]
struct ActiveLaunchGuard {
    path: std::path::PathBuf,
    launch_id: String,
    armed: bool,
}

#[cfg(windows)]
impl ActiveLaunchGuard {
    fn create(sandbox_sid: &str, snapshot_dir: &Path) -> crate::Result<Self> {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|_| crate::Error::internal("cannot generate launch marker identity"))?;
        let launch_id = hex::encode(random);
        random.fill(0);
        let marker = ActiveLaunchMarker {
            version: 1,
            launch_id: launch_id.clone(),
            sandbox_sid: sandbox_sid.to_owned(),
            snapshot_dir: snapshot_dir.to_string_lossy().into_owned(),
            pid: None,
            creation_time_100ns: None,
        };
        let path = active_launch_marker_path()?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                crate::Error::isolation_unavailable(format!(
                    "cannot create active launch refusal marker: {e}"
                ))
            })?;
        serde_json::to_writer(&mut file, &marker)
            .map_err(|_| crate::Error::internal("cannot encode active launch marker"))?;
        file.sync_all()?;
        set_system_owner(&path)?;
        let check = open_windows_object(
            &path,
            false,
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ,
        )?;
        if crate::ipc::winsec::owner_sid(&check)? != "S-1-5-18" {
            return Err(crate::Error::integrity(
                "active launch marker is not SYSTEM-owned",
            ));
        }
        Ok(Self {
            path,
            launch_id,
            armed: true,
        })
    }

    #[allow(unsafe_code)]
    fn record_process(&mut self, pid: u32, creation_time_100ns: u64) -> crate::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
        let file = open_windows_object(
            &self.path,
            false,
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ,
        )?;
        let mut bytes = Vec::with_capacity(ACTIVE_LAUNCH_MARKER_MAX);
        (&file)
            .take((ACTIVE_LAUNCH_MARKER_MAX + 1) as u64)
            .read_to_end(&mut bytes)?;
        let mut marker = decode_active_launch_marker(&bytes).map_err(crate::Error::integrity)?;
        if marker.launch_id != self.launch_id || marker.pid.is_some() {
            return Err(crate::Error::integrity(
                "active launch marker identity changed",
            ));
        }
        drop(file);
        marker.pid = Some(pid);
        marker.creation_time_100ns = Some(creation_time_100ns);
        let temp_path = self
            .path
            .with_file_name(format!("active-launch-{}.tmp", self.launch_id));
        let mut temp = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        serde_json::to_writer(&mut temp, &marker)
            .map_err(|_| crate::Error::internal("cannot encode active launch marker"))?;
        temp.sync_all()?;
        drop(temp);
        set_system_owner(&temp_path)?;
        let target_w: Vec<u16> = self.path.as_os_str().encode_wide().chain([0]).collect();
        let temp_w: Vec<u16> = temp_path.as_os_str().encode_wide().chain([0]).collect();
        if unsafe {
            ReplaceFileW(
                target_w.as_ptr(),
                temp_w.as_ptr(),
                std::ptr::null(),
                1,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            let _ = std::fs::remove_file(&temp_path);
            return Err(crate::Error::isolation_unavailable(format!(
                "cannot persist launcher process identity (Win32 error {code})"
            )));
        }
        Ok(())
    }

    /// Keep an interrupted launch locked. The next service instance refuses
    /// all launches and snapshot sweeps when it finds this marker.
    fn retain(&mut self) {
        self.armed = false;
    }

    fn clear(&mut self) -> crate::Result<()> {
        let file = open_windows_object(
            &self.path,
            false,
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ,
        )?;
        let mut bytes = Vec::with_capacity(ACTIVE_LAUNCH_MARKER_MAX);
        (&file)
            .take((ACTIVE_LAUNCH_MARKER_MAX + 1) as u64)
            .read_to_end(&mut bytes)?;
        let marker = decode_active_launch_marker(&bytes).map_err(crate::Error::integrity)?;
        if marker.launch_id != self.launch_id || crate::ipc::winsec::owner_sid(&file)? != "S-1-5-18"
        {
            return Err(crate::Error::integrity(
                "active launch marker identity changed",
            ));
        }
        drop(file);
        std::fs::remove_file(&self.path)?;
        self.armed = false;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ActiveLaunchGuard {
    fn drop(&mut self) {
        // Never clear on unwind. Only the normal confirmed cleanup path calls
        // clear(); all other exits deliberately leave the durable refusal.
        let _ = self.armed;
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn service_running() -> bool {
    use std::ffi::c_void;
    #[repr(C)]
    struct Status {
        kind: u32,
        state: u32,
        accepted: u32,
        win32: u32,
        specific: u32,
        checkpoint: u32,
        hint: u32,
    }
    const NAME: &[u16] = &[
        102, 97, 105, 108, 50, 99, 111, 109, 109, 105, 116, 45, 104, 97, 114, 100, 101, 110, 101,
        100, 0,
    ];
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> *mut c_void;
        fn OpenServiceW(manager: *mut c_void, name: *const u16, access: u32) -> *mut c_void;
        fn QueryServiceStatus(service: *mut c_void, status: *mut Status) -> i32;
        fn CloseServiceHandle(service: *mut c_void) -> i32;
    }
    // SAFETY: all names are static NUL-terminated UTF-16 strings.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), 1) };
    if manager.is_null() {
        return false;
    }
    let svc = unsafe { OpenServiceW(manager, NAME.as_ptr(), 4) };
    if svc.is_null() {
        unsafe { CloseServiceHandle(manager) };
        return false;
    }
    let mut status = Status {
        kind: 0,
        state: 0,
        accepted: 0,
        win32: 0,
        specific: 0,
        checkpoint: 0,
        hint: 0,
    };
    let ok = unsafe { QueryServiceStatus(svc, &mut status) } != 0 && status.state == 4;
    unsafe {
        CloseServiceHandle(svc);
        CloseServiceHandle(manager)
    };
    ok
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn serve_windows() -> crate::Result<()> {
    use std::ffi::c_void;
    use std::sync::atomic::Ordering;
    #[repr(C)]
    struct Status {
        kind: u32,
        state: u32,
        accepted: u32,
        win32: u32,
        specific: u32,
        checkpoint: u32,
        hint: u32,
    }
    #[repr(C)]
    struct Entry {
        name: *mut u16,
        main: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
    }
    const SERVICE_NAME_W: &[u16] = &[
        102, 97, 105, 108, 50, 99, 111, 109, 109, 105, 116, 45, 104, 97, 114, 100, 101, 110, 101,
        100, 0,
    ];
    static mut STATUS_HANDLE: *mut c_void = std::ptr::null_mut();
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const Entry) -> i32;
        fn RegisterServiceCtrlHandlerW(
            name: *const u16,
            handler: Option<unsafe extern "system" fn(u32)>,
        ) -> *mut c_void;
        fn SetServiceStatus(handle: *mut c_void, status: *const Status) -> i32;
    }
    unsafe extern "system" fn handler(control: u32) {
        if control == 1 {
            SERVICE_STOP_REQUESTED.store(true, Ordering::SeqCst);
            let st = Status {
                kind: 0x10,
                state: 3,
                accepted: 0,
                win32: 0,
                specific: 0,
                checkpoint: 1,
                hint: 5000,
            };
            // SAFETY: service status handle is set by service_main and st is a valid value.
            unsafe { SetServiceStatus(STATUS_HANDLE, &st) };
        }
    }
    unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
        SERVICE_STOP_REQUESTED.store(false, Ordering::SeqCst);
        // SAFETY: constant service name and callback have static lifetime.
        unsafe {
            STATUS_HANDLE = RegisterServiceCtrlHandlerW(SERVICE_NAME_W.as_ptr(), Some(handler));
        }
        if unsafe { STATUS_HANDLE.is_null() } {
            return;
        }
        let mut st = Status {
            kind: 0x10,
            state: 2,
            accepted: 0,
            win32: 0,
            specific: 0,
            checkpoint: 1,
            hint: 5000,
        };
        unsafe { SetServiceStatus(STATUS_HANDLE, &st) };
        st.state = 4;
        st.accepted = 1;
        st.checkpoint = 0;
        st.hint = 0;
        unsafe { SetServiceStatus(STATUS_HANDLE, &st) };
        let code = service_loop_windows();
        st.state = 1;
        st.accepted = 0;
        st.win32 = if code.is_ok() { 0 } else { 1066 };
        st.specific = 0;
        st.checkpoint = 0;
        st.hint = 0;
        unsafe { SetServiceStatus(STATUS_HANDLE, &st) };
    }
    SERVICE_STOP_REQUESTED.store(false, Ordering::SeqCst);
    let table = [
        Entry {
            name: SERVICE_NAME_W.as_ptr() as *mut u16,
            main: Some(service_main),
        },
        Entry {
            name: std::ptr::null_mut(),
            main: None,
        },
    ];
    // SAFETY: table and service name remain live for the dispatcher call.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(crate::Error::rejected(format!(
            "hardened service must be started by SCM: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_pipe_request(pipe: windows_sys::Win32::Foundation::HANDLE) -> crate::Result<Vec<u8>> {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    let mut line = Vec::new();
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(crate::Error::invalid("service request timed out"));
        }
        let mut available = 0u32;
        // SAFETY: pipe is a connected local named-pipe handle, and available is writable.
        if unsafe {
            PeekNamedPipe(
                pipe,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(crate::Error::invalid(
                "cannot peek authenticated request pipe",
            ));
        }
        if available == 0 {
            if std::time::Instant::now() >= deadline {
                return Err(crate::Error::invalid("service request timed out"));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        let count = available.min(4096).min((MAX_REQUEST - line.len()) as u32);
        let mut buf = vec![0u8; count as usize];
        let mut read = 0u32;
        // SAFETY: buf has count writable bytes; pipe is nonblocking and data is available.
        if unsafe {
            ReadFile(
                pipe,
                buf.as_mut_ptr(),
                count,
                &mut read,
                std::ptr::null_mut(),
            )
        } == 0
            || read == 0
        {
            return Err(crate::Error::invalid(
                "cannot read authenticated request pipe",
            ));
        }
        line.extend_from_slice(&buf[..read as usize]);
        if line.contains(&b'\n') {
            return Ok(line);
        }
        if line.len() >= MAX_REQUEST {
            return Err(crate::Error::invalid("service request exceeds size limit"));
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn write_pipe_response(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    reply: &Response,
) -> crate::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let mut bytes = serde_json::to_vec(reply).map_err(|e| crate::Error::internal(e.to_string()))?;
    bytes.push(b'\n');
    let mut written = 0u32;
    // SAFETY: bytes is a valid readable buffer; the response is bounded by MAX_REQUEST.
    if unsafe {
        WriteFile(
            pipe,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    } == 0
        || written as usize != bytes.len()
    {
        return Err(crate::Error::internal(
            "cannot write authenticated service response",
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn service_loop_windows() -> crate::Result<()> {
    use crate::ipc::winsec::{self, PipeSecurity};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, SetNamedPipeHandleState,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    };

    let state = super::lifecycle::installed_state()?;
    let sid_text = state
        .installer_sid
        .as_deref()
        .ok_or_else(|| crate::Error::integrity("Windows install state has no installer SID"))?;
    let expected = winsec::sid_from_string(sid_text)
        .ok_or_else(|| crate::Error::integrity("Windows installer SID is malformed"))?;
    let sandbox_sid = state.sandbox_sid.clone().ok_or_else(|| {
        crate::Error::integrity("Windows install state has no sandbox account SID")
    })?;
    let state_path = super::machine_state_path()?;
    let jobs = state_path
        .parent()
        .ok_or_else(|| crate::Error::integrity("install state has no parent"))?
        .join("jobs");
    let marker_check = active_launch_pending();
    if may_sweep_after_marker_check(&marker_check) {
        sweep_stale_snapshots(&jobs)?;
    } else {
        // Never delete snapshots or grants until a prior process has been
        // positively reconciled. Invalid markers also remain locked.
        LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
    }
    let name = format!(r"\\.\pipe\fail2commit-hardened-{sid_text}");
    let wide: Vec<u16> = OsStr::new(&name).encode_wide().chain([0]).collect();
    let security = PipeSecurity::new(&expected)?;
    loop {
        if SERVICE_STOP_REQUESTED.load(Ordering::SeqCst) {
            break Ok(());
        }
        // SAFETY: name is NUL-terminated and security attributes remain alive
        // until the handle is wrapped; pipe mode is local, synchronous byte IO.
        let raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | 0x00000001 | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                MAX_REQUEST as u32,
                MAX_REQUEST as u32,
                0,
                security.attributes(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(crate::Error::isolation_unavailable(format!(
                "cannot create hardened service pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: raw is a fresh named-pipe handle owned here.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        // SAFETY: raw is a connected server pipe handle; NULL requests sync IO.
        let mut connected = unsafe { ConnectNamedPipe(raw, std::ptr::null_mut()) } != 0;
        while !connected && unsafe { GetLastError() } == ERROR_PIPE_LISTENING {
            if SERVICE_STOP_REQUESTED.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            connected = unsafe { ConnectNamedPipe(raw, std::ptr::null_mut()) } != 0;
        }
        connected |= unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            if SERVICE_STOP_REQUESTED.load(Ordering::SeqCst) {
                break Ok(());
            }
            continue;
        }
        let mut mode = PIPE_READMODE_BYTE | 0x00000001;
        // SAFETY: valid connected server pipe and writable mode value.
        if unsafe {
            SetNamedPipeHandleState(raw, &mut mode, std::ptr::null_mut(), std::ptr::null_mut())
        } == 0
        {
            continue;
        }
        let mut pid = 0u32;
        // SAFETY: valid connected pipe handle and writable PID output.
        if unsafe { GetNamedPipeClientProcessId(raw, &mut pid) } == 0 {
            continue;
        }
        let facts = match winsec::process_facts(pid) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if !windows_peer_allowed(&facts.user, &expected, facts.app_container) {
            continue;
        }
        let line = match read_pipe_request(raw) {
            Ok(line) => line,
            Err(_) => {
                let _ = write_pipe_response(
                    raw,
                    &response(false, "malformed or timed-out service request"),
                );
                continue;
            }
        };
        let request = match decode_request(&line) {
            Ok(request) => request,
            Err(_) => {
                let _ = write_pipe_response(
                    raw,
                    &response(false, "malformed or timed-out service request"),
                );
                continue;
            }
        };
        let reply = match request.op.as_str() {
            "STATUS"
                if request.job_dir.is_none()
                    && LAUNCHER_CONTAINMENT_FAILED.load(Ordering::SeqCst) =>
            {
                response(
                    false,
                    "an unresolved active launch marker blocks cleanup and launch",
                )
            }
            "STATUS" if request.job_dir.is_none() => response(
                true,
                "service authenticated peer; launcher and platform controls are not verified",
            ),
            "LAUNCH" if request.job_dir.is_none() => {
                response(false, "job_dir is required; job was not started")
            }
            "LAUNCH" if LAUNCHER_CONTAINMENT_FAILED.load(Ordering::SeqCst) => response(
                false,
                "a prior launcher termination was not confirmed; service is locked fail-closed",
            ),
            "LAUNCH" => match launch_windows_request(
                raw,
                request.job_dir.as_deref().unwrap(),
                &expected,
                &sandbox_sid,
            ) {
                Ok(()) => response(true, "launcher completed; outcome was verified"),
                Err(error) => {
                    // Only the authenticated installer SID can read this pipe. Return a bounded
                    // user-facing control error so failed platform checks can be diagnosed;
                    // never log passwords, process output, or unbounded error text.
                    let detail = bounded_error_detail(&error.message);
                    response(false, format!("launcher rejected the job: {detail}"))
                }
            },
            _ => response(false, "unknown or malformed operation"),
        };
        let _ = write_pipe_response(raw, &reply);
        drop(handle);
    }
}

#[cfg(windows)]
fn windows_peer_allowed(peer: &[u8], expected: &[u8], app_container: bool) -> bool {
    !app_container && peer == expected
}

#[cfg(windows)]
struct UserJobDir {
    _handle: std::fs::File,
    path: std::path::PathBuf,
}

#[cfg(windows)]
fn open_windows_object(path: &Path, directory: bool, share: u32) -> crate::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true).share_mode(share).custom_flags(
        FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            },
    );
    options
        .open(path)
        .map_err(|e| crate::Error::rejected(format!("cannot safely open hardened job path: {e}")))
}

#[cfg(windows)]
fn open_user_job_dir(path: &str, peer_sid: &[u8]) -> crate::Result<UserJobDir> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(crate::Error::rejected("job_dir must be absolute"));
    }
    let canonical = path.canonicalize()?;
    if !same_windows_path(&canonical, path) {
        return Err(crate::Error::rejected("job_dir must be canonical"));
    }
    let handle = open_windows_object(&canonical, true, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
    let metadata = handle.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(crate::Error::rejected("job_dir is not a plain directory"));
    }
    let expected = crate::ipc::winsec::sid_string(peer_sid);
    if crate::ipc::winsec::owner_sid(&handle)? != expected {
        return Err(crate::Error::rejected(
            "job_dir is not owned by the authenticated peer",
        ));
    }
    Ok(UserJobDir {
        _handle: handle,
        path: canonical,
    })
}

#[cfg(any(windows, test))]
fn same_windows_path(left: &Path, right: &Path) -> bool {
    fn normalized(path: &Path) -> String {
        let mut value = path.to_string_lossy().replace('/', "\\");
        if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
            value = format!(r"\\{}", rest);
        } else if let Some(rest) = value.strip_prefix(r"\\?\") {
            value = rest.to_owned();
        }
        value.to_lowercase()
    }
    normalized(left) == normalized(right)
}

#[cfg(windows)]
fn snapshot_job(
    dir: &UserJobDir,
    peer_sid: &[u8],
    sandbox_sid: &str,
) -> crate::Result<(tempfile::TempDir, std::fs::File)> {
    use std::io::Read;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ};
    let source_path = dir.path.join("job.json");
    let source = open_windows_object(&source_path, false, FILE_SHARE_READ)?;
    let metadata = source.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || crate::sandbox::link_count(&metadata, &source_path)? != 1
        || metadata.len() > super::protocol::MAX_JOB_BYTES as u64
        || crate::ipc::winsec::owner_sid(&source)? != crate::ipc::winsec::sid_string(peer_sid)
    {
        return Err(crate::Error::rejected(
            "job.json is unsafe, oversized, or not peer-owned",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    source
        .take((super::protocol::MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > super::protocol::MAX_JOB_BYTES {
        return Err(crate::Error::rejected(
            "job.json exceeds the hardened job limit",
        ));
    }

    let state_path = super::machine_state_path()?;
    let data_dir = state_path
        .parent()
        .ok_or_else(|| crate::Error::integrity("install state has no parent"))?;
    let jobs = ensure_snapshot_store(&data_dir.join("jobs"))?;
    let temp = tempfile::Builder::new().prefix("job-").tempdir_in(&jobs)?;
    set_snapshot_acl(temp.path(), sandbox_sid, "RX")?;
    let input_dir = temp.path().join("input");
    let output_dir = temp.path().join("output");
    std::fs::create_dir(&input_dir)?;
    std::fs::create_dir(&output_dir)?;
    set_snapshot_acl(&input_dir, sandbox_sid, "RX")?;
    set_snapshot_acl(&output_dir, sandbox_sid, "M")?;
    let snapshot = input_dir.join("job.json");
    std::fs::write(&snapshot, bytes)?;
    let snapshot = open_windows_object(&snapshot, false, FILE_SHARE_READ)?;
    Ok((temp, snapshot))
}

#[cfg(windows)]
fn ensure_snapshot_store(path: &Path) -> crate::Result<std::path::PathBuf> {
    std::fs::create_dir_all(path)?;
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| crate::Error::isolation_unavailable("SystemRoot is unavailable"))?;
    let output = std::process::Command::new(root.join("System32\\icacls.exe"))
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .output()?;
    if !output.status.success() {
        return Err(crate::Error::integrity(
            "cannot secure hardened snapshot store",
        ));
    }
    // On Windows, a LocalSystem-created directory can default to the
    // Administrators group as owner. The service store has an explicit owner
    // contract, so set and read back SYSTEM ownership below.
    set_system_owner(path)?;
    let dir = open_windows_object(
        path,
        true,
        windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
            | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
    )?;
    if crate::ipc::winsec::owner_sid(&dir)? != "S-1-5-18" {
        return Err(crate::Error::integrity(
            "hardened snapshot store is not SYSTEM-owned",
        ));
    }
    let mut system = false;
    let mut admins = false;
    for (allow, sid, _) in crate::ipc::winsec::dacl_entries(&dir)? {
        if allow && sid == "S-1-5-18" {
            system = true;
        } else if allow && sid == "S-1-5-32-544" {
            admins = true;
        } else if allow {
            return Err(crate::Error::integrity(
                "hardened snapshot store ACL grants an unexpected identity",
            ));
        }
    }
    if !system || !admins {
        return Err(crate::Error::integrity(
            "hardened snapshot store ACL did not read back",
        ));
    }
    Ok(path.to_path_buf())
}

#[cfg(windows)]
fn sweep_stale_snapshots(path: &Path) -> crate::Result<()> {
    use std::os::windows::fs::MetadataExt;
    const REPARSE: u32 = 0x400;
    let path = ensure_snapshot_store(path)?;
    for entry in std::fs::read_dir(&path)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("job-") {
            continue;
        }
        let dir = entry.path();
        let meta = std::fs::symlink_metadata(&dir)?;
        if !meta.is_dir() || meta.file_attributes() & REPARSE != 0 {
            return Err(crate::Error::integrity(
                "stale service snapshot is not a plain directory",
            ));
        }
        let opened = open_windows_object(
            &dir,
            true,
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        )?;
        if crate::ipc::winsec::owner_sid(&opened)? != "S-1-5-18" {
            return Err(crate::Error::integrity(
                "stale service snapshot is not SYSTEM-owned",
            ));
        }
        for subdir in ["input", "output"] {
            let child = dir.join(subdir);
            match std::fs::symlink_metadata(&child) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
                Ok(md) if md.is_dir() && md.file_attributes() & REPARSE == 0 => {}
                Ok(_) => {
                    return Err(crate::Error::integrity(
                        "stale snapshot child is not a plain directory",
                    ))
                }
            }
            for file in std::fs::read_dir(&child)? {
                let file = file?;
                let expected = if subdir == "input" {
                    "job.json"
                } else {
                    "outcome.json"
                };
                if file.file_name() != expected {
                    return Err(crate::Error::integrity(
                        "stale snapshot contains an unexpected file",
                    ));
                }
                let md = std::fs::symlink_metadata(file.path())?;
                if !md.is_file() || md.file_attributes() & REPARSE != 0 {
                    return Err(crate::Error::integrity(
                        "stale snapshot file is not a plain file",
                    ));
                }
                std::fs::remove_file(file.path())?;
            }
            std::fs::remove_dir(child)?;
        }
        std::fs::remove_dir(dir)?;
    }
    Ok(())
}

#[cfg(windows)]
fn set_snapshot_acl(path: &Path, sandbox_sid: &str, sandbox_access: &str) -> crate::Result<()> {
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| crate::Error::isolation_unavailable("SystemRoot is unavailable"))?;
    let sandbox_ace = format!("*{sandbox_sid}:(OI)(CI){sandbox_access}");
    let output = std::process::Command::new(root.join("System32\\icacls.exe"))
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            &sandbox_ace,
        ])
        .output()?;
    if !output.status.success() {
        return Err(crate::Error::isolation_unavailable(
            "failed to restrict hardened job snapshot ACL",
        ));
    }
    set_system_owner(path)?;
    let directory = open_windows_object(
        path,
        true,
        windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
            | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
            | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
    )?;
    if crate::ipc::winsec::owner_sid(&directory)? != "S-1-5-18" {
        return Err(crate::Error::integrity(
            "job snapshot directory is not SYSTEM-owned",
        ));
    }
    let aces = crate::ipc::winsec::dacl_entries(&directory)?;
    let mut has_system = false;
    let mut has_sandbox = false;
    for (allow, sid, _mask) in aces {
        if !allow {
            return Err(crate::Error::integrity(
                "job snapshot ACL has an unexpected deny entry",
            ));
        } else if sid == "S-1-5-18" {
            has_system = true;
        } else if sid == sandbox_sid {
            has_sandbox = true;
        } else {
            return Err(crate::Error::integrity(
                "job snapshot ACL grants an unexpected identity",
            ));
        }
    }
    if !has_system || !has_sandbox {
        return Err(crate::Error::integrity(
            "job snapshot ACL did not read back",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn set_system_owner(path: &Path) -> crate::Result<()> {
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| crate::Error::isolation_unavailable("SystemRoot is unavailable"))?;
    let output = std::process::Command::new(root.join("System32\\icacls.exe"))
        .arg(path)
        .args(["/setowner", "*S-1-5-18"])
        .output()?;
    if !output.status.success() {
        return Err(crate::Error::integrity(
            "failed to assign hardened snapshot ownership to SYSTEM",
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn run_snapshot_as_sandbox(
    jobfile: &Path,
    client_pipe: windows_sys::Win32::Foundation::HANDLE,
    sandbox_sid: &str,
) -> crate::Result<u32> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Foundation::{
        GetLastError, SetHandleInformation, FILETIME, HANDLE, HANDLE_FLAG_INHERIT,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::{
        DeleteProcThreadAttributeList, GetExitCodeProcess, GetProcessTimes,
        InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
        WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTUPINFOEXW,
    };

    #[repr(C)]
    struct ProfileInfo {
        size: u32,
        flags: u32,
        username: *mut u16,
        profile_path: *mut u16,
        default_path: *mut u16,
        server_name: *mut u16,
        policy_path: *mut u16,
        profile: HANDLE,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn LogonUserW(
            username: *const u16,
            domain: *const u16,
            password: *const u16,
            logon_type: u32,
            provider: u32,
            token: *mut HANDLE,
        ) -> i32;
        fn CreateProcessAsUserW(
            token: HANDLE,
            application: *const u16,
            command_line: *mut u16,
            process_attributes: *const c_void,
            thread_attributes: *const c_void,
            inherit_handles: i32,
            creation_flags: u32,
            environment: *const c_void,
            current_directory: *const u16,
            startup_info: *mut c_void,
            process_info: *mut PROCESS_INFORMATION,
        ) -> i32;
    }
    #[link(name = "userenv")]
    unsafe extern "system" {
        fn LoadUserProfileW(token: HANDLE, profile_info: *mut ProfileInfo) -> i32;
        fn UnloadUserProfile(token: HANDLE, profile: HANDLE) -> i32;
        fn CreateEnvironmentBlock(
            environment: *mut *mut c_void,
            token: HANDLE,
            inherit: i32,
        ) -> i32;
        fn DestroyEnvironmentBlock(environment: *mut c_void) -> i32;
    }
    use windows_sys::Win32::System::Pipes::CreatePipe;

    let state_path = super::machine_state_path()?;
    let data_dir = state_path
        .parent()
        .ok_or_else(|| crate::Error::integrity("install state has no parent"))?;
    let secret_path = data_dir.join("sandbox.secret");
    use std::os::windows::fs::MetadataExt;
    let secret_meta = std::fs::symlink_metadata(&secret_path)?;
    if !secret_meta.is_file()
        || secret_meta.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return Err(crate::Error::integrity(
            "sandbox account secret is not a regular file",
        ));
    }
    let secret_file = std::fs::File::open(&secret_path)?;
    let mut system = false;
    let mut admins = false;
    for (allow, sid, _) in crate::ipc::winsec::dacl_entries(&secret_file)? {
        if allow && sid == "S-1-5-18" {
            system = true;
        } else if allow && sid == "S-1-5-32-544" {
            admins = true;
        } else if allow {
            return Err(crate::Error::integrity(
                "sandbox account secret ACL grants an unexpected identity",
            ));
        }
    }
    if !system || !admins {
        return Err(crate::Error::integrity(
            "sandbox account secret ACL did not read back",
        ));
    }
    let password = zeroize::Zeroizing::new(std::fs::read_to_string(&secret_path)?);
    if password.len() != 64 || !password.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(crate::Error::integrity(
            "sandbox account secret has invalid format",
        ));
    }
    let mut password_w: zeroize::Zeroizing<Vec<u16>> = zeroize::Zeroizing::new(
        std::ffi::OsStr::new(&*password)
            .encode_wide()
            .chain([0])
            .collect(),
    );

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut read_raw, mut write_raw): (HANDLE, HANDLE) =
        (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: output handles and security descriptor are valid; both handles are fresh.
    if unsafe { CreatePipe(&mut read_raw, &mut write_raw, &mut sa, 0) } == 0 {
        return Err(crate::Error::internal(format!(
            "CreatePipe(watchdog) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: CreatePipe returned two owned handles.
    let read_end = unsafe { OwnedHandle::from_raw_handle(read_raw as RawHandle) };
    // SAFETY: CreatePipe returned two owned handles.
    let write_end = unsafe { OwnedHandle::from_raw_handle(write_raw as RawHandle) };
    // Only the read end is inherited by the launcher.
    if unsafe { SetHandleInformation(write_raw, HANDLE_FLAG_INHERIT, 0) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(crate::Error::isolation_unavailable(format!(
            "cannot exclude watchdog writer from launcher inheritance (Win32 error {code})"
        )));
    }
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    let job_raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job_raw.is_null() {
        return Err(crate::Error::isolation_unavailable(format!(
            "CreateJobObjectW failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let _job_handle = unsafe { OwnedHandle::from_raw_handle(job_raw as RawHandle) };
    let mut job_limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job_raw,
            JobObjectExtendedLimitInformation,
            (&job_limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(crate::Error::isolation_unavailable(
            "cannot configure kill-on-close launcher job",
        ));
    }
    let handle_list = [read_raw];
    let mut needed = 0usize;
    // SAFETY: sizing call to obtain the required attribute-list buffer size.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut needed) };
    if needed == 0 || needed > 64 * 1024 {
        return Err(crate::Error::internal("cannot size process attribute list"));
    }
    let mut attr_buf = vec![0usize; needed.div_ceil(std::mem::size_of::<usize>())];
    let attr = attr_buf.as_mut_ptr().cast();
    // SAFETY: attr_buf is aligned and sized as reported by the sizing call.
    if unsafe { InitializeProcThreadAttributeList(attr, 2, 0, &mut needed) } == 0 {
        return Err(crate::Error::internal(
            "InitializeProcThreadAttributeList failed",
        ));
    }
    struct AttrGuard(*mut c_void);
    impl Drop for AttrGuard {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.0.cast()) }
        }
    }
    let _attr_guard = AttrGuard(attr);
    // SAFETY: one valid inherited handle, stored in handle_list for the call.
    if unsafe {
        UpdateProcThreadAttribute(
            attr,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handle_list.as_ptr().cast(),
            std::mem::size_of_val(&handle_list),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } == 0
    {
        return Err(crate::Error::internal(
            "cannot restrict inherited launcher handles",
        ));
    }
    let job_list = [job_raw];
    // SAFETY: the per-launch kill-on-close job remains owned through process creation.
    if unsafe {
        UpdateProcThreadAttribute(
            attr,
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            job_list.as_ptr().cast(),
            std::mem::size_of_val(&job_list),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } == 0
    {
        return Err(crate::Error::isolation_unavailable(
            "cannot bind launcher to kill-on-close containment job",
        ));
    }
    let exe = std::env::current_exe()?;
    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();
    let raw_handle = read_raw as usize;
    let cmd = format!(
        "{} sandbox launch {} --watchdog {}",
        quote_windows_arg(&exe.to_string_lossy()),
        quote_windows_arg(&jobfile.to_string_lossy()),
        raw_handle
    );
    let mut cmd_w: Vec<u16> = std::ffi::OsStr::new(&cmd)
        .encode_wide()
        .chain([0])
        .collect();
    let mut username: Vec<u16> = std::ffi::OsStr::new("f2c-sandbox")
        .encode_wide()
        .chain([0])
        .collect();
    let mut token_raw: HANDLE = std::ptr::null_mut();
    // SAFETY: output token pointer is valid; LOGON32_LOGON_BATCH is granted
    // only to the protected f2c-sandbox SID during install.
    if unsafe {
        LogonUserW(
            username.as_ptr(),
            std::ptr::null(),
            password_w.as_mut_ptr(),
            4,
            0,
            &mut token_raw,
        )
    } == 0
    {
        let code = unsafe { GetLastError() };
        return Err(crate::Error::isolation_unavailable(format!(
            "LogonUserW(batch) failed with Win32 error {code}"
        )));
    }
    // SAFETY: LogonUserW returned a fresh token handle.
    let _token = unsafe { OwnedHandle::from_raw_handle(token_raw as RawHandle) };
    let mut profile = ProfileInfo {
        size: std::mem::size_of::<ProfileInfo>() as u32,
        flags: 1,
        username: username.as_mut_ptr(),
        profile_path: std::ptr::null_mut(),
        default_path: std::ptr::null_mut(),
        server_name: std::ptr::null_mut(),
        policy_path: std::ptr::null_mut(),
        profile: std::ptr::null_mut(),
    };
    // Batch logon plus an explicit profile load lets the service verify profile
    // and AppContainer creation without granting interactive logon.
    if unsafe { LoadUserProfileW(token_raw, &mut profile) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(crate::Error::isolation_unavailable(format!(
            "LoadUserProfileW failed with Win32 error {code}"
        )));
    }
    let mut retained_process = None;
    let mut containment_confirmed = true;
    let mut active_marker = None;
    let launch_result = (|| {
        let mut environment = std::ptr::null_mut();
        // SAFETY: environment is a writable output pointer for the user token.
        if unsafe { CreateEnvironmentBlock(&mut environment, token_raw, 0) } == 0 {
            let code = unsafe { GetLastError() };
            return Err(crate::Error::isolation_unavailable(format!(
                "CreateEnvironmentBlock failed with Win32 error {code}"
            )));
        }
        struct EnvironmentGuard(*mut c_void);
        impl Drop for EnvironmentGuard {
            fn drop(&mut self) {
                unsafe { DestroyEnvironmentBlock(self.0) };
            }
        }
        let _environment_guard = EnvironmentGuard(environment);
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attr.cast();
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let flags = EXTENDED_STARTUPINFO_PRESENT
            | CREATE_UNICODE_ENVIRONMENT
            | CREATE_NO_WINDOW
            | CREATE_SUSPENDED;
        let snapshot_dir = jobfile
            .parent()
            .ok_or_else(|| crate::Error::integrity("snapshot job has no directory"))?;
        active_marker = Some(ActiveLaunchGuard::create(sandbox_sid, snapshot_dir)?);
        // SAFETY: token is a primary batch-logon token, its profile/environment
        // are loaded, and the handle list contains only the watchdog read end.
        if unsafe {
            CreateProcessAsUserW(
                token_raw,
                exe_w.as_ptr(),
                cmd_w.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                flags,
                environment,
                std::ptr::null(),
                (&mut startup.StartupInfo
                    as *mut windows_sys::Win32::System::Threading::STARTUPINFOW)
                    .cast::<c_void>(),
                &mut pi,
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            if let Some(marker) = active_marker.as_mut() {
                if marker.clear().is_err() {
                    LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
                }
            }
            return Err(crate::Error::isolation_unavailable(format!(
                "CreateProcessAsUserW failed with Win32 error {code}"
            )));
        }
        drop(read_end);
        retained_process = Some(unsafe { OwnedHandle::from_raw_handle(pi.hProcess as RawHandle) });
        let process = retained_process
            .as_ref()
            .expect("launcher process handle is present");
        let thread = unsafe { OwnedHandle::from_raw_handle(pi.hThread as RawHandle) };
        let mut created = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exited = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        if unsafe {
            GetProcessTimes(
                process.as_raw_handle() as HANDLE,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            if let Err(error) =
                terminate_launcher_and_confirm(process.as_raw_handle() as HANDLE, 0xE004)
            {
                containment_confirmed = false;
                return Err(crate::Error::isolation_unavailable(format!(
                    "GetProcessTimes failed with Win32 error {code}; containment is unconfirmed: {error}"
                )));
            }
            active_marker.as_mut().expect("marker created").clear()?;
            return Err(crate::Error::isolation_unavailable(format!(
                "GetProcessTimes failed with Win32 error {code}; launcher termination was confirmed"
            )));
        }
        let creation_time_100ns =
            (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        if let Err(error) = active_marker
            .as_mut()
            .expect("marker created")
            .record_process(pi.dwProcessId, creation_time_100ns)
        {
            if let Err(termination) =
                terminate_launcher_and_confirm(process.as_raw_handle() as HANDLE, 0xE005)
            {
                containment_confirmed = false;
                return Err(crate::Error::isolation_unavailable(format!(
                    "cannot persist launcher identity ({error}); containment is unconfirmed: {termination}"
                )));
            }
            active_marker.as_mut().expect("marker created").clear()?;
            return Err(crate::Error::isolation_unavailable(format!(
                "cannot persist launcher identity ({error}); launcher termination was confirmed"
            )));
        }
        // The process is assigned to the kill-on-close job while suspended;
        // resume only after the durable PID and creation time are stored.
        if unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } == u32::MAX {
            let code = unsafe { GetLastError() };
            if let Err(termination) =
                terminate_launcher_and_confirm(process.as_raw_handle() as HANDLE, 0xE006)
            {
                containment_confirmed = false;
                return Err(crate::Error::isolation_unavailable(format!(
                    "ResumeThread failed with Win32 error {code}; containment is unconfirmed: {termination}"
                )));
            }
            active_marker.as_mut().expect("marker created").clear()?;
            return Err(crate::Error::isolation_unavailable(format!(
                "ResumeThread failed with Win32 error {code}; launcher termination was confirmed"
            )));
        }
        drop(thread);
        let mut watchdog = Some(write_end);
        let mut disconnected_at = None;
        loop {
            let waited = unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 100) };
            if waited == 0 {
                break;
            }
            if waited != windows_sys::Win32::Foundation::WAIT_TIMEOUT {
                let code = unsafe { GetLastError() };
                watchdog.take();
                if let Err(termination) =
                    terminate_launcher_and_confirm(process.as_raw_handle() as HANDLE, 0xE003)
                {
                    containment_confirmed = false;
                    return Err(crate::Error::isolation_unavailable(format!(
                        "WaitForSingleObject(launcher) failed with Win32 error {code}; containment is unconfirmed: {termination}"
                    )));
                }
                return Err(crate::Error::internal(format!(
                    "WaitForSingleObject(launcher) failed with Win32 error {code}; launcher termination was confirmed"
                )));
            }
            match client_pipe_read(client_pipe) {
                ClientPipeRead::Idle => {}
                ClientPipeRead::Disconnected | ClientPipeRead::UnexpectedData => {
                    // The request is one line only. Any later bytes are an invalid suffix,
                    // and a disconnected client must not keep the launcher alive with bytes
                    // left buffered in the pipe. Closing the watchdog writer asks the
                    // launcher to terminate its Job Object; the explicit process termination
                    // below is the bounded fallback if that path stalls.
                    watchdog.take();
                    disconnected_at.get_or_insert_with(std::time::Instant::now);
                }
                ClientPipeRead::Failed(code) => {
                    watchdog.take();
                    if let Err(termination) =
                        terminate_launcher_and_confirm(process.as_raw_handle() as HANDLE, 0xE003)
                    {
                        containment_confirmed = false;
                        return Err(crate::Error::isolation_unavailable(format!(
                            "cannot track hardened client pipe (Win32 error {code}); containment is unconfirmed: {termination}"
                        )));
                    }
                    return Err(crate::Error::isolation_unavailable(format!(
                        "cannot track hardened client pipe (Win32 error {code}); launcher termination was confirmed"
                    )));
                }
            }
            if disconnected_at.is_some_and(|at| at.elapsed() > std::time::Duration::from_secs(2)) {
                watchdog.take();
                if let Err(termination) =
                    terminate_launcher_and_confirm(process.as_raw_handle() as HANDLE, 0xE002)
                {
                    containment_confirmed = false;
                    return Err(crate::Error::isolation_unavailable(format!(
                        "launcher cancellation did not complete; containment is unconfirmed: {termination}"
                    )));
                }
                break;
            }
        }
        let mut exit = 1u32;
        if unsafe { GetExitCodeProcess(process.as_raw_handle() as HANDLE, &mut exit) } == 0 {
            return Err(crate::Error::internal(
                "GetExitCodeProcess(launcher) failed",
            ));
        }
        Ok(exit)
    })();
    if !containment_confirmed {
        // Keep the process and token handles, plus the loaded profile, until
        // the service exits; do not unload a profile that a live process may
        // still be using. The service's global flag refuses later LAUNCH jobs.
        LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
        if let Some(process) = retained_process.take() {
            std::mem::forget(process);
        }
        std::mem::forget(_token);
        if let Some(marker) = active_marker.as_mut() {
            marker.retain();
        }
        return launch_result;
    }
    // SAFETY: the launcher process was observed signaled or forced termination
    // was confirmed before unloading the sandbox account profile.
    if unsafe { UnloadUserProfile(token_raw, profile.profile) } == 0 {
        let code = unsafe { GetLastError() };
        LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
        if let Some(marker) = active_marker.as_mut() {
            marker.retain();
        }
        return Err(crate::Error::isolation_unavailable(format!(
            "UnloadUserProfile failed with Win32 error {code}"
        )));
    }
    if let Some(marker) = active_marker.as_mut() {
        marker.clear()?;
    }
    drop(username);
    drop(password_w);
    launch_result
}

#[cfg(windows)]
enum ClientPipeRead {
    Idle,
    Disconnected,
    UnexpectedData,
    Failed(u32),
}

/// Consume any post-request bytes and observe the broken-pipe error after EOF.
/// `PeekNamedPipe` cannot do this: buffered suffix data can remain readable
/// after the peer has closed and falsely look like a live client.
#[cfg(windows)]
#[allow(unsafe_code)]
fn client_pipe_read(pipe: windows_sys::Win32::Foundation::HANDLE) -> ClientPipeRead {
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::ReadFile;

    let mut byte = 0u8;
    let mut read = 0u32;
    // The server pipe was placed in nonblocking byte mode before the first
    // request read. One byte is enough to detect and reject every suffix.
    if unsafe {
        ReadFile(
            pipe,
            (&mut byte as *mut u8).cast(),
            1,
            &mut read,
            std::ptr::null_mut(),
        )
    } != 0
    {
        return if read == 0 {
            ClientPipeRead::Disconnected
        } else {
            ClientPipeRead::UnexpectedData
        };
    }
    match unsafe { GetLastError() } {
        ERROR_NO_DATA => ClientPipeRead::Idle,
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED => ClientPipeRead::Disconnected,
        code => ClientPipeRead::Failed(code),
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn terminate_launcher_and_confirm(
    process: windows_sys::Win32::Foundation::HANDLE,
    exit_code: u32,
) -> std::result::Result<(), String> {
    use windows_sys::Win32::Foundation::{GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

    termination_confirmation(
        || {
            if unsafe { TerminateProcess(process, exit_code) } == 0 {
                Err(unsafe { GetLastError() })
            } else {
                Ok(())
            }
        },
        |timeout_ms| match unsafe { WaitForSingleObject(process, timeout_ms) } {
            WAIT_OBJECT_0 => ProcessWait::Signaled,
            WAIT_TIMEOUT => ProcessWait::TimedOut,
            _ => ProcessWait::Failed(unsafe { GetLastError() }),
        },
    )
}

#[cfg(any(windows, test))]
fn quote_windows_arg(arg: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            slashes += 1;
        } else if ch == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
            out.push(ch);
            slashes = 0;
        } else {
            out.push_str(&"\\".repeat(slashes));
            out.push(ch);
            slashes = 0;
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

#[cfg(windows)]
fn launch_windows_request(
    client_pipe: windows_sys::Win32::Foundation::HANDLE,
    job_dir: &str,
    peer_sid: &[u8],
    sandbox_sid: &str,
) -> crate::Result<()> {
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ};

    let dir = open_user_job_dir(job_dir, peer_sid)?;
    let (snapshot_dir, _snapshot_handle) = snapshot_job(&dir, peer_sid, sandbox_sid)?;
    let jobfile = snapshot_dir.path().join("job.json");
    let exit = run_snapshot_as_sandbox(&jobfile, client_pipe, sandbox_sid)?;
    if exit != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "hardened launcher exited with code {exit}"
        )));
    }
    let outcome_path = snapshot_dir.path().join("output").join("outcome.json");
    use std::os::windows::fs::MetadataExt;
    let outcome = open_windows_object(&outcome_path, false, FILE_SHARE_READ)?;
    let metadata = outcome.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || crate::sandbox::link_count(&metadata, &outcome_path)? != 1
        || metadata.len() > super::protocol::MAX_OUTCOME_BYTES as u64
    {
        return Err(crate::Error::integrity(
            "launcher outcome is unsafe or oversized",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    outcome
        .take((super::protocol::MAX_OUTCOME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > super::protocol::MAX_OUTCOME_BYTES {
        return Err(crate::Error::integrity(
            "launcher outcome exceeded the hardened outcome limit",
        ));
    }
    super::protocol::decode_outcome(&bytes)?;
    let output = dir.path.join("outcome.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(output)
        .map_err(|e| {
            crate::Error::integrity(format!("cannot safely publish hardened outcome: {e}"))
        })?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(super) fn launch_hidden(jobfile: &Path, watchdog: Option<u64>) -> crate::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, FILE_ATTRIBUTE_REPARSE_POINT};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
    let watchdog = watchdog
        .ok_or_else(|| crate::Error::rejected("hardened launcher requires a watchdog handle"))?;
    let handle_value = watchdog as usize;
    let handle = handle_value as HANDLE;
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(crate::Error::rejected(
            "hardened launcher watchdog handle is invalid",
        ));
    }
    let watchdog_thread = std::thread::spawn(move || {
        let handle = handle_value as HANDLE;
        loop {
            let mut byte = 0u8;
            let mut read = 0u32;
            // SAFETY: the inherited anonymous-pipe handle remains owned by this thread.
            let ok = unsafe {
                ReadFile(
                    handle,
                    (&mut byte as *mut u8).cast(),
                    1,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                // SAFETY: terminating the launcher closes the AppContainer job handle,
                // whose kill-on-close policy terminates the untrusted process tree.
                unsafe { TerminateProcess(GetCurrentProcess(), 0xE001) };
                break;
            }
        }
    });
    let metadata = std::fs::symlink_metadata(jobfile)?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > super::protocol::MAX_JOB_BYTES as u64
    {
        return Err(crate::Error::integrity(
            "hardened launcher job file is unsafe or oversized",
        ));
    }
    let bytes = std::fs::read(jobfile)?;
    let job = super::protocol::decode_job(&bytes)?;
    use crate::isolation::SandboxBackend;
    let report = crate::sandbox::windows::AppContainer::default().probe();
    if !report.available {
        return Err(crate::Error::isolation_unavailable(format!(
            "AppContainer controls are unavailable: {}",
            report.detail
        )));
    }
    // The standard AppContainer does not yet enable LPAC, and the hardened
    // service has no verified per-profile WFP controls. Never start package code
    // until both mandatory controls have real read-back and self-test evidence.
    let _ = job;
    drop(watchdog_thread);
    Err(crate::Error::isolation_unavailable(
        "LPAC and per-job WFP controls are unverified; package code was not started",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_decoder_requires_bounded_newline_terminated_json() {
        let response = decode_response(b"{\"ok\":false,\"service_running\":true,\"probe_available\":false,\"detail\":\"not ready\"}\n").unwrap();
        assert!(!response.ok);
        assert!(decode_response(b"{\"ok\":true}").is_err());
        assert!(decode_response(&vec![b'x'; MAX_REQUEST]).is_err());
    }

    fn marker(pid: Option<u32>, creation_time_100ns: Option<u64>) -> ActiveLaunchMarker {
        ActiveLaunchMarker {
            version: 1,
            launch_id: "a".repeat(64),
            sandbox_sid: "S-1-5-21-1-2-3-1001".into(),
            snapshot_dir: r"C:\ProgramData\f2c\jobs\launch-1".into(),
            pid,
            creation_time_100ns,
        }
    }

    #[test]
    fn active_launch_marker_rejects_corrupt_partial_and_unpaired_identity() {
        let valid = serde_json::to_vec(&marker(None, None)).unwrap();
        assert!(decode_active_launch_marker(&valid).is_ok());
        assert!(decode_active_launch_marker(b"{").is_err());
        assert!(decode_active_launch_marker(&vec![b'x'; ACTIVE_LAUNCH_MARKER_MAX + 1]).is_err());
        let partial = serde_json::to_vec(&marker(Some(42), None)).unwrap();
        assert!(decode_active_launch_marker(&partial).is_err());
        let invalid = serde_json::to_vec(&marker(Some(0), Some(10))).unwrap();
        assert!(decode_active_launch_marker(&invalid).is_err());
    }

    #[test]
    fn restart_sweeps_only_when_persistent_marker_is_proven_absent() {
        assert!(may_sweep_after_marker_check::<()>(&Ok(false)));
        assert!(!may_sweep_after_marker_check::<()>(&Ok(true)));
        assert!(!may_sweep_after_marker_check::<()>(&Err(())));
    }

    #[test]
    fn windows_path_comparison_handles_case_and_verbatim_prefix_only() {
        assert!(same_windows_path(
            Path::new(r"C:\Users\Tester\stage"),
            Path::new(r"c:\users\tester\STAGE")
        ));
        assert!(same_windows_path(
            Path::new(r"\\?\C:\Users\Tester\stage"),
            Path::new(r"C:\Users\Tester\stage")
        ));
        assert!(!same_windows_path(
            Path::new(r"C:\Users\Tester\stage"),
            Path::new(r"C:\Users\Tester\..\Other")
        ));
    }

    #[test]
    fn launcher_error_details_are_bounded() {
        assert_eq!(bounded_error_detail(&"x".repeat(300)).len(), 256);
        assert_eq!(bounded_error_detail("safe failure"), "safe failure");
    }

    #[test]
    fn termination_is_not_confirmed_by_api_success_without_signal() {
        let result = termination_confirmation(
            || Ok(()),
            |timeout| {
                assert_eq!(timeout, 5_000);
                ProcessWait::TimedOut
            },
        );
        assert!(result.unwrap_err().contains("did not exit"));
    }

    #[test]
    fn already_signaled_process_is_safe_when_terminate_races_exit() {
        let result = termination_confirmation(|| Err(5), |_| ProcessWait::Signaled);
        assert!(result.is_ok());
    }

    #[test]
    fn termination_wait_failure_remains_an_explicit_containment_error() {
        let result = termination_confirmation(|| Ok(()), |_| ProcessWait::Failed(6));
        assert!(result.unwrap_err().contains("launcher exit is unconfirmed"));
    }

    #[test]
    fn terminate_api_failure_and_timeout_are_both_reported() {
        let result = termination_confirmation(|| Err(5), |_| ProcessWait::TimedOut);
        let error = result.unwrap_err();
        assert!(error.contains("TerminateProcess failed with Win32 error 5"));
        assert!(error.contains("did not exit within 5000 ms"));
    }

    #[test]
    fn windows_command_arguments_are_quoted_without_shell_interpretation() {
        assert_eq!(
            quote_windows_arg(r"C:\Program Files\tool.exe"),
            r#""C:\Program Files\tool.exe""#
        );
        assert_eq!(quote_windows_arg(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[test]
    fn only_installer_uid_is_accepted_and_sandbox_identity_is_denied() {
        assert!(peer_uid_allowed(1000, 1000, 999));
        assert!(!peer_uid_allowed(1001, 1000, 999));
        assert!(!peer_uid_allowed(999, 1000, 999));
        assert!(!peer_uid_allowed(0, 1000, 999));
    }

    #[cfg(windows)]
    #[test]
    fn windows_peer_auth_rejects_foreign_and_appcontainer_tokens() {
        assert!(windows_peer_allowed(b"installer", b"installer", false));
        assert!(!windows_peer_allowed(b"other", b"installer", false));
        assert!(!windows_peer_allowed(b"installer", b"installer", true));
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn test_pipe() -> (
        std::os::windows::io::OwnedHandle,
        std::os::windows::io::OwnedHandle,
    ) {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
        use windows_sys::Win32::Foundation::{
            GetLastError, ERROR_PIPE_CONNECTED, GENERIC_WRITE, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
        };
        use windows_sys::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        };

        static PIPE_SEQUENCE: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let name = format!(
            r"\\.\pipe\f2c-watchdog-test-{}-{}",
            std::process::id(),
            PIPE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let name_w: Vec<u16> = OsStr::new(&name).encode_wide().chain([0]).collect();
        let server_raw = unsafe {
            CreateNamedPipeW(
                name_w.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
                1,
                1024,
                1024,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(server_raw, INVALID_HANDLE_VALUE);
        let server = unsafe { OwnedHandle::from_raw_handle(server_raw as RawHandle) };
        let client_raw = unsafe {
            CreateFileW(
                name_w.as_ptr(),
                GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        let connected = unsafe { ConnectNamedPipe(server_raw, std::ptr::null_mut()) };
        assert!(connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED);
        assert_ne!(client_raw, INVALID_HANDLE_VALUE, "Win32 error {}", unsafe {
            GetLastError()
        });
        let client = unsafe { OwnedHandle::from_raw_handle(client_raw as RawHandle) };
        (server, client)
    }

    #[cfg(windows)]
    #[test]
    fn client_pipe_read_reports_idle_connected_peer() {
        use std::os::windows::io::AsRawHandle;

        let (server, _client) = test_pipe();
        assert!(matches!(
            client_pipe_read(server.as_raw_handle() as _),
            ClientPipeRead::Idle
        ));
    }

    #[cfg(windows)]
    #[test]
    fn client_pipe_read_observes_disconnect_without_suffix() {
        use std::os::windows::io::AsRawHandle;

        let (server, client) = test_pipe();
        drop(client);
        assert!(matches!(
            client_pipe_read(server.as_raw_handle() as _),
            ClientPipeRead::Disconnected
        ));
    }

    #[cfg(windows)]
    #[test]
    #[allow(unsafe_code)]
    fn client_pipe_read_drains_suffix_then_observes_disconnect() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::WriteFile;

        let (server, client) = test_pipe();
        let mut written = 0u32;
        let byte = b'x';
        assert_ne!(
            unsafe {
                WriteFile(
                    client.as_raw_handle() as _,
                    (&byte as *const u8).cast(),
                    1,
                    &mut written,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(written, 1);
        drop(client);
        assert!(matches!(
            client_pipe_read(server.as_raw_handle() as _),
            ClientPipeRead::UnexpectedData
        ));
        assert!(matches!(
            client_pipe_read(server.as_raw_handle() as _),
            ClientPipeRead::Disconnected
        ));
    }

    #[test]
    fn unauthorized_peer_launch_does_not_touch_filesystem() {
        let req = Request {
            op: "LAUNCH".into(),
            job_dir: Some("/no/such/path".into()),
        };
        let r = dispatch(req, 1001, 1000, 999);
        assert!(!r.ok);
        assert_eq!(r.detail, "peer uid is not authorized");
    }

    #[test]
    fn malformed_or_unterminated_request_is_rejected_without_dispatch() {
        assert!(decode_request(b"{ definitely not json }\n").is_err());
        assert!(decode_request(b"{\"op\":\"STATUS\"}").is_err());
        let oversized = vec![b'a'; MAX_REQUEST];
        assert!(decode_request(&oversized).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn silent_linux_peer_hits_absolute_request_deadline() {
        let (mut server, _client) = std::os::unix::net::UnixStream::pair().unwrap();
        let started = std::time::Instant::now();
        assert!(read_request_deadline(&mut server, std::time::Duration::from_millis(40)).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_launch_still_refuses_before_execution_when_controls_are_absent() {
        let td = tempfile::tempdir().unwrap();
        let canonical = td.path().canonicalize().unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&canonical).unwrap());
        let request = Request {
            op: "LAUNCH".into(),
            job_dir: Some(canonical.to_string_lossy().into_owned()),
        };
        let reply = dispatch(request, uid, uid, u32::MAX);
        assert!(!reply.ok);
        assert!(!reply.probe_available);
        assert!(reply.detail.contains("job was not started"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_refuses_job_dir_owned_by_a_different_uid() {
        let td = tempfile::tempdir().unwrap();
        let canonical = td.path().canonicalize().unwrap();
        assert!(validate_job_dir(&canonical, u32::MAX).is_err());
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&canonical).unwrap());
        assert!(validate_job_dir(&canonical, uid).is_ok());
        let link = td.path().with_extension("hardened-link");
        std::os::unix::fs::symlink(&canonical, &link).unwrap();
        assert!(validate_job_dir(&link, uid).is_err());
        std::fs::remove_file(link).unwrap();
    }
}
