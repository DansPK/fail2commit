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
#[cfg(any(windows, test))]
const RESPONSE_ACK: &[u8] = b"F2C-RESPONSE-READ\n";

#[cfg(any(target_os = "linux", windows, test))]
#[derive(Debug, Serialize, Deserialize, Default)]
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
    #[serde(default = "default_true")]
    containment_confirmed: bool,
    detail: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    version: u32,
    launch_id: String,
    launcher_pid: u32,
    launcher_creation_time_100ns: u64,
    package_sid: String,
    profile_name: String,
    network: crate::isolation::NetworkMode,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareAck {
    version: u32,
    launch_id: String,
    package_sid: String,
    ready: bool,
    detail: String,
}

#[cfg(any(windows, test))]
const MAX_PREPARE_FRAME: usize = 4096;

#[cfg(any(target_os = "linux", windows, test))]
fn default_true() -> bool {
    true
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
    let stage_root = paths.cache_dir.join("sandbox-stage");
    let encoded = super::protocol::encode_hardened_job(job, &stage_root)?;
    std::fs::write(&jobfile, encoded)?;
    let job_dir = temp.path().to_string_lossy().into_owned();
    let request = Request {
        op: "LAUNCH".into(),
        job_dir: Some(job_dir),
    };
    let mut pipe = open_service_pipe(&pipe_name)?;
    let result = crate::sandbox::windows::with_hardened_job_grants(job, sandbox_sid, || {
        let result = (|| {
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
        })();
        match result {
            Ok(outcome) => crate::sandbox::windows::HardenedGrantAction::Complete(Ok(outcome)),
            Err(error) => {
                // If the response itself was lost, the service may still have a
                // live tree. The durable marker is authoritative for cleanup.
                let contained = launch_recovery_pending().unwrap_or(true);
                if contained {
                    crate::sandbox::windows::HardenedGrantAction::ContainmentUnconfirmed(error)
                } else {
                    crate::sandbox::windows::HardenedGrantAction::Complete(Err(error))
                }
            }
        }
    });
    result
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn open_service_pipe(name: &str) -> crate::Result<std::fs::File> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    // The service uses one synchronous pipe instance and recreates it after
    // each request. SCM can already report Running while that next instance
    // is not yet listening, so opening the path once creates a startup/race
    // failure. Bound the wait and retry only absence/busy errors; preserve all
    // other errors as fail-closed transport failures.
    let wide: Vec<u16> = OsStr::new(name).encode_wide().chain([0]).collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
        {
            Ok(pipe) => return Ok(pipe),
            Err(error) => {
                let code = error.raw_os_error().unwrap_or_default() as u32;
                if !matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PIPE_BUSY)
                    || std::time::Instant::now() >= deadline
                {
                    return Err(crate::Error::isolation_unavailable(format!(
                        "open hardened service pipe: {error}"
                    )));
                }
                // WaitNamedPipe may itself report the pipe absent; in that
                // case retry until the same fixed deadline rather than
                // treating a transient between-instance gap as fatal.
                let _ = unsafe { WaitNamedPipeW(wide.as_ptr(), 100) };
            }
        }
    }
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
    let mut reader = BufReader::new(&mut *pipe);
    let mut line = Vec::new();
    reader
        .by_ref()
        .take(MAX_REQUEST as u64)
        .read_until(b'\n', &mut line)?;
    let reply = decode_response(&line)?;
    // The server disconnects only after it sees this private completion frame,
    // proving the entire bounded response line was consumed by the client.
    drop(reader);
    pipe.write_all(RESPONSE_ACK)?;
    pipe.flush()?;
    Ok(reply)
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
        containment_confirmed: true,
        detail: detail.into(),
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PipeConnectDecision {
    InitialAvailability,
    Connected,
    Listening,
    PreviousClientClosed,
    Unexpected,
}

#[cfg(any(windows, test))]
fn classify_pipe_connect(
    first_call: bool,
    call_succeeded: bool,
    error: u32,
    pipe_connected: u32,
    pipe_listening: u32,
    no_data: u32,
) -> PipeConnectDecision {
    if call_succeeded {
        if first_call {
            PipeConnectDecision::InitialAvailability
        } else {
            PipeConnectDecision::Unexpected
        }
    } else if error == pipe_connected {
        PipeConnectDecision::Connected
    } else if error == pipe_listening {
        PipeConnectDecision::Listening
    } else if error == no_data {
        PipeConnectDecision::PreviousClientClosed
    } else {
        PipeConnectDecision::Unexpected
    }
}

#[cfg(any(windows, test))]
fn valid_response_ack(bytes: &[u8]) -> bool {
    bytes == RESPONSE_ACK
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
        let mut reader = BufReader::new(file);
        reader
            .by_ref()
            .take(MAX_REQUEST as u64)
            .read_until(b'\n', &mut line)?;
        let reply = decode_response(&line)?;
        let mut file = reader.into_inner();
        file.write_all(RESPONSE_ACK)?;
        file.flush()?;
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
    let marker = decode_active_launch_marker(&bytes).map_err(crate::Error::integrity)?;
    validate_marker_snapshot_root(&marker)?;
    Ok(true)
}

#[cfg(windows)]
fn validate_marker_snapshot_root(marker: &ActiveLaunchMarker) -> crate::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let root_path = Path::new(&marker.snapshot_dir);
    if !root_path.is_absolute()
        || !root_path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("job-"))
    {
        return Err(crate::Error::integrity(
            "active launch snapshot path is not a service job root",
        ));
    }
    let canonical = root_path.canonicalize()?;
    let jobs_path = active_launch_marker_path()?
        .parent()
        .ok_or_else(|| crate::Error::integrity("active marker has no data directory"))?
        .join("jobs")
        .canonicalize()?;
    if !same_windows_path(&canonical, root_path)
        || !canonical
            .parent()
            .is_some_and(|parent| same_windows_path(parent, &jobs_path))
    {
        return Err(crate::Error::integrity(
            "active launch snapshot path escaped the service jobs directory",
        ));
    }
    let directory = open_windows_object(
        &canonical,
        true,
        windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ,
    )?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        || crate::ipc::winsec::owner_sid(&directory)? != "S-1-5-18"
    {
        return Err(crate::Error::integrity(
            "active launch snapshot root failed ownership or object checks",
        ));
    }
    let mut has_system = false;
    let mut has_sandbox = false;
    for (allow, sid, _) in crate::ipc::winsec::dacl_entries(&directory)? {
        if !allow {
            return Err(crate::Error::integrity(
                "active launch snapshot root has an unexpected deny ACL",
            ));
        } else if sid == "S-1-5-18" {
            has_system = true;
        } else if sid == marker.sandbox_sid {
            has_sandbox = true;
        } else {
            return Err(crate::Error::integrity(
                "active launch snapshot root grants an unexpected identity",
            ));
        }
    }
    if !has_system || !has_sandbox {
        return Err(crate::Error::integrity(
            "active launch snapshot root ACL did not read back",
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn launch_recovery_pending() -> crate::Result<bool> {
    active_launch_pending()
}

#[cfg(any(windows, test))]
pub(super) fn marker_blocks_cleanup<T>(check: &std::result::Result<bool, T>) -> bool {
    !matches!(check, Ok(false))
}

#[cfg(any(windows, test))]
fn snapshot_root_for_jobfile(jobfile: &Path) -> Option<std::path::PathBuf> {
    jobfile.parent()?.parent().map(Path::to_path_buf)
}

#[cfg(any(windows, test))]
fn retain_snapshot_if_unconfirmed(
    snapshot: tempfile::TempDir,
    containment_unconfirmed: bool,
) -> Option<std::path::PathBuf> {
    containment_unconfirmed.then(|| snapshot.keep())
}

#[cfg(any(windows, test))]
fn process_tree_barrier(
    mut query_active: impl FnMut() -> std::result::Result<u32, u32>,
    terminate_tree: impl FnOnce() -> std::result::Result<(), u32>,
    mut wait_interval: impl FnMut(),
    max_polls: usize,
) -> std::result::Result<bool, String> {
    let mut count = query_active().map_err(|code| {
        format!("cannot query launcher job active-process count (Win32 error {code})")
    })?;
    if count == 0 {
        return Ok(false);
    }
    let termination_error = terminate_tree().err();
    for _ in 0..max_polls {
        count = query_active().map_err(|code| match termination_error {
            Some(terminate) => format!(
                "TerminateJobObject failed with Win32 error {terminate}; process count query failed with Win32 error {code}"
            ),
            None => format!("cannot confirm launcher job termination (Win32 error {code})"),
        })?;
        if count == 0 {
            return Ok(true);
        }
        wait_interval();
    }
    Err(format!(
        "launcher job still has {count} active process(es) after {max_polls} bounded polls"
    ))
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

    fn launch_id(&self) -> &str {
        &self.launch_id
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
enum PrepareRead {
    Pending,
    Request(PrepareRequest),
    Invalid(String),
}

#[cfg(any(windows, test))]
fn accumulate_prepare_frame(
    buffer: &mut Vec<u8>,
    fragment: &[u8],
) -> std::result::Result<Option<Vec<u8>>, String> {
    if buffer.len().saturating_add(fragment.len()) > MAX_PREPARE_FRAME + 4 {
        return Err("preparation frame exceeds its bound".into());
    }
    buffer.extend_from_slice(fragment);
    if buffer.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_le_bytes(buffer[..4].try_into().expect("four-byte length")) as usize;
    if length == 0 || length > MAX_PREPARE_FRAME {
        return Err("preparation frame size is invalid".into());
    }
    let expected = length + 4;
    if buffer.len() < expected {
        return Ok(None);
    }
    if buffer.len() != expected {
        return Err("preparation frame contains a duplicate or trailing suffix".into());
    }
    let payload = buffer[4..].to_vec();
    buffer.clear();
    Ok(Some(payload))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_prepare_request(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    buffer: &mut Vec<u8>,
) -> PrepareRead {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut available = 0u32;
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
        return PrepareRead::Invalid(format!(
            "cannot inspect launcher preparation pipe (Win32 error {})",
            unsafe { GetLastError() }
        ));
    }
    if available == 0 {
        return PrepareRead::Pending;
    }
    let capacity = MAX_PREPARE_FRAME + 4 - buffer.len();
    if capacity == 0 {
        return PrepareRead::Invalid("launcher preparation frame exceeded its bound".into());
    }
    let mut fragment = vec![0u8; (available as usize).min(4096).min(capacity)];
    let mut read = 0u32;
    if unsafe {
        ReadFile(
            pipe,
            fragment.as_mut_ptr().cast(),
            fragment.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        )
    } == 0
        || read == 0
    {
        return PrepareRead::Invalid("cannot read launcher preparation frame fragment".into());
    }
    fragment.truncate(read as usize);
    let payload = match accumulate_prepare_frame(buffer, &fragment) {
        Ok(None) => return PrepareRead::Pending,
        Ok(Some(payload)) => payload,
        Err(detail) => return PrepareRead::Invalid(detail),
    };
    match decode_prepare_request(&payload) {
        Ok(request) => PrepareRead::Request(request),
        Err(error) => PrepareRead::Invalid(error.message),
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn write_prepare_ack(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    ack: &PrepareAck,
) -> crate::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let payload = serde_json::to_vec(ack)
        .map_err(|_| crate::Error::internal("cannot encode WFP preparation response"))?;
    if payload.is_empty() || payload.len() > MAX_PREPARE_FRAME {
        return Err(crate::Error::integrity(
            "WFP preparation response exceeded its frame limit",
        ));
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    let mut written = 0u32;
    if unsafe {
        WriteFile(
            pipe,
            frame.as_ptr().cast(),
            frame.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    } == 0
        || written as usize != frame.len()
    {
        return Err(crate::Error::isolation_unavailable(
            "WFP preparation response could not be delivered",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn is_appcontainer_package_sid(sid: &str) -> bool {
    let mut fields = sid.split('-');
    if fields.next() != Some("S")
        || fields.next() != Some("1")
        || fields.next() != Some("15")
        || fields.next() != Some("2")
    {
        return false;
    }
    let components: Vec<_> = fields.collect();
    (1..=15).contains(&components.len())
        && components
            .iter()
            .all(|component| !component.is_empty() && component.parse::<u32>().is_ok())
}

#[cfg(windows)]
fn validate_prepare_request(
    request: &PrepareRequest,
    launch_id: &str,
    launcher_pid: u32,
    launcher_creation_time_100ns: u64,
    sandbox_sid: &str,
) -> crate::Result<()> {
    if request.version != 1
        || request.launch_id != launch_id
        || request.launcher_pid != launcher_pid
        || request.launcher_creation_time_100ns != launcher_creation_time_100ns
        || request.network != crate::isolation::NetworkMode::None
        || !is_appcontainer_package_sid(&request.package_sid)
        || !request
            .profile_name
            .starts_with(crate::sandbox::windows::ffi::PROFILE_PREFIX)
        || !derived_package_sid_matches(&request.profile_name, &request.package_sid)
        || request.package_sid == sandbox_sid
    {
        return Err(crate::Error::integrity(
            "launcher preparation identity, package SID or network mode mismatch",
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn derive_package_sid(name: &str) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
    let name: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain([0])
        .collect();
    let mut sid = std::ptr::null_mut();
    // SAFETY: the name is NUL-terminated and the API writes a caller-owned SID
    // pointer that is freed below with FreeSid regardless of success.
    let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
    if hr < 0 || sid.is_null() {
        return None;
    }
    let derived = crate::sandbox::windows::ffi::sid_to_string(sid);
    unsafe { windows_sys::Win32::Security::FreeSid(sid) };
    derived.ok()
}

#[cfg(windows)]
fn derived_package_sid_matches(name: &str, expected: &str) -> bool {
    derive_package_sid(name).is_some_and(|sid| sid == expected)
}

#[cfg(windows)]
fn validate_prepare_ack(
    ack: Option<&PrepareAck>,
    launch_id: &str,
    package_sid: &str,
) -> crate::Result<()> {
    let ack = ack.ok_or_else(|| {
        crate::Error::isolation_unavailable("SYSTEM service did not acknowledge WFP preparation")
    })?;
    if ack.version != 1
        || ack.launch_id != launch_id
        || ack.package_sid != package_sid
        || !ack.ready
    {
        return Err(crate::Error::isolation_unavailable(format!(
            "SYSTEM service rejected WFP preparation: {}",
            bounded_error_detail(&ack.detail)
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn decode_prepare_request(payload: &[u8]) -> crate::Result<PrepareRequest> {
    if payload.is_empty() || payload.len() > MAX_PREPARE_FRAME {
        return Err(crate::Error::integrity(
            "launcher preparation payload has invalid size",
        ));
    }
    let request: PrepareRequest = serde_json::from_slice(payload)
        .map_err(|_| crate::Error::integrity("launcher preparation frame is malformed"))?;
    if !is_launch_id(&request.launch_id) || !is_appcontainer_package_sid(&request.package_sid) {
        return Err(crate::Error::integrity(
            "launcher preparation identity fields are malformed",
        ));
    }
    Ok(request)
}

#[cfg(windows)]
fn is_duplicate_prepare(already_ready: bool, read: &PrepareRead) -> bool {
    already_ready && !matches!(read, PrepareRead::Pending)
}

#[cfg(windows)]
pub(crate) struct PreparationClient {
    request: std::os::windows::io::OwnedHandle,
    ack: std::os::windows::io::OwnedHandle,
    launch_id: String,
}

#[cfg(windows)]
pub(crate) struct PackagePolicyReceipt {
    pub(crate) launch_id: String,
    pub(crate) package_sid: String,
}

#[cfg(windows)]
impl PreparationClient {
    #[allow(unsafe_code)]
    pub(crate) fn from_raw_handles(request: u64, ack: u64, launch_id: &str) -> crate::Result<Self> {
        use std::os::windows::io::{FromRawHandle, RawHandle};
        if request == 0
            || ack == 0
            || request == u64::MAX
            || ack == u64::MAX
            || !is_launch_id(launch_id)
        {
            return Err(crate::Error::rejected(
                "hardened launcher preparation handles or launch identity are invalid",
            ));
        }
        Ok(Self {
            request: unsafe {
                std::os::windows::io::OwnedHandle::from_raw_handle(request as RawHandle)
            },
            ack: unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(ack as RawHandle) },
            launch_id: launch_id.to_owned(),
        })
    }

    #[allow(unsafe_code)]
    pub(crate) fn prepare(
        &mut self,
        package_sid: &str,
        profile_name: &str,
        network: crate::isolation::NetworkMode,
    ) -> crate::Result<PackagePolicyReceipt> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{FILETIME, HANDLE};
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetProcessTimes,
        };

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
                GetCurrentProcess(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(crate::Error::isolation_unavailable(
                "cannot read launcher creation identity for WFP setup",
            ));
        }
        let request = PrepareRequest {
            version: 1,
            launch_id: self.launch_id.clone(),
            launcher_pid: unsafe { GetCurrentProcessId() },
            launcher_creation_time_100ns: (u64::from(created.dwHighDateTime) << 32)
                | u64::from(created.dwLowDateTime),
            package_sid: package_sid.to_owned(),
            profile_name: profile_name.to_owned(),
            network,
        };
        let payload = serde_json::to_vec(&request)
            .map_err(|_| crate::Error::internal("cannot encode WFP preparation request"))?;
        if payload.is_empty() || payload.len() > MAX_PREPARE_FRAME {
            return Err(crate::Error::integrity(
                "WFP preparation request exceeded its frame limit",
            ));
        }
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        let mut written = 0u32;
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::WriteFile(
                self.request.as_raw_handle() as HANDLE,
                frame.as_ptr().cast(),
                frame.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        } == 0
            || written as usize != frame.len()
        {
            return Err(crate::Error::isolation_unavailable(
                "WFP preparation request could not be delivered to the SYSTEM service",
            ));
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut ack_buffer = Vec::new();
        loop {
            match read_prepare_ack(self.ack.as_raw_handle() as HANDLE, &mut ack_buffer)? {
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                None => {
                    return Err(crate::Error::isolation_unavailable(
                        "SYSTEM service did not acknowledge WFP filters before the preparation deadline",
                    ));
                }
                Some(ack) => {
                    validate_prepare_ack(Some(&ack), &self.launch_id, package_sid)?;
                    return Ok(PackagePolicyReceipt {
                        launch_id: ack.launch_id,
                        package_sid: ack.package_sid,
                    });
                }
            }
        }
    }

    pub(crate) fn launch_id(&self) -> &str {
        &self.launch_id
    }
}

#[cfg(windows)]
fn is_launch_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_prepare_ack(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    buffer: &mut Vec<u8>,
) -> crate::Result<Option<PrepareAck>> {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut available = 0u32;
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
        return Err(crate::Error::isolation_unavailable(
            "SYSTEM service closed the WFP acknowledgement pipe",
        ));
    }
    if available == 0 {
        return Ok(None);
    }
    let capacity = MAX_PREPARE_FRAME + 4 - buffer.len();
    if capacity == 0 {
        return Err(crate::Error::integrity(
            "WFP acknowledgement frame exceeded its bound",
        ));
    }
    let mut fragment = vec![0u8; (available as usize).min(4096).min(capacity)];
    let mut read = 0u32;
    if unsafe {
        ReadFile(
            pipe,
            fragment.as_mut_ptr().cast(),
            fragment.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        )
    } == 0
        || read == 0
    {
        return Err(crate::Error::integrity(
            "cannot read WFP acknowledgement frame fragment",
        ));
    }
    fragment.truncate(read as usize);
    let payload =
        match accumulate_prepare_frame(buffer, &fragment).map_err(crate::Error::integrity)? {
            None => return Ok(None),
            Some(payload) => payload,
        };
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|_| crate::Error::integrity("WFP acknowledgement frame is malformed"))
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
fn write_pipe_response_and_wait_ack(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    reply: &Response,
) -> crate::Result<()> {
    write_pipe_response(pipe, reply)?;
    let ack = read_pipe_request(pipe)?;
    if !valid_response_ack(&ack) {
        return Err(crate::Error::integrity(
            "authenticated service response acknowledgement was malformed",
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
        GetLastError, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
        ERROR_PIPE_NOT_CONNECTED, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        SetNamedPipeHandleState, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
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
    if !marker_blocks_cleanup(&marker_check) {
        sweep_stale_snapshots(&jobs)?;
    } else {
        // Never delete snapshots or grants until a prior process has been
        // positively reconciled. Invalid markers also remain locked.
        LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
    }
    let name = format!(r"\\.\pipe\fail2commit-hardened-{sid_text}");
    let wide: Vec<u16> = OsStr::new(&name).encode_wide().chain([0]).collect();
    let security = PipeSecurity::new(&expected)?;
    // Keep the initial server pipe instance for the service lifetime. Creating
    // a new FIRST_PIPE_INSTANCE after STATUS can fail while that client still
    // owns its connected handle, which had been killing the listener between
    // requests and exposing the pipe name to races.
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
    // SAFETY: raw is the single server instance owned throughout this loop.
    let _handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
    loop {
        if SERVICE_STOP_REQUESTED.load(Ordering::SeqCst) {
            break Ok(());
        }
        // In PIPE_NOWAIT mode the first successful call only makes this
        // instance available; it does not prove a client connected. Only the
        // ERROR_PIPE_CONNECTED result is evidence of a completed connection.
        let connected = {
            let mut first_connect = true;
            loop {
                if SERVICE_STOP_REQUESTED.load(Ordering::SeqCst) {
                    break false;
                }
                // SAFETY: raw is the owned server pipe handle; NULL requests
                // synchronous nonblocking connect behavior.
                let connected_call = unsafe { ConnectNamedPipe(raw, std::ptr::null_mut()) } != 0;
                let code = unsafe { GetLastError() };
                let decision = classify_pipe_connect(
                    first_connect,
                    connected_call,
                    code,
                    ERROR_PIPE_CONNECTED,
                    ERROR_PIPE_LISTENING,
                    ERROR_NO_DATA,
                );
                first_connect = false;
                match decision {
                    PipeConnectDecision::Connected => break true,
                    PipeConnectDecision::InitialAvailability | PipeConnectDecision::Listening => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    PipeConnectDecision::PreviousClientClosed => {
                        // A previous client closed before this accept completed.
                        // Reset only this completed/stale client state, never the
                        // initial availability transition above.
                        // SAFETY: raw is our owned instance and ERROR_NO_DATA says
                        // its previous client has closed.
                        if unsafe { DisconnectNamedPipe(raw) } == 0 {
                            let reset = unsafe { GetLastError() };
                            if reset != ERROR_PIPE_NOT_CONNECTED {
                                return Err(crate::Error::isolation_unavailable(format!(
                                "cannot reset stale hardened service pipe (Win32 error {reset})"
                            )));
                            }
                        }
                        first_connect = true;
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    PipeConnectDecision::Unexpected => {
                        return Err(crate::Error::isolation_unavailable(format!(
                            "ConnectNamedPipe returned an unrecognized state (Win32 error {code})"
                        )));
                    }
                }
            }
        };
        if !connected {
            break Ok(());
        }
        macro_rules! disconnect_and_continue {
            () => {{
                // SAFETY: raw is the connected, owned server instance.
                if unsafe { DisconnectNamedPipe(raw) } == 0 {
                    let code = unsafe { GetLastError() };
                    if code != ERROR_PIPE_NOT_CONNECTED {
                        return Err(crate::Error::isolation_unavailable(format!(
                            "cannot reset hardened service pipe for next peer (Win32 error {code})"
                        )));
                    }
                }
                continue;
            }};
        }
        let mut mode = PIPE_READMODE_BYTE | 0x00000001;
        // SAFETY: valid connected server pipe and writable mode value.
        if unsafe {
            SetNamedPipeHandleState(raw, &mut mode, std::ptr::null_mut(), std::ptr::null_mut())
        } == 0
        {
            disconnect_and_continue!();
        }
        let mut pid = 0u32;
        // SAFETY: valid connected pipe handle and writable PID output.
        if unsafe { GetNamedPipeClientProcessId(raw, &mut pid) } == 0 {
            disconnect_and_continue!();
        }
        let facts = match winsec::process_facts(pid) {
            Ok(f) => f,
            Err(_) => disconnect_and_continue!(),
        };
        if !windows_peer_allowed(&facts.user, &expected, facts.app_container) {
            disconnect_and_continue!();
        }
        let line = match read_pipe_request(raw) {
            Ok(line) => line,
            Err(_) => {
                let _ = write_pipe_response_and_wait_ack(
                    raw,
                    &response(false, "malformed or timed-out service request"),
                );
                disconnect_and_continue!();
            }
        };
        let request = match decode_request(&line) {
            Ok(request) => request,
            Err(_) => {
                let _ = write_pipe_response_and_wait_ack(
                    raw,
                    &response(false, "malformed or timed-out service request"),
                );
                disconnect_and_continue!();
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
            "LAUNCH" if LAUNCHER_CONTAINMENT_FAILED.load(Ordering::SeqCst) => {
                let mut reply = response(
                    false,
                    "a prior launcher termination was not confirmed; service is locked fail-closed",
                );
                reply.containment_confirmed = false;
                reply
            }
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
                    let mut reply = response(false, format!("launcher rejected the job: {detail}"));
                    reply.containment_confirmed =
                        !LAUNCHER_CONTAINMENT_FAILED.load(Ordering::SeqCst);
                    reply
                }
            },
            _ => response(false, "unknown or malformed operation"),
        };
        let _ = write_pipe_response_and_wait_ack(raw, &reply);
        // Do not call FlushFileBuffers: it could wait on a peer that keeps its
        // client handle open. WriteFile completed the bounded response, and
        // disconnecting resets this same listener instance for the next peer.
        // SAFETY: raw is the connected, owned server instance.
        if unsafe { DisconnectNamedPipe(raw) } == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_PIPE_NOT_CONNECTED {
                return Err(crate::Error::isolation_unavailable(format!(
                    "cannot reset hardened service pipe for next peer (Win32 error {code})"
                )));
            }
        }
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
    job: &crate::isolation::JobSpec,
    stage_root: &Path,
    test_diagnostic: bool,
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
    let mut request_read_raw: HANDLE = std::ptr::null_mut();
    let mut request_write_raw: HANDLE = std::ptr::null_mut();
    // SAFETY: fresh anonymous pipes; child endpoints are restricted by the
    // explicit handle list below and server endpoints are made non-inheritable.
    if unsafe { CreatePipe(&mut request_read_raw, &mut request_write_raw, &mut sa, 4096) } == 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "CreatePipe(WFP preparation) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let request_read = unsafe { OwnedHandle::from_raw_handle(request_read_raw as RawHandle) };
    let request_write = unsafe { OwnedHandle::from_raw_handle(request_write_raw as RawHandle) };
    let mut ack_read_raw: HANDLE = std::ptr::null_mut();
    let mut ack_write_raw: HANDLE = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut ack_read_raw, &mut ack_write_raw, &mut sa, 4096) } == 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "CreatePipe(WFP acknowledgement) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let ack_read = unsafe { OwnedHandle::from_raw_handle(ack_read_raw as RawHandle) };
    let ack_write = unsafe { OwnedHandle::from_raw_handle(ack_write_raw as RawHandle) };
    for server_handle in [request_read_raw, ack_write_raw] {
        if unsafe { SetHandleInformation(server_handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            let code = unsafe { GetLastError() };
            return Err(crate::Error::isolation_unavailable(format!(
                "cannot exclude WFP service pipe endpoint from launcher inheritance (Win32 error {code})"
            )));
        }
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
    let job_handle = unsafe { OwnedHandle::from_raw_handle(job_raw as RawHandle) };
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
    let handle_list = [read_raw, request_write_raw, ack_read_raw];
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
    #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
    let mut diagnostic_stage = ServiceLauncherDiagnostic {
        profile_loaded: true,
        ..Default::default()
    };
    let mut retained_process = None;
    let mut containment_confirmed = true;
    let mut active_marker = None;
    let mut network_guard = None;
    let mut package_grants = None;
    let mut launch_result = (|| {
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
        #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
        {
            diagnostic_stage.environment_created = true;
        }
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attr.cast();
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let flags = EXTENDED_STARTUPINFO_PRESENT
            | CREATE_UNICODE_ENVIRONMENT
            | CREATE_NO_WINDOW
            | CREATE_SUSPENDED;
        let snapshot_dir = snapshot_root_for_jobfile(jobfile)
            .ok_or_else(|| crate::Error::integrity("snapshot job has no root directory"))?;
        active_marker = match ActiveLaunchGuard::create(sandbox_sid, &snapshot_dir) {
            Ok(marker) => Some(marker),
            Err(error) => {
                if active_launch_pending().unwrap_or(true) {
                    LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
                }
                return Err(error);
            }
        };
        let marker_id = active_marker
            .as_ref()
            .expect("marker created")
            .launch_id()
            .to_owned();
        let diagnostic_arg = if test_diagnostic {
            #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
            {
                " --test-diagnostic"
            }
            #[cfg(not(all(feature = "hardened-test-diagnostics", debug_assertions)))]
            {
                return Err(crate::Error::rejected(
                    "test diagnostic launcher is unavailable in this build",
                ));
            }
        } else {
            ""
        };
        let cmd = format!(
            "{} sandbox launch {} --watchdog {} --prepare-request {} --prepare-ack {} --launch-id {}{}",
            quote_windows_arg(&exe.to_string_lossy()),
            quote_windows_arg(&jobfile.to_string_lossy()),
            read_raw as usize,
            request_write_raw as usize,
            ack_read_raw as usize,
            marker_id,
            diagnostic_arg,
        );
        let mut cmd_w: Vec<u16> = std::ffi::OsStr::new(&cmd)
            .encode_wide()
            .chain([0])
            .collect();
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
        #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
        {
            diagnostic_stage.launcher_created = true;
        }
        drop(read_end);
        drop(request_write);
        drop(ack_read);
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
        let preparation_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut preparation_buffer = Vec::new();
        loop {
            let waited = unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 100) };
            if waited == 0 {
                #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
                {
                    diagnostic_stage.launcher_exit_confirmed = true;
                }
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
            if network_guard.is_none() {
                match read_prepare_request(
                    request_read.as_raw_handle() as HANDLE,
                    &mut preparation_buffer,
                ) {
                    PrepareRead::Pending => {}
                    PrepareRead::Invalid(detail) => {
                        watchdog.take();
                        if let Err(termination) = terminate_launcher_and_confirm(
                            process.as_raw_handle() as HANDLE,
                            0xE008,
                        ) {
                            containment_confirmed = false;
                            return Err(crate::Error::isolation_unavailable(format!(
                                "invalid launcher preparation request; containment is unconfirmed: {termination}"
                            )));
                        }
                        return Err(crate::Error::integrity(detail));
                    }
                    PrepareRead::Request(message) => {
                        if validate_prepare_request(
                            &message,
                            &marker_id,
                            pi.dwProcessId,
                            creation_time_100ns,
                            sandbox_sid,
                        )
                        .is_err()
                        {
                            write_prepare_ack(
                                ack_write.as_raw_handle() as HANDLE,
                                &PrepareAck {
                                    version: 1,
                                    launch_id: marker_id.clone(),
                                    package_sid: message.package_sid,
                                    ready: false,
                                    detail: "launcher identity or job network policy did not match"
                                        .into(),
                                },
                            )?;
                            watchdog.take();
                            if let Err(termination) = terminate_launcher_and_confirm(
                                process.as_raw_handle() as HANDLE,
                                0xE009,
                            ) {
                                containment_confirmed = false;
                                return Err(crate::Error::isolation_unavailable(format!(
                                    "launcher preparation identity mismatch; containment is unconfirmed: {termination}"
                                )));
                            }
                            return Err(crate::Error::integrity(
                                "launcher preparation identity or network mode mismatch",
                            ));
                        }
                        let grants = match crate::sandbox::windows::grant_hardened_package(
                            job,
                            stage_root,
                            &message.package_sid,
                        ) {
                            Ok(grants) => grants,
                            Err(error) => {
                                let _ = write_prepare_ack(
                                    ack_write.as_raw_handle() as HANDLE,
                                    &PrepareAck {
                                        version: 1,
                                        launch_id: marker_id.clone(),
                                        package_sid: message.package_sid,
                                        ready: false,
                                        detail: bounded_error_detail(&error.message),
                                    },
                                );
                                watchdog.take();
                                if let Err(termination) = terminate_launcher_and_confirm(
                                    process.as_raw_handle() as HANDLE,
                                    0xE00D,
                                ) {
                                    containment_confirmed = false;
                                    return Err(crate::Error::isolation_unavailable(format!(
                                        "package ACL setup failed and launcher containment is unconfirmed: {termination}"
                                    )));
                                }
                                return Err(error);
                            }
                        };
                        match super::windows_wfp::PackageGuard::install(&message.package_sid) {
                            Ok(guard) => {
                                write_prepare_ack(
                                    ack_write.as_raw_handle() as HANDLE,
                                    &PrepareAck {
                                        version: 1,
                                        launch_id: marker_id.clone(),
                                        package_sid: message.package_sid,
                                        ready: true,
                                        detail: "package-scoped deny filters read back".into(),
                                    },
                                )?;
                                network_guard = Some(guard);
                                package_grants = Some(grants);
                            }
                            Err(error) => {
                                let _ = write_prepare_ack(
                                    ack_write.as_raw_handle() as HANDLE,
                                    &PrepareAck {
                                        version: 1,
                                        launch_id: marker_id.clone(),
                                        package_sid: message.package_sid,
                                        ready: false,
                                        detail: bounded_error_detail(&error.message),
                                    },
                                );
                                watchdog.take();
                                if let Err(termination) = terminate_launcher_and_confirm(
                                    process.as_raw_handle() as HANDLE,
                                    0xE00A,
                                ) {
                                    containment_confirmed = false;
                                    return Err(crate::Error::isolation_unavailable(format!(
                                        "WFP setup failed and launcher containment is unconfirmed: {termination}"
                                    )));
                                }
                                let mut grants = grants;
                                if let Err(cleanup) = grants.release() {
                                    LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
                                    return Err(crate::Error::isolation_unavailable(format!(
                                        "WFP setup failed and package ACL rollback failed: {}",
                                        cleanup.message
                                    )));
                                }
                                return Err(error);
                            }
                        }
                    }
                }
                if network_guard.is_none() && std::time::Instant::now() >= preparation_deadline {
                    watchdog.take();
                    if let Err(termination) =
                        terminate_launcher_and_confirm(process.as_raw_handle() as HANDLE, 0xE00B)
                    {
                        containment_confirmed = false;
                        return Err(crate::Error::isolation_unavailable(format!(
                            "launcher did not complete WFP preparation before deadline; containment is unconfirmed: {termination}"
                        )));
                    }
                    return Err(crate::Error::isolation_unavailable(
                        "launcher did not complete WFP preparation before deadline",
                    ));
                }
            } else {
                let read = read_prepare_request(
                    request_read.as_raw_handle() as HANDLE,
                    &mut preparation_buffer,
                );
                if is_duplicate_prepare(true, &read) {
                    watchdog.take();
                    if let Err(termination) =
                        terminate_launcher_and_confirm(process.as_raw_handle() as HANDLE, 0xE00C)
                    {
                        containment_confirmed = false;
                        return Err(crate::Error::isolation_unavailable(format!(
                            "duplicate or malformed WFP preparation message; containment is unconfirmed: {termination}"
                        )));
                    }
                    return Err(crate::Error::integrity(
                        "duplicate or malformed WFP preparation message",
                    ));
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
        if network_guard.is_none() {
            return Err(crate::Error::isolation_unavailable(
                "launcher exited without completing the WFP preparation handshake",
            ));
        }
        Ok(exit)
    })();
    match terminate_job_tree_and_confirm(job_raw) {
        Ok(had_residual_processes) => {
            containment_confirmed = true;
            // Confirmed zero active processes before closing the last handle.
            drop(job_handle);
            if had_residual_processes && launch_result.is_ok() {
                launch_result = Err(crate::Error::isolation_unavailable(
                    "launcher exited while child processes remained; tree was terminated and outcome rejected",
                ));
            }
        }
        Err(_) => containment_confirmed = false,
    }
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
        if let Some(guard) = network_guard.take() {
            std::mem::forget(guard);
        }
        if let Some(grants) = package_grants.take() {
            std::mem::forget(grants);
        }
        return launch_result;
    }
    // The durable marker covers the entire grant/filter cleanup interval. A
    // failed revoke or WFP close must therefore remain visible to STATUS,
    // direct LAUNCH requests, and uninstall after this process returns.
    if let Some(mut grants) = package_grants.take() {
        if let Err(error) = grants.release() {
            LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
            if let Some(marker) = active_marker.as_mut() {
                marker.retain();
            }
            return Err(crate::Error::isolation_unavailable(format!(
                "job tree exited but package ACL revocation failed: {}",
                error.message
            )));
        }
    }
    if let Some(mut guard) = network_guard.take() {
        if let Err(error) = guard.close() {
            LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
            if let Some(marker) = active_marker.as_mut() {
                marker.retain();
            }
            // Keep the live dynamic session owned while the service remains
            // running; process shutdown will close it, while the marker blocks
            // any later job or uninstall attempt.
            std::mem::forget(guard);
            return Err(error);
        }
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
    #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
    {
        diagnostic_stage.profile_unloaded = true;
    }
    if let Some(marker) = active_marker.as_mut() {
        if let Err(error) = marker.clear() {
            LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
            marker.retain();
            return Err(error);
        }
    }
    #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
    {
        diagnostic_stage.marker_cleared = true;
    }
    #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
    {
        diagnostic_stage.package_grants_revoked = package_grants.is_none();
        diagnostic_stage.wfp_session_closed = true;
        if test_diagnostic {
            let snapshot_root = snapshot_root_for_jobfile(jobfile)
                .ok_or_else(|| crate::Error::integrity("diagnostic snapshot root is missing"))?;
            write_service_launcher_diagnostic(&snapshot_root.join("output"), &diagnostic_stage)?;
        }
    }
    drop(username);
    drop(password_w);
    launch_result
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn terminate_job_tree_and_confirm(
    job: windows_sys::Win32::Foundation::HANDLE,
) -> std::result::Result<bool, String> {
    use windows_sys::Win32::System::JobObjects::{
        JobObjectBasicAccountingInformation, QueryInformationJobObject, TerminateJobObject,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    };
    const POLLS: usize = 200;
    let mut active = || -> std::result::Result<u32, u32> {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            Err(unsafe { windows_sys::Win32::Foundation::GetLastError() })
        } else {
            Ok(info.ActiveProcesses)
        }
    };
    process_tree_barrier(
        &mut active,
        || {
            if unsafe { TerminateJobObject(job, 0xE007) } == 0 {
                Err(unsafe { windows_sys::Win32::Foundation::GetLastError() })
            } else {
                Ok(())
            }
        },
        || std::thread::sleep(std::time::Duration::from_millis(25)),
        POLLS,
    )
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
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ};

    let dir = open_user_job_dir(job_dir, peer_sid)?;
    let (snapshot_dir, _snapshot_handle) = snapshot_job(&dir, peer_sid, sandbox_sid)?;
    let jobfile = snapshot_dir.path().join("job.json");
    let snapshot_bytes = std::fs::read(&jobfile)?;
    let (job, stage_root, test_diagnostic) =
        super::protocol::decode_hardened_job_for_service(&snapshot_bytes)?;
    let stage_handle = open_windows_object(
        &stage_root,
        true,
        windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
            | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
    )?;
    let stage_metadata = stage_handle.metadata()?;
    if !stage_metadata.is_dir()
        || stage_metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        || !same_windows_path(&stage_root.canonicalize()?, &stage_root)
    {
        return Err(crate::Error::rejected(
            "hardened stage root is not a canonical plain directory",
        ));
    }
    if crate::ipc::winsec::owner_sid(&stage_handle)? != crate::ipc::winsec::sid_string(peer_sid) {
        return Err(crate::Error::rejected(
            "hardened stage root is not owned by the authenticated peer",
        ));
    }
    let exit = match run_snapshot_as_sandbox(
        &jobfile,
        client_pipe,
        sandbox_sid,
        &job,
        &stage_root,
        test_diagnostic,
    ) {
        Ok(exit) => exit,
        Err(error) if LAUNCHER_CONTAINMENT_FAILED.load(Ordering::SeqCst) => {
            // Preserve every snapshot file as long as a process-tree cleanup
            // barrier was unconfirmed; the SYSTEM marker records this root.
            let _retained_root = retain_snapshot_if_unconfirmed(snapshot_dir, true);
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    if exit != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "hardened launcher exited with code {exit}"
        )));
    }
    if test_diagnostic {
        #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
        {
            copy_test_diagnostic_to_peer(&snapshot_dir.path().join("output"), &dir.path)?;
            return Err(crate::Error::isolation_unavailable(
                "test diagnostic completed; hardened execution remains unavailable until all platform probes pass",
            ));
        }
        #[cfg(not(all(feature = "hardened-test-diagnostics", debug_assertions)))]
        {
            return Err(crate::Error::rejected(
                "test diagnostic job is unavailable in this build",
            ));
        }
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

#[cfg(all(windows, feature = "hardened-test-diagnostics", debug_assertions))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HardenedLauncherDiagnostic {
    pub(crate) service_received_diagnostic_request: bool,
    pub(crate) service_profile_loaded: bool,
    pub(crate) service_environment_created: bool,
    pub(crate) service_launcher_created: bool,
    pub(crate) service_launcher_exit_confirmed: bool,
    pub(crate) service_profile_unloaded: bool,
    pub(crate) service_marker_cleared: bool,
    pub(crate) service_package_grants_revoked: bool,
    pub(crate) service_wfp_session_closed: bool,
    pub(crate) launcher_created: bool,
    pub(crate) profile_created: bool,
    pub(crate) child_process_created_suspended: bool,
    pub(crate) token_is_appcontainer: bool,
    pub(crate) token_is_lpac: bool,
    pub(crate) token_sid_matches_profile: bool,
    pub(crate) child_assigned_to_job: bool,
    pub(crate) system_acknowledged_package_policy: bool,
    pub(crate) child_termination_confirmed: bool,
    pub(crate) child_tree_empty: bool,
    pub(crate) profile_removed: bool,
}

#[cfg(all(windows, feature = "hardened-test-diagnostics", debug_assertions))]
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ServiceLauncherDiagnostic {
    profile_loaded: bool,
    environment_created: bool,
    launcher_created: bool,
    launcher_exit_confirmed: bool,
    profile_unloaded: bool,
    marker_cleared: bool,
    package_grants_revoked: bool,
    wfp_session_closed: bool,
}

#[cfg(all(windows, feature = "hardened-test-diagnostics", debug_assertions))]
fn write_test_diagnostic(jobfile: &Path, bytes: &[u8]) -> crate::Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(crate::Error::integrity(
            "test diagnostic record exceeded its bound",
        ));
    }
    let root = jobfile
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| crate::Error::integrity("diagnostic snapshot root is missing"))?;
    let output_dir = root.join("output");
    let metadata = std::fs::symlink_metadata(&output_dir)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(crate::Error::integrity(
            "test diagnostic output directory is unsafe",
        ));
    }
    let path = output_dir.join("diagnostic.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    use std::io::Write;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(all(windows, feature = "hardened-test-diagnostics", debug_assertions))]
fn write_service_launcher_diagnostic(
    output_dir: &Path,
    diagnostic: &ServiceLauncherDiagnostic,
) -> crate::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let bytes = serde_json::to_vec(diagnostic)
        .map_err(|_| crate::Error::internal("cannot encode service launcher diagnostic"))?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(crate::Error::integrity(
            "service launcher diagnostic exceeded its bound",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(output_dir.join("service-diagnostic.json"))?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(all(windows, feature = "hardened-test-diagnostics", debug_assertions))]
fn copy_test_diagnostic_to_peer(output_dir: &Path, job_dir: &Path) -> crate::Result<()> {
    use std::io::{Read, Write};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };
    merge_test_diagnostics(output_dir)?;
    let source_path = output_dir.join("combined-diagnostic.json");
    let source = open_windows_object(&source_path, false, FILE_SHARE_READ)?;
    let metadata = source.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || crate::sandbox::link_count(&metadata, &source_path)? != 1
        || metadata.len() == 0
        || metadata.len() > 4096
    {
        return Err(crate::Error::integrity(
            "test diagnostic record is unsafe or oversized",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&source).take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(crate::Error::integrity(
            "test diagnostic record exceeded its bound",
        ));
    }
    serde_json::from_slice::<HardenedLauncherDiagnostic>(&bytes)
        .map_err(|_| crate::Error::integrity("test diagnostic record is malformed"))?;
    let output = job_dir.join("diagnostic.json");
    let mut destination = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(output)?;
    destination.write_all(&bytes)?;
    destination.sync_all()?;
    Ok(())
}

#[cfg(all(windows, feature = "hardened-test-diagnostics", debug_assertions))]
fn merge_test_diagnostics(output_dir: &Path) -> crate::Result<()> {
    use std::io::{Read, Write};
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    fn read_bounded(path: &Path) -> crate::Result<Vec<u8>> {
        let file = open_windows_object(path, false, FILE_SHARE_READ)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            || crate::sandbox::link_count(&metadata, path)? != 1
            || metadata.len() == 0
            || metadata.len() > 4096
        {
            return Err(crate::Error::integrity(
                "test diagnostic component is unsafe or oversized",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&file).take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(crate::Error::integrity(
                "test diagnostic component exceeded its bound",
            ));
        }
        Ok(bytes)
    }
    let launcher_bytes = read_bounded(&output_dir.join("diagnostic.json"))?;
    let service_bytes = read_bounded(&output_dir.join("service-diagnostic.json"))?;
    let mut launcher: HardenedLauncherDiagnostic = serde_json::from_slice(&launcher_bytes)
        .map_err(|_| crate::Error::integrity("launcher test diagnostic is malformed"))?;
    let service: ServiceLauncherDiagnostic = serde_json::from_slice(&service_bytes)
        .map_err(|_| crate::Error::integrity("service test diagnostic is malformed"))?;
    launcher.service_received_diagnostic_request = true;
    launcher.service_profile_loaded = service.profile_loaded;
    launcher.service_environment_created = service.environment_created;
    launcher.service_launcher_created = service.launcher_created;
    launcher.service_launcher_exit_confirmed = service.launcher_exit_confirmed;
    launcher.service_profile_unloaded = service.profile_unloaded;
    launcher.service_marker_cleared = service.marker_cleared;
    launcher.service_package_grants_revoked = service.package_grants_revoked;
    launcher.service_wfp_session_closed = service.wfp_session_closed;
    let bytes = serde_json::to_vec(&launcher)
        .map_err(|_| crate::Error::internal("cannot encode merged test diagnostic"))?;
    if bytes.len() > 4096 {
        return Err(crate::Error::integrity(
            "merged test diagnostic exceeded its bound",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_dir.join("combined-diagnostic.json"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(super) fn launch_hidden(
    jobfile: &Path,
    watchdog: Option<u64>,
    prepare_request: Option<u64>,
    prepare_ack: Option<u64>,
    launch_id: Option<&str>,
    cli_test_diagnostic: bool,
) -> crate::Result<()> {
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
    let (request, ack, launch_id) = match (prepare_request, prepare_ack, launch_id) {
        (Some(request), Some(ack), Some(launch_id)) => (request, ack, launch_id),
        _ => {
            return Err(crate::Error::rejected(
                "hardened launcher requires its bounded SYSTEM preparation channel",
            ))
        }
    };
    let mut preparation = PreparationClient::from_raw_handles(request, ack, launch_id)?;
    let graceful_watchdog_exit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog_done = std::sync::Arc::clone(&graceful_watchdog_exit);
    let watchdog_thread = std::thread::spawn(move || {
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        let handle = handle_value as HANDLE;
        loop {
            if watchdog_done.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            let mut available = 0u32;
            // Polling lets a completed, already-drained job stop its watchdog
            // thread cleanly before the process exits. EOF before that point is
            // still an immediate fail-closed termination signal.
            let peek_ok = unsafe {
                PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if peek_ok == 0 {
                // SAFETY: the inherited watchdog handle is a valid pipe; an
                // unexpected close means the SYSTEM service disappeared.
                unsafe { TerminateProcess(GetCurrentProcess(), 0xE001) };
                break;
            }
            if available == 0 {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
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
            if ok == 0 || read == 0 || byte != 0 {
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
    let (job, stage_root, test_diagnostic) =
        super::protocol::decode_hardened_job_for_service(&bytes)?;
    if test_diagnostic != cli_test_diagnostic {
        return Err(crate::Error::rejected(
            "test diagnostic envelope and inherited launcher mode do not match",
        ));
    }
    if test_diagnostic {
        #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
        {
            let diagnostic = crate::sandbox::windows::run_hardened_lpac_diagnostic(
                &job,
                &stage_root,
                &mut preparation,
            )?;
            let encoded = serde_json::to_vec(&diagnostic)
                .map_err(|_| crate::Error::internal("cannot encode launcher diagnostic"))?;
            write_test_diagnostic(jobfile, &encoded)?;
            graceful_watchdog_exit.store(true, std::sync::atomic::Ordering::Release);
            watchdog_thread.join().map_err(|_| {
                crate::Error::internal("hardened launcher watchdog thread panicked")
            })?;
            return Ok(());
        }
        #[cfg(not(all(feature = "hardened-test-diagnostics", debug_assertions)))]
        {
            return Err(crate::Error::rejected(
                "test diagnostic job is unavailable in this build",
            ));
        }
    }
    if job.network != crate::isolation::NetworkMode::None {
        return Err(crate::Error::isolation_unavailable(
            "hardened Internet jobs remain disabled until the shared proxy path is implemented and probed",
        ));
    }
    let outcome = crate::sandbox::windows::run_hardened_lpac(&job, &stage_root, &mut preparation)?;
    let encoded = super::protocol::encode_outcome(&outcome)?;
    if encoded.len() > super::protocol::MAX_OUTCOME_BYTES {
        return Err(crate::Error::integrity(
            "hardened launcher outcome exceeded its wire limit",
        ));
    }
    let root = jobfile
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| crate::Error::integrity("hardened snapshot output root is missing"))?;
    let output_dir = root.join("output");
    let output_meta = std::fs::symlink_metadata(&output_dir)?;
    if !output_meta.is_dir() || output_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(crate::Error::integrity(
            "hardened launcher output directory is unsafe",
        ));
    }
    let output_path = output_dir.join("outcome.json");
    use std::os::windows::fs::OpenOptionsExt;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&output_path)
        .map_err(|error| {
            crate::Error::integrity(format!("cannot safely publish hardened outcome: {error}"))
        })?;
    use std::io::Write;
    output.write_all(&encoded)?;
    output.sync_all()?;
    graceful_watchdog_exit.store(true, std::sync::atomic::Ordering::Release);
    watchdog_thread
        .join()
        .map_err(|_| crate::Error::internal("hardened launcher watchdog thread panicked"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(windows, feature = "hardened-test-diagnostics", debug_assertions))]
    #[test]
    #[ignore = "requires the installed hardened service in a disposable Windows VM"]
    fn disposable_win10_authenticated_service_lpac_launcher_diagnostic() {
        use std::time::Duration;

        let state = super::super::lifecycle::installed_state().expect("installed state");
        let installer_sid = state
            .installer_sid
            .as_deref()
            .expect("installer SID in install state");
        let sandbox_sid = state
            .sandbox_sid
            .as_deref()
            .expect("sandbox SID in install state");
        assert_eq!(
            crate::ipc::winsec::sid_string(
                &crate::ipc::winsec::current_user_sid().expect("test peer SID")
            ),
            installer_sid,
            "run the diagnostic as the installed installer account"
        );

        // Exercise persistent listener reuse with client handles that outlive
        // their replies, then verify a malformed authenticated request does
        // not tear down the listener before the diagnostic LAUNCH request.
        let pipe_name = format!(r"\\.\pipe\fail2commit-hardened-{installer_sid}");
        let mut held_pipe = open_service_pipe(&pipe_name).expect("service pipe after install");
        let status = service_request_on_pipe(
            &mut held_pipe,
            &Request {
                op: "STATUS".into(),
                job_dir: None,
            },
        )
        .expect("first authenticated STATUS");
        assert!(status.ok && status.service_running);
        std::thread::sleep(Duration::from_millis(150));
        drop(held_pipe);

        let status = service_request(
            &pipe_name,
            &Request {
                op: "STATUS".into(),
                job_dir: None,
            },
        )
        .expect("listener survives held client handle");
        assert!(status.ok && status.service_running);

        let mut malformed =
            open_service_pipe(&pipe_name).expect("service pipe for malformed request");
        malformed
            .write_all(b"{malformed-json}\n")
            .expect("write bounded malformed request");
        let mut malformed_reply = Vec::new();
        BufReader::new(malformed)
            .take(MAX_REQUEST as u64)
            .read_until(b'\n', &mut malformed_reply)
            .expect("read malformed request rejection");
        let rejected: Response = serde_json::from_slice(&malformed_reply)
            .expect("malformed request gets a bounded protocol response");
        assert!(!rejected.ok);
        let status = service_request(
            &pipe_name,
            &Request {
                op: "STATUS".into(),
                job_dir: None,
            },
        )
        .expect("listener survives malformed request");
        assert!(status.ok && status.service_running);

        let paths = crate::paths::TrustedPaths::resolve().expect("trusted paths");
        crate::fsutil::ensure_private_dir(&paths.cache_dir).expect("private cache directory");
        let stage_root =
            crate::sandbox::windows::hardened_test_stage_root().expect("hardened peer stage root");
        let stage = tempfile::Builder::new()
            .prefix("fr027-diagnostic-stage-")
            .tempdir_in(&stage_root)
            .expect("fixture stage");
        let read_only = stage.path().join("read-only");
        let work = stage.path().join("work");
        std::fs::create_dir(&read_only).expect("read-only fixture directory");
        std::fs::create_dir(&work).expect("work fixture directory");
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let cmd = read_only.join("diagnostic-cmd.exe");
        std::fs::copy(Path::new(&system_root).join("System32\\cmd.exe"), &cmd)
            .expect("stage fixed Windows command interpreter");
        let sentinel = work.join("package-command-ran.txt");
        let job = crate::isolation::JobSpec {
            program: cmd,
            args: vec![
                "/d".into(),
                "/c".into(),
                format!("echo unsafe > {}", sentinel.display()).into(),
            ],
            cwd: work.clone(),
            env: Vec::new(),
            read_only: vec![read_only],
            work_dir: work,
            exports: Vec::new(),
            export_to: None,
            limits: crate::isolation::JobLimits {
                timeout: Duration::from_secs(10),
                memory_bytes: Some(128 * 1024 * 1024),
                max_processes: Some(4),
                max_output_bytes: 4096,
                disk_bytes: None,
            },
            network: crate::isolation::NetworkMode::None,
            bait: false,
        };

        let job_dir = tempfile::Builder::new()
            .prefix("fr027-diagnostic-job-")
            .tempdir_in(&paths.cache_dir)
            .expect("peer-owned job request directory");
        let jobfile = job_dir.path().join("job.json");
        let envelope = super::super::protocol::encode_hardened_diagnostic_job(&job, &stage_root)
            .expect("bounded diagnostic envelope");
        std::fs::write(&jobfile, envelope).expect("write diagnostic envelope");
        let mut pipe = open_service_pipe(&pipe_name).expect("installed authenticated service pipe");
        let request = Request {
            op: "LAUNCH".into(),
            job_dir: Some(job_dir.path().to_string_lossy().into_owned()),
        };
        let diagnostic =
            crate::sandbox::windows::with_hardened_job_grants(&job, sandbox_sid, || {
                let result = (|| {
                    let reply = service_request_on_pipe(&mut pipe, &request)?;
                    if reply.ok {
                        return Err(crate::Error::integrity(
                            "service accepted a diagnostic request as a job outcome",
                        ));
                    }
                    let path = job_dir.path().join("diagnostic.json");
                    let metadata = std::fs::symlink_metadata(&path)?;
                    if !metadata.is_file() || metadata.len() > 4096 {
                        return Err(crate::Error::integrity(
                            "service diagnostic evidence is unsafe or oversized",
                        ));
                    }
                    let bytes = crate::fsutil::read_bounded(&path, 4096)?;
                    let diagnostic: HardenedLauncherDiagnostic = serde_json::from_slice(&bytes)
                        .map_err(|_| {
                            crate::Error::integrity("service diagnostic evidence is malformed")
                        })?;
                    Ok(diagnostic)
                })();
                match result {
                    Ok(value) => crate::sandbox::windows::HardenedGrantAction::Complete(Ok(value)),
                    Err(error) if launch_recovery_pending().unwrap_or(true) => {
                        crate::sandbox::windows::HardenedGrantAction::ContainmentUnconfirmed(error)
                    }
                    Err(error) => {
                        crate::sandbox::windows::HardenedGrantAction::Complete(Err(error))
                    }
                }
            })
            .expect("authenticated SYSTEM launcher diagnostic");
        let status = service_request(
            &pipe_name,
            &Request {
                op: "STATUS".into(),
                job_dir: None,
            },
        )
        .expect("listener survives LAUNCH response");
        assert!(status.ok && status.service_running);

        assert!(diagnostic.service_received_diagnostic_request);
        assert!(diagnostic.service_profile_loaded);
        assert!(diagnostic.service_environment_created);
        assert!(diagnostic.service_launcher_created);
        assert!(diagnostic.service_launcher_exit_confirmed);
        assert!(diagnostic.service_profile_unloaded);
        assert!(diagnostic.service_marker_cleared);
        assert!(diagnostic.service_package_grants_revoked);
        assert!(diagnostic.service_wfp_session_closed);
        assert!(diagnostic.launcher_created);
        assert!(diagnostic.profile_created);
        assert!(diagnostic.child_process_created_suspended);
        assert!(diagnostic.token_is_appcontainer);
        assert!(diagnostic.token_is_lpac);
        assert!(diagnostic.token_sid_matches_profile);
        assert!(diagnostic.child_assigned_to_job);
        assert!(diagnostic.system_acknowledged_package_policy);
        assert!(diagnostic.child_termination_confirmed);
        assert!(diagnostic.child_tree_empty);
        assert!(diagnostic.profile_removed);
        assert!(!sentinel.exists(), "fixture package command must never run");
        assert!(!launch_recovery_pending().expect("read launch recovery state"));
    }

    #[test]
    fn response_decoder_requires_bounded_newline_terminated_json() {
        let response = decode_response(b"{\"ok\":false,\"service_running\":true,\"probe_available\":false,\"detail\":\"not ready\"}\n").unwrap();
        assert!(!response.ok);
        assert!(decode_response(b"{\"ok\":true}").is_err());
        assert!(decode_response(&vec![b'x'; MAX_REQUEST]).is_err());
    }

    #[test]
    fn response_ack_is_exact_and_pipe_connect_needs_error_connected_proof() {
        const ERROR_PIPE_CONNECTED_TEST: u32 = 535;
        const ERROR_PIPE_LISTENING_TEST: u32 = 536;
        const ERROR_NO_DATA_TEST: u32 = 232;
        assert!(valid_response_ack(RESPONSE_ACK));
        assert!(!valid_response_ack(b"F2C-RESPONSE-READ"));
        assert!(!valid_response_ack(b"F2C-RESPONSE-READ\nextra"));

        assert_eq!(
            classify_pipe_connect(
                true,
                true,
                0,
                ERROR_PIPE_CONNECTED_TEST,
                ERROR_PIPE_LISTENING_TEST,
                ERROR_NO_DATA_TEST,
            ),
            PipeConnectDecision::InitialAvailability,
            "initial nonzero availability is not an authenticated connection"
        );
        assert_eq!(
            classify_pipe_connect(
                false,
                false,
                ERROR_PIPE_CONNECTED_TEST,
                ERROR_PIPE_CONNECTED_TEST,
                ERROR_PIPE_LISTENING_TEST,
                ERROR_NO_DATA_TEST,
            ),
            PipeConnectDecision::Connected
        );
        assert_eq!(
            classify_pipe_connect(
                false,
                false,
                ERROR_PIPE_LISTENING_TEST,
                ERROR_PIPE_CONNECTED_TEST,
                ERROR_PIPE_LISTENING_TEST,
                ERROR_NO_DATA_TEST,
            ),
            PipeConnectDecision::Listening
        );
        assert_eq!(
            classify_pipe_connect(
                false,
                false,
                ERROR_NO_DATA_TEST,
                ERROR_PIPE_CONNECTED_TEST,
                ERROR_PIPE_LISTENING_TEST,
                ERROR_NO_DATA_TEST,
            ),
            PipeConnectDecision::PreviousClientClosed
        );
    }

    #[test]
    fn preparation_frame_accumulates_fragmented_length_and_payload() {
        let payload = b"fragmented preparation payload";
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        let mut buffered = Vec::new();

        assert_eq!(
            accumulate_prepare_frame(&mut buffered, &frame[..2]).unwrap(),
            None,
            "a split length prefix remains pending"
        );
        assert_eq!(
            accumulate_prepare_frame(&mut buffered, &frame[2..7]).unwrap(),
            None,
            "a complete prefix with partial payload remains pending"
        );
        assert_eq!(
            accumulate_prepare_frame(&mut buffered, &frame[7..]).unwrap(),
            Some(payload.to_vec())
        );
        assert!(buffered.is_empty());

        let mut invalid = Vec::new();
        assert!(accumulate_prepare_frame(&mut invalid, &u32::MAX.to_le_bytes()).is_err());
    }

    #[cfg(windows)]
    fn sample_prepare_request() -> PrepareRequest {
        let profile_name = format!(
            "{}{}",
            crate::sandbox::windows::ffi::PROFILE_PREFIX,
            "a".repeat(32)
        );
        PrepareRequest {
            version: 1,
            launch_id: "a".repeat(64),
            launcher_pid: 412,
            launcher_creation_time_100ns: 987_654_321,
            package_sid: derive_package_sid(&profile_name).expect("derive package SID"),
            profile_name,
            network: crate::isolation::NetworkMode::None,
        }
    }

    #[cfg(windows)]
    #[test]
    fn wfp_preparation_binds_launch_sid_pid_and_creation_identity() {
        let mut request = sample_prepare_request();
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
        )
        .is_ok());
        request.launcher_pid += 1;
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
        )
        .is_err());
        request = sample_prepare_request();
        request.launcher_creation_time_100ns += 1;
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
        )
        .is_err());
        request = sample_prepare_request();
        request.package_sid = "S-1-5-21-1-2-3-1001".into();
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
        )
        .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn wfp_preparation_rejects_missing_bad_and_mismatched_acknowledgements() {
        let sid = "S-1-15-2-1-2-3-4-5-6-7-8-9-10-11-12";
        assert!(validate_prepare_ack(None, &"a".repeat(64), sid).is_err());
        let mut ack = PrepareAck {
            version: 1,
            launch_id: "a".repeat(64),
            package_sid: sid.into(),
            ready: true,
            detail: "ready".into(),
        };
        assert!(validate_prepare_ack(Some(&ack), &"a".repeat(64), sid).is_ok());
        ack.launch_id = "b".repeat(64);
        assert!(validate_prepare_ack(Some(&ack), &"a".repeat(64), sid).is_err());
        ack.launch_id = "a".repeat(64);
        ack.ready = false;
        assert!(validate_prepare_ack(Some(&ack), &"a".repeat(64), sid).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn wfp_preparation_rejects_malformed_oversized_and_duplicate_messages() {
        assert!(decode_prepare_request(b"{").is_err());
        assert!(decode_prepare_request(&vec![b'x'; MAX_PREPARE_FRAME + 1]).is_err());
        let request = sample_prepare_request();
        let encoded = serde_json::to_vec(&request).unwrap();
        assert!(decode_prepare_request(&encoded).is_ok());
        assert!(!is_duplicate_prepare(true, &PrepareRead::Pending));
        assert!(is_duplicate_prepare(true, &PrepareRead::Request(request)));
        assert!(!is_duplicate_prepare(
            false,
            &PrepareRead::Request(sample_prepare_request())
        ));
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
    fn snapshot_marker_owns_the_top_level_job_root() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        std::fs::create_dir(&input).unwrap();
        let jobfile = input.join("job.json");
        assert_eq!(
            snapshot_root_for_jobfile(&jobfile).as_deref(),
            Some(temp.path())
        );
    }

    #[test]
    fn unconfirmed_containment_keeps_the_snapshot_tree() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        std::fs::write(root.join("job.json"), b"snapshot").unwrap();
        let retained = retain_snapshot_if_unconfirmed(temp, true).unwrap();
        assert_eq!(retained, root);
        assert_eq!(
            std::fs::read(retained.join("job.json")).unwrap(),
            b"snapshot"
        );
        std::fs::remove_dir_all(retained).unwrap();
    }

    #[test]
    fn confirmed_containment_keeps_tempdir_cleanup_armed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_path_buf();
        std::fs::write(path.join("job.json"), b"snapshot").unwrap();
        assert!(retain_snapshot_if_unconfirmed(temp, false).is_none());
        assert!(!path.exists());
    }

    #[test]
    fn process_tree_cleanup_requires_a_confirmed_zero_process_count() {
        use std::cell::Cell;
        use std::collections::VecDeque;
        let terminate_called = Cell::new(false);
        let mut counts = VecDeque::from([3, 2, 1, 0]);
        let had_residual = process_tree_barrier(
            || Ok(counts.pop_front().unwrap()),
            || {
                terminate_called.set(true);
                Ok(())
            },
            || {},
            3,
        )
        .unwrap();
        assert!(had_residual);
        assert!(terminate_called.get());

        let terminate_called = Cell::new(false);
        let had_residual = process_tree_barrier(
            || Ok(0),
            || {
                terminate_called.set(true);
                Ok(())
            },
            || {},
            3,
        )
        .unwrap();
        assert!(!had_residual);
        assert!(!terminate_called.get());

        let error = process_tree_barrier(|| Ok(1), || Ok(()), || {}, 2).unwrap_err();
        assert!(error.contains("still has 1 active process"));
        assert!(process_tree_barrier(|| Err(5), || Ok(()), || {}, 2)
            .unwrap_err()
            .contains("Win32 error 5"));
    }

    #[test]
    fn persistent_marker_blocks_restart_sweep_and_uninstall_cleanup() {
        assert!(!marker_blocks_cleanup::<()>(&Ok(false)));
        assert!(marker_blocks_cleanup::<()>(&Ok(true)));
        assert!(marker_blocks_cleanup::<()>(&Err(())));
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
