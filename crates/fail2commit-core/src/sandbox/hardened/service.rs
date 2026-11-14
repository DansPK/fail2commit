//! Minimal authenticated service transport for SPEC-018 §4.2.

#![allow(unsafe_code)]

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
    #[serde(default)]
    effect_probe_passed: bool,
    #[serde(default)]
    network_probe_available: bool,
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
    proxy_port: Option<u16>,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareAck {
    version: u32,
    launch_id: String,
    package_sid: String,
    proxy_port: Option<u16>,
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
    if job.network == crate::isolation::NetworkMode::Internet && !status.probe_available {
        return Err(crate::Error::isolation_unavailable(
            "hardened Internet jobs remain unavailable until the package-scoped WFP route effect probes pass",
        ));
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

#[cfg(target_os = "linux")]
pub(super) fn run_linux(
    job: &crate::isolation::JobSpec,
) -> crate::Result<crate::isolation::JobOutcome> {
    use std::os::unix::fs::OpenOptionsExt;

    let state = super::lifecycle::installed_state()?;
    // SAFETY: getuid has no preconditions and returns the real caller uid.
    let uid = unsafe { libc::getuid() };
    if uid != state.installer_uid || uid == 0 {
        return Err(crate::Error::rejected(
            "hardened launch must be requested by the installed non-root account",
        ));
    }
    let status = linux_service_request(
        &Request {
            op: "PROBE".into(),
            job_dir: None,
        },
        std::time::Duration::from_secs(240),
    )?;
    if !status.ok || !status.service_running {
        return Err(crate::Error::isolation_unavailable(status.detail));
    }
    if !status.probe_available {
        return Err(crate::Error::isolation_unavailable(
            "hardened Linux launcher, watchdog and platform controls are unavailable",
        ));
    }
    if job.network == crate::isolation::NetworkMode::Internet && !status.network_probe_available {
        return Err(crate::Error::isolation_unavailable(
            "hardened Linux Internet jobs remain unavailable until service-owned egress effect probes pass",
        ));
    }

    let paths = crate::paths::TrustedPaths::resolve()?;
    crate::fsutil::ensure_private_dir(&paths.cache_dir)?;
    let job_dir = tempfile::Builder::new()
        .prefix("hardened-job-")
        .tempdir_in(&paths.cache_dir)?;
    let stage_root = paths.cache_dir.join("sandbox-stage");
    let encoded = super::protocol::encode_hardened_job(job, &stage_root)?;
    let job_path = job_dir.path().join("job.json");
    let mut job_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&job_path)?;
    job_file.write_all(&encoded)?;
    job_file.sync_all()?;
    let request = Request {
        op: "LAUNCH".into(),
        job_dir: Some(job_dir.path().to_string_lossy().into_owned()),
    };
    let reply = linux_service_request(
        &request,
        job.limits
            .timeout
            .saturating_add(std::time::Duration::from_secs(45)),
    )?;
    if !reply.ok || !reply.containment_confirmed {
        return Err(crate::Error::isolation_unavailable(reply.detail));
    }
    let outcome_path = job_dir.path().join("outcome.json");
    let outcome_file = open_linux_regular(&outcome_path, uid, super::protocol::MAX_OUTCOME_BYTES)?;
    let mut bytes = Vec::new();
    outcome_file
        .take((super::protocol::MAX_OUTCOME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    super::protocol::decode_outcome(&bytes)
}

#[cfg(target_os = "linux")]
pub(super) fn launch_linux_hidden(jobfile: &Path, watchdog: Option<u64>) -> crate::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let watchdog_fd = watchdog
        .and_then(|fd| i32::try_from(fd).ok())
        .filter(|fd| *fd >= 0)
        .ok_or_else(|| crate::Error::rejected("hardened Linux launcher requires a watchdog fd"))?;
    // SAFETY: geteuid has no preconditions and returns the effective uid.
    if unsafe { libc::geteuid() } == 0 {
        return Err(crate::Error::rejected(
            "hardened Linux launcher must not run as root",
        ));
    }
    let output_dir = validate_linux_snapshot_paths(jobfile)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(jobfile)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > super::protocol::MAX_JOB_BYTES as u64
    {
        return Err(crate::Error::integrity(
            "hardened Linux launcher job snapshot owner, type or size is invalid",
        ));
    }
    let mut bytes = Vec::new();
    file.take((super::protocol::MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != metadata.len() as usize {
        return Err(crate::Error::integrity(
            "hardened Linux launcher job snapshot changed while reading",
        ));
    }
    let (job, _stage_root, diagnostic) = super::protocol::decode_hardened_job_for_service(&bytes)?;
    if diagnostic {
        return Err(crate::Error::rejected(
            "Linux hardened diagnostic jobs are unavailable in this build",
        ));
    }
    let outcome = crate::sandbox::linux::run_hardened(&job, watchdog_fd)?;
    let encoded = super::protocol::encode_outcome(&outcome)?;
    if encoded.len() > super::protocol::MAX_OUTCOME_BYTES {
        return Err(crate::Error::integrity(
            "hardened Linux launcher outcome exceeded its size limit",
        ));
    }
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(output_dir.join("outcome.json"))?;
    output.write_all(&encoded)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_linux_snapshot_paths(jobfile: &Path) -> crate::Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let jobs = Path::new("/run/fail2commit-hardened/jobs");
    let canonical_jobs = jobs.canonicalize()?;
    let canonical_jobfile = jobfile.canonicalize()?;
    if canonical_jobfile != jobfile
        || jobfile.file_name().and_then(|s| s.to_str()) != Some("job.json")
    {
        return Err(crate::Error::integrity(
            "hardened Linux launcher path is not the canonical service snapshot job.json",
        ));
    }
    let input = jobfile
        .parent()
        .ok_or_else(|| crate::Error::integrity("hardened Linux snapshot has no input directory"))?;
    let root = input
        .parent()
        .ok_or_else(|| crate::Error::integrity("hardened Linux snapshot has no root directory"))?;
    if input.file_name().and_then(|s| s.to_str()) != Some("input")
        || root.parent() != Some(canonical_jobs.as_path())
    {
        return Err(crate::Error::integrity(
            "hardened Linux snapshot is outside the service-owned job store",
        ));
    }
    for path in [canonical_jobs.as_path(), root, input] {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
        {
            return Err(crate::Error::integrity(
                "hardened Linux snapshot ancestor is not a private root-owned directory",
            ));
        }
    }
    let output = root.join("output");
    let output_metadata = std::fs::symlink_metadata(&output)?;
    if !output_metadata.is_dir()
        || output_metadata.file_type().is_symlink()
        || output_metadata.uid() != 0
        || output_metadata.mode() & 0o077 != 0
    {
        return Err(crate::Error::integrity(
            "hardened Linux outcome directory is not a private root-owned ACL grant directory",
        ));
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn linux_service_request(
    request: &Request,
    read_timeout: std::time::Duration,
) -> crate::Result<Response> {
    use std::io::{BufRead, BufReader};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect("/run/fail2commit-hardened/sock")?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
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
            "hardened service peer is not verified as root",
        ));
    }
    let mut encoded = serde_json::to_vec(request)
        .map_err(|_| crate::Error::internal("cannot encode hardened Linux service request"))?;
    encoded.push(b'\n');
    if encoded.len() >= MAX_REQUEST {
        return Err(crate::Error::invalid(
            "hardened Linux service request exceeds size limit",
        ));
    }
    stream.write_all(&encoded)?;
    stream.flush()?;
    let mut line = Vec::new();
    BufReader::new(stream)
        .take(MAX_REQUEST as u64)
        .read_until(b'\n', &mut line)?;
    decode_response(&line)
}

#[cfg(target_os = "linux")]
fn open_linux_regular(path: &Path, owner_uid: u32, limit: usize) -> crate::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > limit as u64
    {
        return Err(crate::Error::integrity(
            "hardened Linux outcome file owner, type or size is invalid",
        ));
    }
    Ok(file)
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
        effect_probe_passed: false,
        network_probe_available: false,
        containment_confirmed: true,
        detail: bounded_linux_detail(detail.into()),
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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PreparationCleanupProof {
    ack_sent: bool,
    launcher_tree_empty: bool,
    package_grants_revoked: bool,
    package_policy_closed: bool,
    profile_unloaded: bool,
}

#[cfg(any(windows, test))]
impl PreparationCleanupProof {
    fn cleanup_complete(self) -> bool {
        self.launcher_tree_empty
            && self.package_grants_revoked
            && self.package_policy_closed
            && self.profile_unloaded
    }

    fn may_clear_marker(self) -> bool {
        self.cleanup_complete()
    }

    fn operation_succeeded(self) -> bool {
        self.ack_sent && self.cleanup_complete()
    }
}

#[cfg(any(windows, test))]
fn send_policy_ack(
    proof: &mut PreparationCleanupProof,
    send: impl FnOnce() -> crate::Result<()>,
) -> crate::Result<()> {
    send()?;
    proof.ack_sent = true;
    Ok(())
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
    let acl_dir = super::lifecycle::linux_acl_journal_dir();
    ensure_linux_private_dir(&acl_dir, 0o700)?;
    super::linux_acl::recover(&acl_dir)?;
    ensure_linux_private_dir(Path::new("/run/fail2commit-hardened/jobs"), 0o700)?;
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
    let sandbox_uid = state.sandbox_uid.ok_or_else(|| {
        crate::Error::integrity("hardened Linux install state has no sandbox uid")
    })?;
    let _identity = linux_sandbox_identity(&state.account, sandbox_uid)?;
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
fn ensure_linux_private_dir(path: &Path, mode: u32) -> crate::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match std::fs::create_dir(path) {
        Ok(()) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(crate::Error::integrity(format!(
            "hardened service directory is not root-owned with mode {mode:o}: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(super) fn probe_linux() -> (bool, bool, bool, bool, String) {
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let result = (|| -> crate::Result<Response> {
        let mut stream = UnixStream::connect("/run/fail2commit-hardened/sock")?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(240)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
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
        stream.write_all(b"{\"op\":\"PROBE\"}\n")?;
        let mut line = String::new();
        BufReader::new(stream)
            .take(MAX_REQUEST as u64)
            .read_line(&mut line)?;
        let r = serde_json::from_str::<Response>(&line)
            .map_err(|_| crate::Error::integrity("malformed service status response"))?;
        if !r.service_running {
            return Err(crate::Error::isolation_unavailable(
                "service refused status request",
            ));
        }
        Ok(r)
    })();
    match result {
        Ok(r) => (
            r.service_running,
            true,
            r.probe_available,
            r.network_probe_available,
            r.detail,
        ),
        Err(e) => (false, false, false, false, e.message),
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(super) fn probe_windows() -> (bool, bool, bool, String) {
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
        file.write_all(b"{\"op\":\"PROBE\"}\n")?;
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
        Ok(reply) => (true, true, reply.effect_probe_passed, reply.detail),
        Err(e) => (false, false, false, e.message),
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
    let result = if !peer_uid_allowed(uid, installer, sandbox) {
        linux_response(false, false, "peer uid is not authorized")
    } else if let Err(error) = super::linux_acl::recover(&super::lifecycle::linux_acl_journal_dir())
    {
        linux_response(false, false, error.message)
    } else {
        match req.op.as_str() {
            "PROBE" if req.job_dir.is_none() => {
                match linux_mandatory_probe_cached(uid, sandbox, stream) {
                    Ok((platform, network, detail)) => {
                        linux_status_response(platform, network, detail)
                    }
                    Err(error) => linux_status_response(false, false, error.message),
                }
            }
            "LAUNCH" => match req.job_dir.as_deref() {
                Some(job_dir) => {
                    match run_linux_service_job(
                        job_dir,
                        uid,
                        sandbox,
                        stream,
                        false,
                        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        None,
                    ) {
                        Ok(detail) => linux_response(true, true, detail),
                        Err(error) => linux_response(false, false, error.message),
                    }
                }
                None => linux_response(false, false, "job_dir is required"),
            },
            _ => linux_response(false, false, "unknown or malformed operation"),
        }
    };
    serde_json::to_writer(&mut *stream, &result)
        .map_err(|e| crate::Error::internal(e.to_string()))?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_response(ok: bool, contained: bool, detail: impl Into<String>) -> Response {
    Response {
        ok,
        service_running: true,
        probe_available: false,
        effect_probe_passed: false,
        network_probe_available: false,
        containment_confirmed: contained,
        detail: bounded_linux_detail(detail.into()),
    }
}

#[cfg(any(target_os = "linux", windows, test))]
fn bounded_linux_detail(detail: String) -> String {
    detail.chars().take(512).collect()
}

#[cfg(target_os = "linux")]
fn linux_status_response(
    probe_available: bool,
    network_probe_available: bool,
    detail: impl Into<String>,
) -> Response {
    Response {
        ok: probe_available && network_probe_available,
        service_running: true,
        probe_available,
        effect_probe_passed: false,
        network_probe_available,
        containment_confirmed: true,
        detail: bounded_linux_detail(detail.into()),
    }
}

#[cfg(target_os = "linux")]
fn linux_mandatory_probe_cached(
    peer_uid: u32,
    sandbox_uid: u32,
    client: &std::os::unix::net::UnixStream,
) -> crate::Result<(bool, bool, String)> {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static LAST_PASS: OnceLock<Mutex<Option<(Instant, String)>>> = OnceLock::new();
    let cache = LAST_PASS.get_or_init(|| Mutex::new(None));
    {
        let last = cache
            .lock()
            .map_err(|_| crate::Error::internal("Linux mandatory probe cache is poisoned"))?;
        if let Some((at, detail)) = last.as_ref() {
            if at.elapsed() < Duration::from_secs(30) {
                return Ok((true, true, detail.clone()));
            }
        }
    }
    let result = linux_mandatory_probe(peer_uid, sandbox_uid, client)?;
    if result.0 && result.1 {
        let mut last = cache
            .lock()
            .map_err(|_| crate::Error::internal("Linux mandatory probe cache is poisoned"))?;
        *last = Some((Instant::now(), result.2.clone()));
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn linux_mandatory_probe(
    peer_uid: u32,
    sandbox_uid: u32,
    client: &std::os::unix::net::UnixStream,
) -> crate::Result<(bool, bool, String)> {
    let state = super::lifecycle::installed_state()?;
    if state.installer_uid != peer_uid || state.sandbox_uid != Some(sandbox_uid) {
        return Err(crate::Error::integrity(
            "Linux probe identity differs from the authenticated install",
        ));
    }
    if peer_uid == 0 || peer_uid == sandbox_uid {
        return Err(crate::Error::rejected(
            "Linux probe requires the recorded installer peer",
        ));
    }
    let executable = trusted_linux_executable(&state.executable)?;
    let _ = linux_sandbox_identity(&state.account, sandbox_uid)?;
    trusted_linux_tool(&["/usr/bin/setpriv", "/bin/setpriv"])?;
    trusted_linux_tool(&["/usr/bin/systemd-run"])?;
    super::linux_acl::verify_required_tools()?;
    linux_watchdog_probe_cached(&state, sandbox_uid)?;

    let platform_outcome = run_linux_probe_job(
        &executable,
        peer_uid,
        sandbox_uid,
        client,
        crate::isolation::NetworkMode::None,
        false,
        true,
    )?;
    if !linux_probe_outcome_passed(&platform_outcome, b"F2C-LINUX-PLATFORM-PROBE-PASS\n") {
        return Err(crate::Error::isolation_unavailable(
            "Linux account, system-scope, ACL, read-only or writable-stage effect probe failed",
        ));
    }

    let egress_outcome = match run_linux_probe_job(
        &executable,
        peer_uid,
        sandbox_uid,
        client,
        crate::isolation::NetworkMode::Internet,
        false,
        false,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            return Ok((
                true,
                false,
                format!(
                    "Linux platform probe passed; shared egress effect probe failed: {}",
                    error.message
                ),
            ));
        }
    };
    if !linux_effect_probe_outcome_passed(&egress_outcome) {
        return Ok((
            true,
            false,
            "Linux platform probe passed; public-allow or restricted-route proxy effects failed"
                .into(),
        ));
    }

    let bait_outcome = match run_linux_probe_job(
        &executable,
        peer_uid,
        sandbox_uid,
        client,
        crate::isolation::NetworkMode::Internet,
        true,
        false,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            return Ok((
                true,
                false,
                format!(
                    "Linux proxy route probe passed; bait-trip probe failed: {}",
                    error.message
                ),
            ));
        }
    };
    if !linux_bait_probe_outcome_passed(&bait_outcome) {
        return Ok((
            true,
            false,
            "Linux proxy route probe passed; bait trip did not kill the job with a bait event"
                .into(),
        ));
    }
    Ok((
        true,
        true,
        "Linux account, system-scope limits, ACL stage, Bubblewrap, watchdog, shared public-only egress, direct-route refusal and bait-trip probes passed".into(),
    ))
}

#[cfg(target_os = "linux")]
fn run_linux_probe_job(
    executable: &Path,
    peer_uid: u32,
    sandbox_uid: u32,
    client: &std::os::unix::net::UnixStream,
    network: crate::isolation::NetworkMode,
    bait: bool,
    platform_only: bool,
) -> crate::Result<crate::isolation::JobOutcome> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;

    let acl_dir = super::lifecycle::linux_acl_journal_dir();
    let probe_root = super::linux_acl::probe_stage_dir(&acl_dir)?;
    let retention = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let temp = tempfile::Builder::new()
        .prefix("probe-")
        .tempdir_in(&probe_root)?;
    let temp = super::linux_acl::RetainedTempDir::new(temp, retention.clone());
    let root = temp.path().canonicalize()?;
    let work = root.join("work");
    let read_only = root.join("readonly");
    std::fs::create_dir(&work)?;
    std::fs::create_dir(&read_only)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o700))?;
    let read_only_file = read_only.join("probe.txt");
    let mut fixture = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&read_only_file)?;
    fixture.write_all(b"f2c-hardened-readonly-probe\n")?;
    fixture.sync_all()?;
    drop(fixture);
    std::fs::set_permissions(&read_only_file, std::fs::Permissions::from_mode(0o400))?;

    let mut args = vec![
        "sandbox".into(),
        "hardened-egress-probe".into(),
        "--expected-uid".into(),
        sandbox_uid.to_string().into(),
    ];
    if bait {
        args.push("--bait-trip".into());
    }
    if platform_only {
        args.push("--platform-only".into());
    }
    let job = crate::isolation::JobSpec {
        program: PathBuf::from(executable),
        args,
        cwd: work.clone(),
        env: Vec::new(),
        read_only: vec![read_only.clone()],
        work_dir: work.clone(),
        exports: Vec::new(),
        export_to: None,
        limits: crate::isolation::JobLimits {
            timeout: std::time::Duration::from_secs(if bait { 15 } else { 60 }),
            memory_bytes: Some(256 * 1024 * 1024),
            max_processes: Some(32),
            max_output_bytes: 32 * 1024,
            disk_bytes: Some(2 * 1024 * 1024),
        },
        network,
        bait,
    };
    let encoded = super::protocol::encode_hardened_job(&job, &root)?;
    let jobfile = root.join("job.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&jobfile)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);

    fn chown_to_peer(path: &Path, uid: u32) -> crate::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| crate::Error::integrity("probe stage path contains NUL"))?;
        // SAFETY: path is a canonical service-created fixture path and uid is
        // the authenticated installer identity recorded at installation.
        if unsafe { libc::chown(path_c.as_ptr(), uid, u32::MAX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    chown_to_peer(&root, peer_uid)?;
    chown_to_peer(&work, peer_uid)?;
    chown_to_peer(&read_only, peer_uid)?;
    chown_to_peer(&read_only_file, peer_uid)?;
    chown_to_peer(&jobfile, peer_uid)?;
    let root_metadata = std::fs::symlink_metadata(&root)?;
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || root_metadata.uid() != peer_uid
        || root_metadata.mode() & 0o077 != 0
    {
        return Err(crate::Error::integrity(
            "Linux fixed probe stage did not acquire the expected peer-owned identity",
        ));
    }
    let job_dir = root
        .to_str()
        .ok_or_else(|| crate::Error::integrity("Linux probe stage path is not UTF-8"))?;
    run_linux_service_job(
        job_dir,
        peer_uid,
        sandbox_uid,
        client,
        network == crate::isolation::NetworkMode::Internet,
        retention,
        Some(&probe_root),
    )?;
    let output = open_linux_regular(
        &root.join("outcome.json"),
        peer_uid,
        super::protocol::MAX_OUTCOME_BYTES,
    )?;
    let mut bytes = Vec::new();
    output
        .take((super::protocol::MAX_OUTCOME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    super::protocol::decode_outcome(&bytes)
}

#[cfg(target_os = "linux")]
fn linux_probe_outcome_passed(outcome: &crate::isolation::JobOutcome, marker: &[u8]) -> bool {
    outcome.status == crate::isolation::JobStatus::Exited(0)
        && outcome.stdout == marker
        && outcome.exported.is_empty()
        && !outcome.truncated
}

#[cfg(target_os = "linux")]
fn linux_effect_probe_outcome_passed(outcome: &crate::isolation::JobOutcome) -> bool {
    linux_probe_outcome_passed(outcome, b"F2C-LINUX-EFFECT-PROBE-PASS\n")
        && outcome
            .report
            .events
            .iter()
            .any(|event| event.kind == crate::isolation::ActivityKind::NetAllowed)
        && outcome
            .report
            .events
            .iter()
            .any(|event| event.kind == crate::isolation::ActivityKind::NetRefused)
}

#[cfg(target_os = "linux")]
fn linux_bait_probe_outcome_passed(outcome: &crate::isolation::JobOutcome) -> bool {
    outcome.status == crate::isolation::JobStatus::Killed
        && outcome.report.bait_touched()
        && outcome.exported.is_empty()
}

#[cfg(target_os = "linux")]
pub(super) fn run_linux_egress_probe_child(
    expected_uid: u32,
    bait_trip: bool,
    platform_only: bool,
) -> crate::Result<()> {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
    use std::time::Duration;

    // SAFETY: geteuid/getuid have no preconditions and report the real IDs.
    if expected_uid == 0 || unsafe { libc::geteuid() } != expected_uid {
        return Err(crate::Error::rejected(
            "Linux effect probe is not running as the installed sandbox account",
        ));
    }
    if unsafe { libc::getuid() } != expected_uid {
        return Err(crate::Error::rejected(
            "Linux effect probe real uid differs from its effective uid",
        ));
    }
    if bait_trip {
        let proxy = validated_probe_proxy()?;
        let token = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| crate::Error::integrity("probe bait value is unavailable"))?;
        if token.len() < 32 {
            return Err(crate::Error::integrity("probe bait value is malformed"));
        }
        let mut stream = TcpStream::connect_timeout(&proxy, Duration::from_secs(3))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        write!(
            stream,
            "GET http://bait-trip.invalid/ HTTP/1.1\r\nHost: bait-trip.invalid\r\nX-F2C-Probe: {token}\r\nConnection: close\r\n\r\n"
        )?;
        let mut response = Vec::new();
        stream.take(1024).read_to_end(&mut response)?;
        if !response.starts_with(b"HTTP/1.1 403") && !response.starts_with(b"HTTP/1.0 403") {
            return Err(crate::Error::isolation_unavailable(
                "shared egress proxy did not refuse the probe bait request",
            ));
        }
        return Ok(());
    }

    let work = std::env::current_dir()?;
    let read_only_file = work
        .parent()
        .ok_or_else(|| crate::Error::integrity("Linux probe work path has no parent"))?
        .join("readonly")
        .join("probe.txt");
    if !linux_mount_is_read_only(&read_only_file)? {
        return Err(crate::Error::isolation_unavailable(
            "Linux service probe read-only fixture is not on a read-only mount",
        ));
    }
    if std::fs::read(&read_only_file)? != b"f2c-hardened-readonly-probe\n" {
        return Err(crate::Error::isolation_unavailable(
            "Linux service probe cannot read its peer-owned read-only fixture",
        ));
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .open(&read_only_file)
    {
        Ok(_) => {
            return Err(crate::Error::isolation_unavailable(
                "Linux service probe unexpectedly gained write access to its read-only fixture",
            ));
        }
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EROFS)
            ) => {}
        Err(_) => {
            return Err(crate::Error::isolation_unavailable(
                "Linux read-only fixture write failed for an unverified reason",
            ));
        }
    }
    let writable_probe = work.join("writable-probe.txt");
    std::fs::write(&writable_probe, b"f2c-hardened-writable-probe\n")?;
    if std::fs::read(&writable_probe)? != b"f2c-hardened-writable-probe\n" {
        return Err(crate::Error::isolation_unavailable(
            "Linux service probe could not read back its writable stage fixture",
        ));
    }
    if platform_only {
        std::io::stdout().write_all(b"F2C-LINUX-PLATFORM-PROBE-PASS\n")?;
        return Ok(());
    }
    let proxy = validated_probe_proxy()?;

    let direct_tcp = [
        "1.1.1.1:80",
        "10.0.0.1:80",
        "169.254.169.254:80",
        "1.1.1.1:53",
        "127.0.0.1:1",
        "[::1]:1",
        "[fd00:ec2::254]:80",
        "[fd00:ec2::254]:53",
        "[2606:4700:4700::1111]:80",
        "[2606:4700:4700::1111]:53",
    ];
    for endpoint in direct_tcp {
        let address = endpoint
            .to_socket_addrs()
            .map_err(|_| {
                crate::Error::integrity("fixed Linux direct-route probe address is invalid")
            })?
            .next()
            .ok_or_else(|| crate::Error::integrity("fixed Linux probe address resolved empty"))?;
        if TcpStream::connect_timeout(&address, Duration::from_millis(750)).is_ok() {
            return Err(crate::Error::isolation_unavailable(format!(
                "direct sandbox TCP route unexpectedly reached {endpoint}"
            )));
        }
    }

    for (bind, destination) in [
        ("0.0.0.0:0", "1.1.1.1:53"),
        ("0.0.0.0:0", "169.254.169.254:53"),
        ("0.0.0.0:0", "127.0.0.1:53"),
        ("[::]:0", "[2606:4700:4700::1111]:53"),
        ("[::]:0", "[fd00:ec2::254]:53"),
    ] {
        let socket = UdpSocket::bind(bind).map_err(|_| {
            crate::Error::isolation_unavailable("cannot create the fixed UDP probe socket")
        })?;
        let destination = destination
            .to_socket_addrs()
            .map_err(|_| crate::Error::integrity("fixed UDP probe address is invalid"))?
            .next()
            .ok_or_else(|| crate::Error::integrity("fixed UDP probe address resolved empty"))?;
        if socket
            .send_to(
                b"\0\0\x01\0\0\x01\0\0\0\0\0\0\x01a\0\0\x01\0\x01",
                destination,
            )
            .is_ok()
        {
            return Err(crate::Error::isolation_unavailable(
                "direct sandbox DNS/UDP send unexpectedly succeeded",
            ));
        }
    }

    // The seccomp filter must deny listening specifically with EPERM. A
    // generic bind failure would not prove the syscall control.
    for address in ["127.0.0.1:0", "[::1]:0"] {
        match TcpListener::bind(address) {
            Ok(listener) => {
                drop(listener);
                return Err(crate::Error::isolation_unavailable(
                    "sandbox unexpectedly opened a listening TCP socket",
                ));
            }
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {}
            Err(_) => {
                return Err(crate::Error::isolation_unavailable(
                    "sandbox listen control did not fail with seccomp EPERM",
                ));
            }
        }
    }

    let public = proxy_http_request(
        proxy,
        b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )?;
    let status = public
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if !(status.starts_with(b"HTTP/1.1 200") || status.starts_with(b"HTTP/1.0 200"))
        || !public
            .windows(b"Example Domain".len())
            .any(|w| w == b"Example Domain")
    {
        return Err(crate::Error::isolation_unavailable(
            "shared egress proxy did not return the fixed public probe page",
        ));
    }

    for target in [
        "169.254.169.254:80",
        "127.0.0.1:1",
        "[::1]:1",
        "[fd00:ec2::254]:80",
    ] {
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        let refused = proxy_http_request(proxy, request.as_bytes())?;
        if !(refused.starts_with(b"HTTP/1.1 403") || refused.starts_with(b"HTTP/1.0 403")) {
            return Err(crate::Error::isolation_unavailable(
                "shared egress proxy allowed a private, metadata or loopback destination",
            ));
        }
    }
    std::io::stdout().write_all(b"F2C-LINUX-EFFECT-PROBE-PASS\n")?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn linux_mount_is_read_only(path: &Path) -> crate::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| crate::Error::rejected("probe fixture path contains NUL"))?;
    // SAFETY: statvfs receives a valid NUL-terminated path and writable struct.
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut info) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(info.f_flag & libc::ST_RDONLY as u64 != 0)
}

#[cfg(target_os = "linux")]
fn validated_probe_proxy() -> crate::Result<std::net::SocketAddr> {
    use std::net::SocketAddr;
    let value = std::env::var("HTTP_PROXY")
        .map_err(|_| crate::Error::integrity("Linux effect probe proxy is unavailable"))?;
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| crate::Error::integrity("Linux effect probe proxy endpoint is invalid"))?;
    for key in [
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        if std::env::var(key).ok().as_deref() != Some(value.as_str()) {
            return Err(crate::Error::integrity(
                "Linux effect probe proxy environment is incomplete",
            ));
        }
    }
    for key in ["NO_PROXY", "no_proxy"] {
        if !std::env::var(key).unwrap_or_default().is_empty() {
            return Err(crate::Error::integrity(
                "Linux effect probe bypass list is not empty",
            ));
        }
    }
    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
}

#[cfg(target_os = "linux")]
fn proxy_http_request(proxy: std::net::SocketAddr, request: &[u8]) -> crate::Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    const MAX_RESPONSE: usize = 64 * 1024;
    let mut stream = TcpStream::connect_timeout(&proxy, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(request)?;
    let mut response = Vec::new();
    stream
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut response)?;
    if response.len() > MAX_RESPONSE {
        return Err(crate::Error::isolation_unavailable(
            "Linux effect probe response exceeded its bound",
        ));
    }
    Ok(response)
}

#[cfg(target_os = "linux")]
fn linux_watchdog_probe(
    state: &super::lifecycle::InstallState,
    sandbox_uid: u32,
) -> crate::Result<()> {
    if state.sandbox_uid != Some(sandbox_uid) || state.installer_uid == 0 {
        return Err(crate::Error::integrity(
            "hardened Linux watchdog probe install identity is invalid",
        ));
    }
    let executable = trusted_linux_executable(&state.executable)?;
    let (uid, gid) = linux_sandbox_identity(&state.account, sandbox_uid)?;
    let setpriv = trusted_linux_tool(&["/usr/bin/setpriv", "/bin/setpriv"])?;
    let systemd_run = trusted_linux_tool(&["/usr/bin/systemd-run"])?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| crate::Error::internal("cannot generate Linux probe scope identity"))?;
    // run_hardened requires this system-scope identity and validates its exact
    // cgroup limits before launching Bubblewrap.
    let unit = format!("f2c-hardened-job-{}.scope", hex::encode(random));
    random.fill(0);
    let marker = super::linux_acl::mark_probe_scope(
        &super::lifecycle::linux_acl_journal_dir(),
        sandbox_uid,
        &unit,
    )?;
    let result = linux_watchdog_probe_in_scope(&unit, executable, setpriv, systemd_run, uid, gid);
    match result {
        Ok(()) => super::linux_acl::clear_probe_scope_marker(&marker, &unit),
        Err(error) => {
            // Reconcile before returning when possible. If systemd cannot
            // prove the exact scope dead, the prewritten marker remains and
            // every later request fails in ACL recovery until it is stopped.
            match stop_and_confirm_linux_scope(&unit) {
                Ok(()) => {
                    if let Err(cleanup) =
                        super::linux_acl::clear_probe_scope_marker(&marker, &unit)
                    {
                        Err(crate::Error::isolation_unavailable(format!(
                            "watchdog probe failed: {}; scope cleanup is verified but its refusal marker remains: {}",
                            error.message, cleanup.message
                        )))
                    } else {
                        Err(error)
                    }
                }
                Err(cleanup) => Err(crate::Error::isolation_unavailable(format!(
                    "watchdog probe failed: {}; scope death is unconfirmed and refusal marker {} is retained: {}",
                    error.message,
                    marker.display(),
                    cleanup.message
                ))),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_watchdog_probe_in_scope(
    unit: &str,
    executable: std::path::PathBuf,
    setpriv: std::path::PathBuf,
    systemd_run: std::path::PathBuf,
    uid: u32,
    gid: u32,
) -> crate::Result<()> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut command = Command::new(systemd_run);
    command
        .args([
            "--scope",
            "--wait",
            "--pipe",
            "--quiet",
            "--collect",
            "--expand-environment=no",
            "--unit",
            unit,
            "--property",
            "TasksMax=8",
            "--property",
            "MemoryMax=134217728",
            "--property",
            "MemorySwapMax=0",
            "--",
        ])
        .arg(setpriv)
        .args([
            "--reuid",
            &uid.to_string(),
            "--regid",
            &gid.to_string(),
            "--init-groups",
            "--",
        ])
        .arg(executable)
        .args(["sandbox", "hardened-probe", "--watchdog", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|error| {
        crate::Error::isolation_unavailable(format!("cannot start Linux watchdog probe: {error}"))
    })?;
    let watchdog = child.stdin.take();
    let stdout = child.stdout.take();
    if watchdog.is_none() || stdout.is_none() {
        stop_linux_probe_child(unit, &mut child, watchdog, None)?;
        return Err(crate::Error::isolation_unavailable(
            "Linux watchdog probe control channel is unavailable",
        ));
    }
    let watchdog = watchdog.unwrap();
    let stdout = stdout.unwrap();
    let (output_thread, ready_rx) = linux_probe_output_thread(stdout);
    let ready = ready_rx.recv_timeout(Duration::from_secs(30));
    if !matches!(ready, Ok(bytes) if bytes == b"F2C-WATCHDOG-READY\n") {
        stop_linux_probe_child(unit, &mut child, Some(watchdog), Some(output_thread))?;
        return Err(crate::Error::isolation_unavailable(
            "Linux watchdog probe did not complete platform controls before its deadline",
        ));
    }
    // READY is written only after account, Bubblewrap and scope limit checks;
    // closing this pipe now exercises the actual launcher watchdog.
    drop(watchdog);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => {
                if !linux_scope_inactive(unit, Duration::from_secs(5))? {
                    stop_linux_probe_child(unit, &mut child, None, Some(output_thread))?;
                    return Err(crate::Error::isolation_unavailable(format!(
                        "Linux watchdog probe launcher exited with {status} before its scope stopped"
                    )));
                }
                let _ = output_thread.join();
                return Err(crate::Error::isolation_unavailable(format!(
                    "Linux watchdog probe launcher exited with {status}"
                )));
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                stop_linux_probe_child(unit, &mut child, None, Some(output_thread))?;
                return Err(crate::Error::isolation_unavailable(
                    "Linux watchdog probe did not stop within its service deadline",
                ));
            }
            Err(error) => {
                stop_linux_probe_child(unit, &mut child, None, Some(output_thread))?;
                return Err(crate::Error::isolation_unavailable(format!(
                    "cannot observe Linux watchdog probe launcher exit: {error}"
                )));
            }
        }
    }
    if !linux_scope_inactive(unit, Duration::from_secs(5))? {
        stop_linux_probe_child(unit, &mut child, None, Some(output_thread))?;
        return Err(crate::Error::isolation_unavailable(
            "Linux watchdog probe scope did not stop cleanly",
        ));
    }
    let (_ready, bytes) = output_thread
        .join()
        .map_err(|_| crate::Error::internal("Linux watchdog probe reader panicked"))??;
    if bytes.len() > 8192 {
        return Err(crate::Error::integrity(
            "Linux watchdog probe output exceeded its bound",
        ));
    }
    let result: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| crate::Error::integrity("Linux watchdog probe returned malformed output"))?;
    if result
        .get("watchdog_cancelled")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err(crate::Error::isolation_unavailable(
            "Linux watchdog effect probe did not confirm process-tree cancellation",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_probe_output_thread(
    stdout: std::process::ChildStdout,
) -> (
    std::thread::JoinHandle<std::io::Result<(Vec<u8>, Vec<u8>)>>,
    std::sync::mpsc::Receiver<Vec<u8>>,
) {
    use std::io::Read;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let output_thread = std::thread::spawn(move || -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let mut reader = BufReader::new(stdout);
        let mut ready = Vec::new();
        reader.by_ref().take(128).read_until(b'\n', &mut ready)?;
        let _ = ready_tx.send(ready.clone());
        let mut rest = Vec::new();
        reader.take(8193).read_to_end(&mut rest)?;
        Ok((ready, rest))
    });
    (output_thread, ready_rx)
}

#[cfg(target_os = "linux")]
fn stop_and_confirm_linux_scope(unit: &str) -> crate::Result<()> {
    stop_and_confirm_linux_scope_with(unit, terminate_linux_scope, linux_scope_inactive)
}

#[cfg(target_os = "linux")]
fn stop_and_confirm_linux_scope_with(
    unit: &str,
    terminate: impl FnOnce(&str) -> crate::Result<()>,
    readback: impl FnOnce(&str, std::time::Duration) -> crate::Result<bool>,
) -> crate::Result<()> {
    let kill = terminate(unit);
    if !readback(unit, std::time::Duration::from_secs(5))? {
        return Err(crate::Error::isolation_unavailable(
            "Linux watchdog probe scope remained active after bounded kill/readback",
        ));
    }
    kill
}

#[cfg(target_os = "linux")]
fn stop_linux_probe_child(
    unit: &str,
    child: &mut std::process::Child,
    watchdog: Option<std::process::ChildStdin>,
    output_thread: Option<std::thread::JoinHandle<std::io::Result<(Vec<u8>, Vec<u8>)>>>,
) -> crate::Result<()> {
    drop(watchdog);
    let scope_result = stop_and_confirm_linux_scope(unit);
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    scope_result?;
    if let Some(output_thread) = output_thread {
        let _ = output_thread.join();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_watchdog_probe_cached(
    state: &super::lifecycle::InstallState,
    sandbox_uid: u32,
) -> crate::Result<()> {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static LAST_PASS: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
    let cache = LAST_PASS.get_or_init(|| Mutex::new(None));
    {
        let last = cache
            .lock()
            .map_err(|_| crate::Error::internal("Linux probe cache is poisoned"))?;
        if last.is_some_and(|at| at.elapsed() < Duration::from_secs(30)) {
            return Ok(());
        }
    }
    linux_watchdog_probe(state, sandbox_uid)?;
    let mut last = cache
        .lock()
        .map_err(|_| crate::Error::internal("Linux probe cache is poisoned"))?;
    *last = Some(Instant::now());
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_linux_service_job(
    client_job_dir: &str,
    peer_uid: u32,
    sandbox_uid: u32,
    client: &std::os::unix::net::UnixStream,
    allow_internet_probe: bool,
    retention: super::linux_acl::RetentionLatch,
    trusted_probe_root: Option<&Path>,
) -> crate::Result<String> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let state = super::lifecycle::installed_state()?;
    if state.installer_uid != peer_uid || state.sandbox_uid != Some(sandbox_uid) {
        return Err(crate::Error::integrity(
            "service install identity differs from the authenticated peer",
        ));
    }
    linux_watchdog_probe_cached(&state, sandbox_uid)?;
    let executable = trusted_linux_executable(&state.executable)?;
    let (account_uid, account_gid) = linux_sandbox_identity(&state.account, sandbox_uid)?;
    let source_dir = std::path::PathBuf::from(client_job_dir);
    if !source_dir.is_absolute() || source_dir.canonicalize()? != source_dir {
        return Err(crate::Error::rejected(
            "hardened Linux job directory must be an absolute canonical path",
        ));
    }
    let source_dir_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(&source_dir)?;
    let source_dir_meta = source_dir_file.metadata()?;
    let opened_source_dir = std::fs::read_link(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        source_dir_file.as_raw_fd()
    ))?;
    let path_source_dir_meta = std::fs::symlink_metadata(&source_dir)?;
    if !source_dir_meta.is_dir()
        || source_dir_meta.uid() != peer_uid
        || source_dir_meta.mode() & 0o077 != 0
        || opened_source_dir != source_dir
        || path_source_dir_meta.dev() != source_dir_meta.dev()
        || path_source_dir_meta.ino() != source_dir_meta.ino()
    {
        return Err(crate::Error::rejected(
            "hardened Linux job directory is not private and peer-owned",
        ));
    }
    let source_fd = unsafe {
        libc::openat(
            source_dir_file.as_raw_fd(),
            c"job.json".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if source_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut source = unsafe { std::fs::File::from_raw_fd(source_fd) };
    let before = source.metadata()?;
    if !before.is_file()
        || before.uid() != peer_uid
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > super::protocol::MAX_JOB_BYTES as u64
    {
        return Err(crate::Error::integrity(
            "hardened Linux job request is not a bounded peer-owned regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut source)
        .take((super::protocol::MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = source.metadata()?;
    if bytes.len() != before.len() as usize
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.size() != after.size()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.uid() != after.uid()
        || before.nlink() != after.nlink()
    {
        return Err(crate::Error::integrity(
            "hardened Linux job request changed while it was snapshotted",
        ));
    }
    let (job, _stage_root, diagnostic) = super::protocol::decode_hardened_job_for_service(&bytes)?;
    if diagnostic {
        return Err(crate::Error::rejected(
            "Linux hardened diagnostic jobs are unavailable",
        ));
    }
    if job.network == crate::isolation::NetworkMode::Internet && !allow_internet_probe {
        return Err(crate::Error::isolation_unavailable(
            "Linux Internet execution is reserved for the authenticated fixed egress probe",
        ));
    }

    let runtime_jobs = Path::new("/run/fail2commit-hardened/jobs");
    let snapshot = tempfile::Builder::new()
        .prefix("job-")
        .tempdir_in(runtime_jobs)?;
    std::fs::set_permissions(snapshot.path(), std::fs::Permissions::from_mode(0o700))?;
    let snapshot = super::linux_acl::RetainedTempDir::new(snapshot, retention.clone());
    let root = snapshot.path();
    let input = root.join("input");
    let output = root.join("output");
    std::fs::create_dir(&input)?;
    std::fs::create_dir(&output)?;
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))?;
    let jobfile = input.join("job.json");
    let mut snapshot_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&jobfile)?;
    snapshot_file.write_all(&bytes)?;
    snapshot_file.sync_all()?;
    drop(snapshot_file);
    let root = root.canonicalize()?;
    let input = input.canonicalize()?;
    let output = output.canonicalize()?;
    let jobfile = jobfile.canonicalize()?;
    if !root.starts_with(runtime_jobs) || !input.starts_with(&root) || !output.starts_with(&root) {
        return Err(crate::Error::integrity(
            "hardened Linux immutable snapshot escaped its root-owned job store",
        ));
    }

    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| crate::Error::internal("cannot generate hardened job scope identity"))?;
    let unit = format!("f2c-hardened-job-{}.scope", hex::encode(random));
    random.fill(0);
    let extra = [
        (root.clone(), "--x"),
        (input.clone(), "r-x"),
        (jobfile.clone(), "r--"),
        (output.clone(), "rwx"),
    ];
    let journal_dir = super::lifecycle::linux_acl_journal_dir();
    let mut grants = super::linux_acl::GrantGuard::apply(
        &job,
        client,
        peer_uid,
        sandbox_uid,
        &extra,
        &journal_dir,
        Some(&unit),
        retention,
        trusted_probe_root,
    )?;
    let setpriv = trusted_linux_tool(&["/usr/bin/setpriv", "/bin/setpriv"])?;
    let systemd_run = trusted_linux_tool(&["/usr/bin/systemd-run"])?;
    let tasks = job.limits.max_processes.unwrap_or(256).clamp(1, 32768);
    let memory = job
        .limits
        .memory_bytes
        .unwrap_or(1024 * 1024 * 1024)
        .max(64 * 1024 * 1024);
    let mut command = Command::new(systemd_run);
    command
        .args([
            "--scope",
            "--wait",
            "--pipe",
            "--quiet",
            "--collect",
            "--expand-environment=no",
            "--unit",
            &unit,
            "--property",
            &format!("TasksMax={tasks}"),
            "--property",
            &format!("MemoryMax={memory}"),
            "--property",
            "MemorySwapMax=0",
            "--",
        ])
        .arg(setpriv)
        .args([
            "--reuid",
            &account_uid.to_string(),
            "--regid",
            &account_gid.to_string(),
            "--init-groups",
            "--",
        ])
        .arg(&executable)
        .args(["sandbox", "launch"])
        .arg(&jobfile)
        .args(["--watchdog", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut scope = command.spawn().map_err(|error| {
        crate::Error::isolation_unavailable(format!("cannot start hardened system scope: {error}"))
    })?;
    let mut watchdog = scope.stdin.take();
    if watchdog.is_none() {
        let _ = terminate_linux_scope(&unit);
        if !linux_scope_inactive(&unit, Duration::from_secs(5))? {
            grants.defer_recovery();
            return Err(crate::Error::isolation_unavailable(
                "launcher watchdog channel is unavailable and system scope did not stop",
            ));
        }
        grants.release()?;
        return Err(crate::Error::isolation_unavailable(
            "launcher watchdog channel could not be created",
        ));
    }
    let deadline = Instant::now() + job.limits.timeout + Duration::from_secs(30);
    let mut disconnected = false;
    let mut timed_out = false;
    let status = loop {
        if !disconnected && linux_client_disconnected(client) {
            disconnected = true;
            watchdog.take();
        }
        if let Some(status) = scope.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            watchdog.take();
            let _ = terminate_linux_scope(&unit);
            let _ = scope.kill();
            break scope.wait()?;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    drop(watchdog);
    if !linux_scope_inactive(&unit, Duration::from_secs(5))? {
        grants.defer_recovery();
        return Err(crate::Error::isolation_unavailable(
            "hardened Linux launcher scope is still active; ACL journal retained for recovery",
        ));
    }
    if !status.success() || timed_out || disconnected {
        grants.release()?;
        return Err(crate::Error::isolation_unavailable(if timed_out {
            "hardened Linux launcher exceeded its service deadline"
        } else if disconnected {
            "hardened Linux client disconnected; job was contained and its result was discarded"
        } else {
            "hardened Linux launcher rejected the job or failed its mandatory controls"
        }));
    }
    let outcome_path = output.join("outcome.json");
    let outcome_file = open_linux_regular(
        &outcome_path,
        sandbox_uid,
        super::protocol::MAX_OUTCOME_BYTES,
    )?;
    let mut encoded = Vec::new();
    outcome_file
        .take((super::protocol::MAX_OUTCOME_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    let outcome = super::protocol::decode_outcome(&encoded)?;
    if let Some(file) = outcome_file_from_client_dir(&source_dir_file, peer_uid)? {
        let mut output = file;
        output.write_all(&encoded)?;
        output.sync_all()?;
        // SAFETY: output is a newly created file owned by this service.
        if unsafe { libc::fchown(output.as_raw_fd(), peer_uid, u32::MAX) } != 0 {
            grants.defer_recovery();
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fsync accepts the live directory descriptor.
        if unsafe { libc::fsync(source_dir_file.as_raw_fd()) } != 0 {
            grants.defer_recovery();
            return Err(std::io::Error::last_os_error().into());
        }
    }
    grants.release()?;
    Ok(format!(
        "hardened Linux job completed with {:?}",
        outcome.status
    ))
}

#[cfg(target_os = "linux")]
fn outcome_file_from_client_dir(
    directory: &std::fs::File,
    _peer_uid: u32,
) -> crate::Result<Option<std::fs::File>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"outcome.json".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Some(unsafe { std::fs::File::from_raw_fd(fd) }))
}

#[cfg(target_os = "linux")]
fn trusted_linux_executable(path: &str) -> crate::Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let requested = Path::new(path);
    let canonical = requested.canonicalize()?;
    let metadata = std::fs::symlink_metadata(&canonical)?;
    let parent = std::fs::symlink_metadata(canonical.parent().unwrap_or(Path::new("/")))?;
    if canonical != requested
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || parent.uid() != 0
        || parent.mode() & 0o022 != 0
    {
        return Err(crate::Error::integrity(
            "hardened Linux installed executable is not a trusted root-owned file",
        ));
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn trusted_linux_tool(paths: &[&str]) -> crate::Result<std::path::PathBuf> {
    paths
        .iter()
        .find_map(|path| trusted_linux_executable(path).ok())
        .ok_or_else(|| {
            crate::Error::isolation_unavailable("required root-owned system tool is unavailable")
        })
}

#[cfg(target_os = "linux")]
fn linux_sandbox_identity(account: &str, expected_uid: u32) -> crate::Result<(u32, u32)> {
    if account != "f2c-sandbox" {
        return Err(crate::Error::integrity(
            "unexpected hardened Linux service account",
        ));
    }
    let passwd = std::fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if fields.next() != Some(account) {
            continue;
        }
        let _password = fields.next();
        let uid = fields.next().and_then(|s| s.parse::<u32>().ok());
        let gid = fields.next().and_then(|s| s.parse::<u32>().ok());
        if uid == Some(expected_uid) && uid != Some(0) {
            return gid
                .map(|gid| (expected_uid, gid))
                .ok_or_else(|| crate::Error::integrity("sandbox account group is malformed"));
        }
        return Err(crate::Error::integrity(
            "sandbox account uid differs from installed state",
        ));
    }
    Err(crate::Error::integrity(
        "hardened Linux sandbox account is missing",
    ))
}

#[cfg(target_os = "linux")]
fn linux_client_disconnected(client: &std::os::unix::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut byte = 0u8;
    let rc = unsafe {
        libc::recv(
            client.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    rc == 0
        || (rc < 0
            && !matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ))
        || rc > 0
}

#[cfg(target_os = "linux")]
fn terminate_linux_scope(unit: &str) -> crate::Result<()> {
    let systemctl = trusted_linux_tool(&["/usr/bin/systemctl", "/bin/systemctl"])?;
    let output = std::process::Command::new(systemctl)
        .args(["kill", "--kill-whom=all", "--signal=KILL", unit])
        .output()?;
    if output.status.success() || linux_scope_inactive(unit, std::time::Duration::ZERO)? {
        Ok(())
    } else {
        Err(crate::Error::isolation_unavailable(
            "cannot kill hardened Linux system scope",
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_scope_inactive(unit: &str, timeout: std::time::Duration) -> crate::Result<bool> {
    let systemctl = trusted_linux_tool(&["/usr/bin/systemctl", "/bin/systemctl"])?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let output = std::process::Command::new(&systemctl)
            .args(["show", "--property=ActiveState", "--value", unit])
            .output()?;
        if !output.status.success() {
            return Err(crate::Error::isolation_unavailable(
                "cannot read hardened Linux scope state",
            ));
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            "active" | "activating" | "deactivating" | "reloading" => {}
            "inactive" | "failed" | "" => return Ok(true),
            _ => {
                return Err(crate::Error::integrity(
                    "systemd returned an unknown hardened scope state",
                ))
            }
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
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
    expected_network: crate::isolation::NetworkMode,
) -> crate::Result<()> {
    if request.version != 1
        || request.launch_id != launch_id
        || request.launcher_pid != launcher_pid
        || request.launcher_creation_time_100ns != launcher_creation_time_100ns
        || request.network != expected_network
        || match (request.network, request.proxy_port) {
            (crate::isolation::NetworkMode::None, None) => false,
            (crate::isolation::NetworkMode::Internet, Some(port)) => port == 0,
            _ => true,
        }
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
    proxy_port: Option<u16>,
) -> crate::Result<()> {
    let ack = ack.ok_or_else(|| {
        crate::Error::isolation_unavailable("SYSTEM service did not acknowledge WFP preparation")
    })?;
    if ack.version != 1
        || ack.launch_id != launch_id
        || ack.package_sid != package_sid
        || ack.proxy_port != proxy_port
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
    pub(crate) proxy_port: Option<u16>,
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
        proxy_port: Option<u16>,
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
            proxy_port,
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
                    validate_prepare_ack(Some(&ack), &self.launch_id, package_sid, proxy_port)?;
                    return Ok(PackagePolicyReceipt {
                        launch_id: ack.launch_id,
                        package_sid: ack.package_sid,
                        proxy_port: ack.proxy_port,
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
    if let Err(error) = super::windows_wfp::sweep_loopback_exemption() {
        LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
        return Err(crate::Error::isolation_unavailable(format!(
            "loopback exemption recovery failed; service remains locked: {}",
            error.message
        )));
    }
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
            "PROBE" if request.job_dir.is_some() => {
                response(false, "probe operation does not accept a caller job path")
            }
            "PROBE" if LAUNCHER_CONTAINMENT_FAILED.load(Ordering::SeqCst) => {
                let mut reply = response(
                    false,
                    "an unresolved launcher containment marker blocks traffic-effect probing",
                );
                reply.containment_confirmed = false;
                reply
            }
            "PROBE" if request.job_dir.is_none() => {
                match probe_windows_effects(raw, &sandbox_sid) {
                    Ok(()) => {
                        let mut reply = response(
                        true,
                        "service-launched LPAC/WFP traffic effects passed; normal Internet jobs remain unavailable because FirewallAPI whole-list updates are not atomic against external writers",
                    );
                        reply.effect_probe_passed = true;
                        reply
                    }
                    Err(error) => {
                        let mut reply = response(
                        true,
                        format!(
                            "service-launched LPAC/WFP traffic effects failed; Internet jobs remain unavailable: {}",
                            bounded_error_detail(&error.message)
                        ),
                    );
                        reply.containment_confirmed =
                            !LAUNCHER_CONTAINMENT_FAILED.load(Ordering::SeqCst);
                        reply
                    }
                }
            }
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
        for child in std::fs::read_dir(&dir)? {
            let child = child?;
            if !matches!(
                child.file_name().to_str(),
                Some("input" | "output" | "stage")
            ) {
                return Err(crate::Error::integrity(
                    "stale service snapshot contains an unexpected top-level object",
                ));
            }
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
        let stage = dir.join("stage");
        match std::fs::symlink_metadata(&stage) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(metadata) if metadata.is_dir() && metadata.file_attributes() & REPARSE == 0 => {
                let stage_handle = open_windows_object(
                    &stage,
                    true,
                    windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                        | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
                )?;
                if crate::ipc::winsec::owner_sid(&stage_handle)? != "S-1-5-18" {
                    return Err(crate::Error::integrity(
                        "stale service probe stage is not SYSTEM-owned",
                    ));
                }
                remove_plain_service_tree(&stage)?;
            }
            Ok(_) => {
                return Err(crate::Error::integrity(
                    "stale service probe stage is not a plain directory",
                ));
            }
        }
        std::fs::remove_dir(dir)?;
    }
    Ok(())
}

#[cfg(windows)]
fn remove_plain_service_tree(path: &Path) -> crate::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    let reparse = metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0;
    if reparse {
        return Err(crate::Error::integrity(
            "service probe cleanup encountered a reparse point",
        ));
    }
    if metadata.is_dir() {
        for child in std::fs::read_dir(path)? {
            remove_plain_service_tree(&child?.path())?;
        }
        std::fs::remove_dir(path)?;
    } else if metadata.is_file() {
        std::fs::remove_file(path)?;
    } else {
        return Err(crate::Error::integrity(
            "service probe cleanup encountered an unexpected filesystem object",
        ));
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
    let mut cleanup_proof = PreparationCleanupProof::default();
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
                            job.network,
                        )
                        .is_err()
                        {
                            write_prepare_ack(
                                ack_write.as_raw_handle() as HANDLE,
                                &PrepareAck {
                                    version: 1,
                                    launch_id: marker_id.clone(),
                                    package_sid: message.package_sid,
                                    proxy_port: message.proxy_port,
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
                                        proxy_port: message.proxy_port,
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
                        match super::windows_wfp::PackageGuard::install(
                            &message.package_sid,
                            message.proxy_port,
                        ) {
                            Ok(guard) => {
                                // Transfer both security resources into the
                                // common checked cleanup path before the ACK
                                // write can fail (for example, if the launcher
                                // closes its read end after policy installation).
                                network_guard = Some(guard);
                                package_grants = Some(grants);
                                send_policy_ack(&mut cleanup_proof, || {
                                    write_prepare_ack(
                                        ack_write.as_raw_handle() as HANDLE,
                                        &PrepareAck {
                                            version: 1,
                                            launch_id: marker_id.clone(),
                                            package_sid: message.package_sid,
                                            proxy_port: message.proxy_port,
                                            ready: true,
                                            detail: "package-scoped deny filters and exact proxy endpoint read back".into(),
                                        },
                                    )
                                })?;
                            }
                            Err(error) => {
                                // PackageGuard::install has already attempted
                                // rollback. If that failed, the dynamic WFP
                                // session or loopback exemption may still be
                                // present, so retain the durable launch marker
                                // and refuse all future launches until restart
                                // recovery removes the exact journaled SID.
                                let rollback_unconfirmed = error
                                    .message
                                    .starts_with("WFP rollback failed after setup error:");
                                if rollback_unconfirmed {
                                    LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
                                    if let Some(marker) = active_marker.as_mut() {
                                        marker.retain();
                                    }
                                }
                                let _ = write_prepare_ack(
                                    ack_write.as_raw_handle() as HANDLE,
                                    &PrepareAck {
                                        version: 1,
                                        launch_id: marker_id.clone(),
                                        package_sid: message.package_sid,
                                        proxy_port: message.proxy_port,
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
                                    if let Some(marker) = active_marker.as_mut() {
                                        marker.retain();
                                    }
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
            cleanup_proof.launcher_tree_empty = true;
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
    cleanup_proof.package_grants_revoked = package_grants.is_none();
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
    cleanup_proof.package_policy_closed = network_guard.is_none();
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
    cleanup_proof.profile_unloaded = true;
    #[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
    {
        diagnostic_stage.profile_unloaded = true;
    }
    if !cleanup_proof.may_clear_marker() {
        LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
        if let Some(marker) = active_marker.as_mut() {
            marker.retain();
        }
        return Err(crate::Error::isolation_unavailable(
            "launch cleanup proof is incomplete; durable refusal marker retained",
        ));
    }
    if launch_result.is_ok() && !cleanup_proof.operation_succeeded() {
        LAUNCHER_CONTAINMENT_FAILED.store(true, Ordering::SeqCst);
        if let Some(marker) = active_marker.as_mut() {
            marker.retain();
        }
        return Err(crate::Error::isolation_unavailable(
            "launch completed without an acknowledged package policy; refusal marker retained",
        ));
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
    if job.network == crate::isolation::NetworkMode::Internet {
        return Err(crate::Error::isolation_unavailable(
            "SYSTEM service has not verified direct-route refusal and proxy-loopback effects; Internet job was not launched",
        ));
    }
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

#[cfg(windows)]
struct ProbeTcpFixture {
    listener: std::net::TcpListener,
    endpoint: std::net::SocketAddr,
}

#[cfg(windows)]
impl ProbeTcpFixture {
    fn bind(address: std::net::SocketAddr) -> crate::Result<Self> {
        let listener = std::net::TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let endpoint = listener.local_addr()?;
        Ok(Self { listener, endpoint })
    }

    fn host_round_trip(&self) -> crate::Result<()> {
        let client = std::net::TcpStream::connect_timeout(
            &self.endpoint,
            std::time::Duration::from_millis(750),
        )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(750);
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    drop(stream);
                    drop(client);
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(crate::Error::isolation_unavailable(
                            "host could not connect to a probe fixture",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn assert_quiet(&self) -> crate::Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    drop(stream);
                    return Err(crate::Error::isolation_unavailable(
                        "an LPAC direct-route probe reached a host fixture",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[cfg(windows)]
fn local_route_source(destination: std::net::SocketAddr) -> crate::Result<std::net::SocketAddr> {
    let bind = match destination {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.connect(destination)?;
    let source = socket.local_addr()?;
    if source.ip().is_loopback() || source.ip().is_unspecified() {
        return Err(crate::Error::isolation_unavailable(
            "no non-loopback interface is available for the traffic-effect fixture",
        ));
    }
    Ok(match source {
        std::net::SocketAddr::V4(address) => {
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(*address.ip(), 0))
        }
        std::net::SocketAddr::V6(address) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            *address.ip(),
            0,
            0,
            address.scope_id(),
        )),
    })
}

#[cfg(windows)]
fn probe_windows_effects(
    client_pipe: windows_sys::Win32::Foundation::HANDLE,
    sandbox_sid: &str,
) -> crate::Result<()> {
    use crate::isolation::{JobLimits, JobSpec, JobStatus, NetworkMode};
    use std::os::windows::fs::MetadataExt;
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ};

    let state = super::lifecycle::installed_state()?;
    if state.sandbox_sid.as_deref() != Some(sandbox_sid) {
        return Err(crate::Error::integrity(
            "effect probe sandbox identity differs from installed service state",
        ));
    }
    let executable = Path::new(&state.executable);
    let current_exe = std::env::current_exe()?;
    if !same_windows_path(&current_exe.canonicalize()?, &executable.canonicalize()?) {
        return Err(crate::Error::integrity(
            "effect probe service executable differs from the installed binary",
        ));
    }
    let source = open_windows_object(executable, false, FILE_SHARE_READ)?;
    let source_metadata = source.metadata()?;
    if !source_metadata.is_file()
        || source_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || source_metadata.len() == 0
        || source_metadata.len() > 256 * 1024 * 1024
    {
        return Err(crate::Error::integrity(
            "installed probe executable is unsafe or oversized",
        ));
    }

    let state_path = super::machine_state_path()?;
    let data_dir = state_path
        .parent()
        .ok_or_else(|| crate::Error::integrity("install state has no parent"))?;
    let jobs = ensure_snapshot_store(&data_dir.join("jobs"))?;
    let snapshot = tempfile::Builder::new().prefix("job-").tempdir_in(&jobs)?;
    set_snapshot_acl(snapshot.path(), sandbox_sid, "RX")?;
    let input_dir = snapshot.path().join("input");
    let output_dir = snapshot.path().join("output");
    let stage_root = snapshot.path().join("stage");
    std::fs::create_dir(&input_dir)?;
    std::fs::create_dir(&output_dir)?;
    std::fs::create_dir(&stage_root)?;
    set_snapshot_acl(&input_dir, sandbox_sid, "RX")?;
    set_snapshot_acl(&output_dir, sandbox_sid, "M")?;
    set_snapshot_acl(&stage_root, sandbox_sid, "RX")?;
    let job_stage = stage_root.join("probe");
    let read_only = job_stage.join("read-only");
    let work_dir = job_stage.join("work");
    std::fs::create_dir(&job_stage)?;
    std::fs::create_dir(&read_only)?;
    std::fs::create_dir(&work_dir)?;
    set_snapshot_acl(&job_stage, sandbox_sid, "RX")?;
    set_snapshot_acl(&read_only, sandbox_sid, "RX")?;
    set_snapshot_acl(&work_dir, sandbox_sid, "M")?;

    let fixture_other = ProbeTcpFixture::bind((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
    let fixture_other_v6 = ProbeTcpFixture::bind((std::net::Ipv6Addr::LOCALHOST, 0).into())?;
    let source_v4 = local_route_source("1.1.1.1:53".parse().unwrap())?;
    if !matches!(source_v4, std::net::SocketAddr::V4(_)) {
        return Err(crate::Error::isolation_unavailable(
            "IPv4 traffic-effect fixture resolved to a non-IPv4 interface",
        ));
    }
    let fixture_private_v4 = ProbeTcpFixture::bind(source_v4)?;
    let source_v6 = local_route_source("[2606:4700:4700::1111]:53".parse().unwrap())?;
    if !matches!(source_v6, std::net::SocketAddr::V6(_)) {
        return Err(crate::Error::isolation_unavailable(
            "IPv6 traffic-effect fixture resolved to a non-IPv6 interface",
        ));
    }
    let fixture_private_v6 = ProbeTcpFixture::bind(source_v6)?;
    for fixture in [
        &fixture_other,
        &fixture_other_v6,
        &fixture_private_v4,
        &fixture_private_v6,
    ] {
        fixture.host_round_trip()?;
    }

    let staged_executable = read_only.join("fail2commit-probe.exe");
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged_executable)?;
    let mut limited_source = source.take(source_metadata.len() + 1);
    std::io::copy(&mut limited_source, &mut target)?;
    target.sync_all()?;
    drop(target);
    let copied = open_windows_object(&staged_executable, false, FILE_SHARE_READ)?;
    if copied.metadata()?.len() != source_metadata.len() {
        return Err(crate::Error::integrity(
            "staged probe executable did not match the installed binary length",
        ));
    }

    let job = JobSpec {
        program: staged_executable,
        args: vec!["sandbox".into(), "egress-probe".into()],
        cwd: work_dir.clone(),
        env: vec![
            (
                "F2C_PROBE_OTHER_LOOPBACK".into(),
                fixture_other.endpoint.to_string().into(),
            ),
            (
                "F2C_PROBE_OTHER_LOOPBACK_V6".into(),
                fixture_other_v6.endpoint.to_string().into(),
            ),
            (
                "F2C_PROBE_INTERFACE_V4".into(),
                fixture_private_v4.endpoint.to_string().into(),
            ),
            (
                "F2C_PROBE_INTERFACE_V6".into(),
                fixture_private_v6.endpoint.to_string().into(),
            ),
        ],
        read_only: vec![read_only],
        work_dir,
        exports: Vec::new(),
        export_to: None,
        limits: JobLimits {
            timeout: std::time::Duration::from_secs(20),
            memory_bytes: Some(256 * 1024 * 1024),
            max_processes: Some(8),
            max_output_bytes: 16 * 1024,
            disk_bytes: Some(16 * 1024 * 1024),
        },
        network: NetworkMode::Internet,
        bait: false,
    };
    let job_bytes = super::protocol::encode_hardened_job(&job, &stage_root)?;
    let jobfile = input_dir.join("job.json");
    std::fs::write(&jobfile, job_bytes)?;
    let jobfile_handle = open_windows_object(&jobfile, false, FILE_SHARE_READ)?;
    if crate::ipc::winsec::owner_sid(&jobfile_handle)? != "S-1-5-18" {
        return Err(crate::Error::integrity(
            "service-generated effect probe snapshot is not SYSTEM-owned",
        ));
    }

    let before_exemptions = crate::sandbox::windows::ffi::loopback_exempt_sids()?;
    let exit =
        match run_snapshot_as_sandbox(&jobfile, client_pipe, sandbox_sid, &job, &stage_root, false)
        {
            Ok(exit) => exit,
            Err(error) if LAUNCHER_CONTAINMENT_FAILED.load(Ordering::SeqCst) => {
                let _retained_snapshot = retain_snapshot_if_unconfirmed(snapshot, true);
                return Err(error);
            }
            Err(error) => return Err(error),
        };
    if exit != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "fixed LPAC effect probe launcher exited with code {exit}"
        )));
    }
    for fixture in [
        &fixture_other,
        &fixture_other_v6,
        &fixture_private_v4,
        &fixture_private_v6,
    ] {
        fixture.assert_quiet()?;
    }
    for fixture in [
        &fixture_other,
        &fixture_other_v6,
        &fixture_private_v4,
        &fixture_private_v6,
    ] {
        fixture.host_round_trip()?;
    }
    let mut after_exemptions = crate::sandbox::windows::ffi::loopback_exempt_sids()?;
    let mut expected_exemptions = before_exemptions;
    after_exemptions.sort_by_key(|sid| sid.to_ascii_lowercase());
    expected_exemptions.sort_by_key(|sid| sid.to_ascii_lowercase());
    if after_exemptions != expected_exemptions {
        return Err(crate::Error::isolation_unavailable(
            "effect probe did not restore the machine loopback exemption list exactly",
        ));
    }
    let outcome_path = output_dir.join("outcome.json");
    let outcome_file = open_windows_object(&outcome_path, false, FILE_SHARE_READ)?;
    let metadata = outcome_file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > super::protocol::MAX_OUTCOME_BYTES as u64
    {
        return Err(crate::Error::integrity(
            "fixed effect probe outcome is unsafe or oversized",
        ));
    }
    let mut outcome_bytes = Vec::new();
    outcome_file
        .take((super::protocol::MAX_OUTCOME_BYTES + 1) as u64)
        .read_to_end(&mut outcome_bytes)?;
    let outcome = super::protocol::decode_outcome(&outcome_bytes)?;
    let result: super::windows_effect_probe::EffectResults =
        serde_json::from_slice(&outcome.stdout).map_err(|_| {
            crate::Error::integrity("fixed effect probe returned a malformed result record")
        })?;
    if !result.complete() || outcome.status != JobStatus::Exited(0) {
        return Err(crate::Error::isolation_unavailable(format!(
            "LPAC/WFP effect report failed checks {:?} (launcher status {:?})",
            result.failed_checks(),
            outcome.status
        )));
    }
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
            proxy_port: None,
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
            crate::isolation::NetworkMode::None,
        )
        .is_ok());
        request.launcher_pid += 1;
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
            crate::isolation::NetworkMode::None,
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
            crate::isolation::NetworkMode::None,
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
            crate::isolation::NetworkMode::None,
        )
        .is_err());
        request = sample_prepare_request();
        request.network = crate::isolation::NetworkMode::Internet;
        request.proxy_port = Some(32123);
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
            crate::isolation::NetworkMode::Internet,
        )
        .is_ok());
        request.proxy_port = None;
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
            crate::isolation::NetworkMode::Internet,
        )
        .is_err());
        request.proxy_port = Some(0);
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
            crate::isolation::NetworkMode::Internet,
        )
        .is_err());
        request.proxy_port = Some(32123);
        assert!(validate_prepare_request(
            &request,
            &"a".repeat(64),
            412,
            987_654_321,
            "S-1-5-21-1-2-3-1001",
            crate::isolation::NetworkMode::None,
        )
        .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn wfp_preparation_rejects_missing_bad_and_mismatched_acknowledgements() {
        let sid = "S-1-15-2-1-2-3-4-5-6-7-8-9-10-11-12";
        assert!(validate_prepare_ack(None, &"a".repeat(64), sid, None).is_err());
        let mut ack = PrepareAck {
            version: 1,
            launch_id: "a".repeat(64),
            package_sid: sid.into(),
            proxy_port: None,
            ready: true,
            detail: "ready".into(),
        };
        assert!(validate_prepare_ack(Some(&ack), &"a".repeat(64), sid, None).is_ok());
        ack.launch_id = "b".repeat(64);
        assert!(validate_prepare_ack(Some(&ack), &"a".repeat(64), sid, None).is_err());
        ack.launch_id = "a".repeat(64);
        ack.proxy_port = Some(43210);
        assert!(validate_prepare_ack(Some(&ack), &"a".repeat(64), sid, None).is_err());
        ack.proxy_port = None;
        ack.ready = false;
        assert!(validate_prepare_ack(Some(&ack), &"a".repeat(64), sid, None).is_err());
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
    fn failed_policy_ack_with_each_cleanup_failure_keeps_marker_and_launch_latched() {
        let stages: [(&str, fn(&mut PreparationCleanupProof)); 4] = [
            ("launcher tree", |proof| proof.launcher_tree_empty = false),
            ("package grants", |proof| {
                proof.package_grants_revoked = false
            }),
            ("WFP policy", |proof| proof.package_policy_closed = false),
            ("sandbox profile", |proof| proof.profile_unloaded = false),
        ];
        for (stage, fail_cleanup) in stages {
            let mut proof = PreparationCleanupProof::default();
            assert!(send_policy_ack(&mut proof, || {
                Err(crate::Error::isolation_unavailable(
                    "injected preparation ACK failure",
                ))
            })
            .is_err());
            proof.launcher_tree_empty = true;
            proof.package_grants_revoked = true;
            proof.package_policy_closed = true;
            proof.profile_unloaded = true;
            fail_cleanup(&mut proof);
            assert!(
                !proof.operation_succeeded(),
                "{stage} accepted a failed ACK"
            );
            assert!(
                !proof.may_clear_marker(),
                "{stage} cleared the refusal marker"
            );
            assert!(!response(true, "probe").probe_available);
        }
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
    fn linux_peer_credentials_are_read_from_kernel_socket_metadata() {
        let (service, _client) = std::os::unix::net::UnixStream::pair().unwrap();
        // SAFETY: getuid has no preconditions and reports the test process's real uid.
        let actual_uid = unsafe { libc::getuid() };
        assert_eq!(peer_uid(&service).unwrap(), actual_uid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_detects_closed_or_protocol_smuggled_client_streams() {
        let (service, client) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(!linux_client_disconnected(&service));
        drop(client);
        assert!(linux_client_disconnected(&service));

        let (service, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
        use std::io::Write;
        client.write_all(b"unexpected trailing bytes").unwrap();
        assert!(linux_client_disconnected(&service));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_mandatory_probe_requires_real_effect_events_and_trip_outcome() {
        use crate::isolation::{ActivityKind, ActivityReport, JobOutcome, JobStatus};

        let passing_routes = JobOutcome {
            status: JobStatus::Exited(0),
            stdout: b"F2C-LINUX-EFFECT-PROBE-PASS\n".to_vec(),
            stderr: Vec::new(),
            truncated: false,
            exported: Vec::new(),
            report: ActivityReport {
                events: vec![
                    crate::isolation::Activity {
                        kind: ActivityKind::NetAllowed,
                        detail: "public destination".into(),
                    },
                    crate::isolation::Activity {
                        kind: ActivityKind::NetRefused,
                        detail: "restricted destination".into(),
                    },
                ],
                truncated: false,
            },
        };
        assert!(linux_effect_probe_outcome_passed(&passing_routes));

        let mut missing_refusal = passing_routes.clone();
        missing_refusal
            .report
            .events
            .retain(|event| event.kind != ActivityKind::NetRefused);
        assert!(!linux_effect_probe_outcome_passed(&missing_refusal));

        let bait_killed = JobOutcome {
            status: JobStatus::Killed,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            exported: Vec::new(),
            report: ActivityReport {
                events: vec![crate::isolation::Activity {
                    kind: ActivityKind::Bait,
                    detail: "bait token detected".into(),
                }],
                truncated: false,
            },
        };
        assert!(linux_bait_probe_outcome_passed(&bait_killed));

        let mut bait_exit = bait_killed.clone();
        bait_exit.status = JobStatus::Exited(0);
        assert!(!linux_bait_probe_outcome_passed(&bait_exit));
        let mut bait_exported = bait_killed;
        bait_exported
            .exported
            .push(std::path::PathBuf::from("/tmp/leak"));
        assert!(!linux_bait_probe_outcome_passed(&bait_exported));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn watchdog_probe_cleanup_requires_successful_kill_and_inactive_readback() {
        let unit = "f2c-hardened-job-0123456789abcdef0123456789abcdef.scope";
        assert!(stop_and_confirm_linux_scope_with(
            unit,
            |_| Err(crate::Error::isolation_unavailable("injected kill failure")),
            |_, timeout| {
                assert_eq!(timeout, std::time::Duration::from_secs(5));
                Ok(false)
            },
        )
        .is_err());
        assert!(stop_and_confirm_linux_scope_with(unit, |_| Ok(()), |_, _| Ok(false),).is_err());
        assert!(stop_and_confirm_linux_scope_with(
            unit,
            |_| Ok(()),
            |_, _| Err(crate::Error::isolation_unavailable(
                "injected readback failure"
            )),
        )
        .is_err());
        assert!(stop_and_confirm_linux_scope_with(unit, |_| Ok(()), |_, _| Ok(true)).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_read_only_mount_check_rejects_writable_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture");
        std::fs::write(&path, b"probe").unwrap();
        assert!(!linux_mount_is_read_only(&path).unwrap());
    }
}
