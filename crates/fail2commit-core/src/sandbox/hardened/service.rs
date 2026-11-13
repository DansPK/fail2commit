//! Minimal authenticated service transport for SPEC-018 §4.2.

#[cfg(any(target_os = "linux", windows, test))]
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", windows, test))]
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(any(target_os = "linux", windows, test))]
const MAX_REQUEST: usize = 16 * 1024;
#[cfg(any(target_os = "linux", windows))]
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(any(target_os = "linux", windows, test))]
#[derive(Debug, Deserialize)]
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

#[cfg(any(target_os = "linux", windows, test))]
fn response(ok: bool, detail: &'static str) -> Response {
    Response {
        ok,
        service_running: true,
        probe_available: false,
        detail: detail.to_owned(),
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
            "STATUS" if request.job_dir.is_none() => response(
                true,
                "service authenticated peer; launcher and platform controls are not verified",
            ),
            "LAUNCH" if request.job_dir.is_none() => {
                response(false, "job_dir is required; job was not started")
            }
            "LAUNCH" => response(
                false,
                "launcher controls are not verified; job was not started",
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

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
