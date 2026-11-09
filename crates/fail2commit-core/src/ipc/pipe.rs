//! Same-user approval pipe: client (`tray_approver`) and server (tray side).
//!
//! Server hardening: first-instance flag (no squatting), remote clients
//! rejected, DACL allowing only the current user and denying the app-package
//! SIDs, per-client token check (same user, not AppContainer), bounded lines.
//! Client hardening: server process must run as the same user, and the
//! connection is opened with anonymous impersonation so the server cannot act
//! as the CLI.
#![allow(unsafe_code)]

use super::winsec::{self, PipeSecurity};
use super::wire;
use crate::approver::{now_secs, validate_response, Approver};
use crate::protocol::{
    ApprovalRequest, ApprovalResponse, ClientMessage, Decision, ServerMessage, PROTOCOL_VERSION,
};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_SEM_TIMEOUT,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

/// Simultaneous pipe instances / in-flight prompts.
const MAX_CLIENTS: usize = 8;

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain([0]).collect()
}

fn into_file(h: HANDLE) -> File {
    // SAFETY: `h` is a valid handle we exclusively own; `File` closes it.
    unsafe { File::from_raw_handle(h as RawHandle) }
}

// ---------------------------------------------------------------- client

/// Returns an approver when a tray is listening on this user's pipe.
pub fn tray_approver() -> Option<Box<dyn Approver>> {
    let name = winsec::pipe_name().ok()?;
    probe(&name)
}

/// Existence probe without consuming a pipe instance (short timeout).
pub fn probe(name: &str) -> Option<Box<dyn Approver>> {
    let w = wide(name);
    // SAFETY: `w` is NUL-terminated.
    let ok = unsafe { WaitNamedPipeW(w.as_ptr(), 1) };
    // SAFETY: reads the thread's last error right after the call.
    let err = unsafe { GetLastError() };
    if ok != 0 || err == ERROR_SEM_TIMEOUT {
        Some(Box::new(PipeApprover { name: name.into() }))
    } else {
        None
    }
}

pub struct PipeApprover {
    name: String,
}

impl PipeApprover {
    fn connect(&self) -> crate::Result<File> {
        let w = wide(&self.name);
        for _ in 0..4 {
            // SAFETY: valid NUL-terminated name; no security attributes/template.
            let h = unsafe {
                CreateFileW(
                    w.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                    std::ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                return Ok(into_file(h));
            }
            // SAFETY: last error of the failed call above.
            match unsafe { GetLastError() } {
                ERROR_PIPE_BUSY => {
                    // SAFETY: valid name; waits at most 500 ms for a free instance.
                    unsafe { WaitNamedPipeW(w.as_ptr(), 500) };
                }
                ERROR_FILE_NOT_FOUND => {
                    return Err(crate::Error::approval_unavailable("tray is not running"))
                }
                e => {
                    return Err(crate::Error::approval_unavailable(format!(
                        "cannot open the tray pipe (os error {e})"
                    )))
                }
            }
        }
        Err(crate::Error::approval_unavailable("tray pipe is busy"))
    }
}

fn require_same_user(pid: u32, me: &[u8], who: &str) -> crate::Result<()> {
    let facts = winsec::process_facts(pid)
        .map_err(|e| crate::Error::approval_unavailable(format!("cannot verify {who}: {e}")))?;
    if facts.user != me || facts.app_container {
        return Err(crate::Error::approval_unavailable(format!(
            "{who} is not a same-user, non-sandboxed process"
        )));
    }
    Ok(())
}

impl Approver for PipeApprover {
    fn name(&self) -> &'static str {
        "tray"
    }

    fn ask(&self, req: &ApprovalRequest) -> crate::Result<ApprovalResponse> {
        let mut pipe = self.connect()?;
        let mut pid = 0u32;
        // SAFETY: valid pipe handle and out pointer.
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
            return Err(crate::Error::approval_unavailable(
                "cannot identify the pipe server",
            ));
        }
        let me = winsec::current_user_sid()?;
        require_same_user(pid, &me, "pipe server")?;

        let line = serde_json::to_string(&ServerMessage::ApprovalRequest(req.clone()))
            .map_err(|e| crate::Error::internal(e.to_string()))?;
        wire::write_line(&mut pipe, &line)?;
        let reply = wire::read_line(&mut pipe)?
            .ok_or_else(|| crate::Error::approval_unavailable("tray closed without answering"))?;
        let msg: ClientMessage = serde_json::from_str(&reply)
            .map_err(|_| crate::Error::rejected("malformed reply from the tray"))?;
        let resp = match msg {
            ClientMessage::ApprovalResponse(r) => r,
            ClientMessage::Cancel { request_id } if request_id == req.request_id => {
                ApprovalResponse {
                    version: PROTOCOL_VERSION,
                    request_id: req.request_id.clone(),
                    nonce: req.nonce.clone(),
                    digest: req.digest.clone(),
                    decision: Decision::Cancel,
                    password: None,
                }
            }
            ClientMessage::Cancel { .. } => {
                return Err(crate::Error::rejected("cancel for a different request"))
            }
        };
        validate_response(req, &resp, now_secs())?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------- server

/// What the UI decided. The server turns it into the wire reply.
pub enum Reply {
    Cancel,
    Decide {
        decision: Decision,
        password: Option<String>,
    },
}

/// UI seam. Called on a pipe thread (never the UI thread) with a validated
/// request; blocks until the user answers or the request expires.
pub trait Prompter: Send + Sync {
    fn prompt(&self, req: ApprovalRequest) -> Reply;
}

pub struct PipeServer {
    name: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn create_instance(name: &str, sec: &PipeSecurity, first: bool) -> crate::Result<OwnedHandle> {
    let w = wide(name);
    let mut open = PIPE_ACCESS_DUPLEX;
    if first {
        open |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: valid NUL-terminated name and security attributes that outlive the call.
    let h = unsafe {
        CreateNamedPipeW(
            w.as_ptr(),
            open,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            MAX_CLIENTS as u32 + 1,
            64 * 1024,
            64 * 1024,
            0,
            sec.attributes(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(crate::Error::approval_unavailable(format!(
            "cannot create the approval pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fresh handle owned by us.
    Ok(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) })
}

impl PipeServer {
    /// Start on this user's default pipe name.
    pub fn start_default(prompter: Arc<dyn Prompter>) -> crate::Result<PipeServer> {
        Self::start(&winsec::pipe_name()?, prompter)
    }

    /// Create the first instance synchronously (so squatting or a second
    /// tray fails here), then accept on a background thread.
    pub fn start(name: &str, prompter: Arc<dyn Prompter>) -> crate::Result<PipeServer> {
        let me = winsec::current_user_sid()?;
        let sec = PipeSecurity::new(&me)?;
        let first = create_instance(name, &sec, true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let (stop2, name2) = (stop.clone(), name.to_string());
        let thread = std::thread::Builder::new()
            .name("f2c-pipe-accept".into())
            .spawn(move || accept_loop(name2, sec, first, me, prompter, stop2, active))
            .map_err(|e| crate::Error::internal(e.to_string()))?;
        Ok(PipeServer {
            name: name.to_string(),
            stop,
            thread: Some(thread),
        })
    }

    /// Stop accepting and join the accept thread. In-flight prompts finish
    /// on their own threads.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking ConnectNamedPipe with a throwaway connection.
        let _ = PipeApprover {
            name: self.name.clone(),
        }
        .connect();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn accept_loop(
    name: String,
    sec: PipeSecurity,
    mut inst: OwnedHandle,
    me: winsec::Sid,
    prompter: Arc<dyn Prompter>,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
) {
    loop {
        let h = inst.as_raw_handle() as HANDLE;
        // SAFETY: blocking connect on our own pipe instance.
        let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0
            // SAFETY: last error of the call above.
            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let next = match create_instance(&name, &sec, false) {
            Ok(n) => n,
            Err(_) => return, // cannot keep listening: fail closed
        };
        let done = std::mem::replace(&mut inst, next);
        if !ok || active.load(Ordering::SeqCst) >= MAX_CLIENTS {
            continue; // dropping `done` closes (and disconnects) it
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (p, me2, act) = (prompter.clone(), me.clone(), active.clone());
        let spawned = std::thread::Builder::new()
            .name("f2c-pipe-client".into())
            .spawn(move || {
                let _ = serve_client(File::from(done), &me2, p.as_ref());
                act.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn serve_client(mut pipe: File, me: &[u8], prompter: &dyn Prompter) -> crate::Result<()> {
    let mut pid = 0u32;
    // SAFETY: valid pipe handle and out pointer.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(crate::Error::rejected("cannot identify the pipe client"));
    }
    require_same_user(pid, me, "pipe client")?;
    let line = wire::read_line(&mut pipe)?.ok_or_else(|| crate::Error::rejected("empty client"))?;
    let req = match serde_json::from_str::<ServerMessage>(&line) {
        Ok(ServerMessage::ApprovalRequest(r)) => r,
        _ => return Err(crate::Error::rejected("expected an approval request")),
    };
    wire::validate_request(&req, now_secs())?;
    let msg = match prompter.prompt(req.clone()) {
        Reply::Decide { decision, password } if req.allowed.contains(&decision) => {
            ClientMessage::ApprovalResponse(ApprovalResponse {
                version: PROTOCOL_VERSION,
                request_id: req.request_id.clone(),
                nonce: req.nonce.clone(),
                digest: req.digest.clone(),
                decision,
                password,
            })
        }
        _ => ClientMessage::Cancel {
            request_id: req.request_id.clone(),
        },
    };
    let mut line =
        serde_json::to_string(&msg).map_err(|e| crate::Error::internal(e.to_string()))?;
    let r = wire::write_line(&mut pipe, &line);
    zeroize::Zeroize::zeroize(&mut line);
    // Wait until the client has read the reply before the handle closes.
    // SAFETY: valid pipe handle.
    unsafe { FlushFileBuffers(pipe.as_raw_handle() as HANDLE) };
    r
}
