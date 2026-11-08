//! Narrow Win32 FFI for the AppContainer backend (T-007b, FR-007, SPEC-007).
//!
//! Every function that touches raw Win32 state opts into `unsafe_code`
//! individually and documents why each call is sound. Callers in
//! `windows.rs` stay safe Rust. Every failure here maps to
//! `IsolationUnavailable` because it happens before package code runs.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, SetHandleInformation, ERROR_PIPE_CONNECTED, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, REVOKE_ACCESS, SDDL_REVISION_1, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, FreeSid, GetAce, GetAclInformation, GetTokenInformation,
    TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer,
    TokenIsLessPrivilegedAppContainer, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JobObjectAssociateCompletionPortInformation, JobObjectBasicAccountingInformation,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject, JOBOBJECTINFOCLASS,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, CreatePipe, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
};

/// All UI restriction classes (the SystemServices `JOB_OBJECT_UILIMIT_ALL`).
pub(super) const UI_LIMIT_ALL: u32 = JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
/// Job completion-port message ids (winnt.h; the SystemServices feature is
/// not enabled for this crate).
pub(super) const MSG_ACTIVE_PROCESS_LIMIT: u32 = 3;
pub(super) const MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
pub(super) const MSG_JOB_MEMORY_LIMIT: u32 = 10;
const JOB_KEY: usize = 0xF2C0;
pub(super) const REQUIRED_LIMIT_FLAGS: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    | JOB_OBJECT_LIMIT_JOB_MEMORY
    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

// Userenv profile API. The windows-sys `Win32_Security_Isolation` feature is
// not enabled for this crate, so the three entry points are declared here.
#[link(name = "userenv")]
extern "system" {
    fn CreateAppContainerProfile(
        name: *const u16,
        display: *const u16,
        description: *const u16,
        capabilities: *const core::ffi::c_void,
        capability_count: u32,
        sid: *mut PSID,
    ) -> i32;
    fn DeleteAppContainerProfile(name: *const u16) -> i32;
}

/// Serializes our own handle-inheritance windows. Every launch passes an
/// explicit HANDLE_LIST, so this only keeps our launches from racing each
/// other while the three stdio handles are temporarily inheritable.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn unavailable(what: &str) -> crate::Error {
    crate::Error::isolation_unavailable(format!("{what} failed: {}", io::Error::last_os_error()))
}

pub(super) fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn raw(h: &impl AsRawHandle) -> HANDLE {
    h.as_raw_handle() as HANDLE
}

#[allow(unsafe_code)]
fn owned(h: HANDLE) -> OwnedHandle {
    // SAFETY: callers pass a freshly created, valid handle that nothing else
    // owns; ownership moves into the returned OwnedHandle exactly once.
    unsafe { OwnedHandle::from_raw_handle(h as RawHandle) }
}

#[allow(unsafe_code)]
fn local_free<T>(p: *mut T) {
    if !p.is_null() {
        // SAFETY: `p` was allocated by a Win32 API documented to return
        // LocalAlloc memory and is freed exactly once here.
        unsafe {
            LocalFree(p.cast());
        }
    }
}

#[allow(unsafe_code)]
fn sid_to_string(sid: PSID) -> crate::Result<String> {
    let mut out: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID owned by the caller; `out` receives a
    // LocalAlloc'd NUL-terminated string freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 || out.is_null() {
        return Err(unavailable("ConvertSidToStringSidW"));
    }
    let mut len = 0usize;
    // SAFETY: the string is NUL-terminated; we stop at the terminator.
    let s = unsafe {
        while *out.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(out, len))
    };
    local_free(out);
    Ok(s)
}

/// A freshly created, uniquely named AppContainer profile. Deleted on drop.
pub(super) struct Profile {
    name: Vec<u16>,
    sid: PSID,
    pub(super) sid_string: String,
}

impl Profile {
    /// Create a new profile with a random 128-bit name. An existing profile
    /// with that name is an error, so no prior loopback exemption or other
    /// per-SID configuration can apply.
    #[allow(unsafe_code)]
    pub(super) fn create_fresh() -> crate::Result<Profile> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|e| {
            crate::Error::isolation_unavailable(format!("random profile name: {e}"))
        })?;
        let name_s = format!("fail2commit.sbx.{}", hex::encode(nonce));
        let name = wide(OsStr::new(&name_s));
        let display = wide(OsStr::new("fail2commit sandbox job"));
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: all strings are NUL-terminated and live across the call; a
        // zero capability count with a null array requests no capabilities;
        // `sid` receives a SID freed with FreeSid in Drop.
        let hr = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                display.as_ptr(),
                std::ptr::null(),
                0,
                &mut sid,
            )
        };
        if hr != 0 || sid.is_null() {
            return Err(crate::Error::isolation_unavailable(format!(
                "CreateAppContainerProfile failed: HRESULT 0x{:08X}",
                hr as u32
            )));
        }
        let mut profile = Profile {
            name,
            sid,
            sid_string: String::new(),
        };
        profile.sid_string = sid_to_string(sid)?;
        Ok(profile)
    }

    pub(super) fn sid(&self) -> PSID {
        self.sid
    }
}

impl Drop for Profile {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `name` is NUL-terminated; `sid` came from
        // CreateAppContainerProfile (FreeSid ownership) and is freed once.
        unsafe {
            DeleteAppContainerProfile(self.name.as_ptr());
            FreeSid(self.sid);
        }
    }
}

/// Add an allow ACE for `sid` with `mask` to the DACL of `path`. Directory
/// grants inherit to children (the system propagates them).
#[allow(unsafe_code)]
pub(super) fn grant(path: &Path, sid: PSID, mask: u32, is_dir: bool) -> crate::Result<()> {
    let path_w = wide(path.as_os_str());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `path_w` is NUL-terminated; out-pointers are valid; `sd` owns
    // the returned DACL and is LocalFree'd below.
    let st = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if st != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "reading ACL of {} failed: Win32 error {st}",
            path.display()
        )));
    }
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: if is_dir {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `ea` and `dacl` are valid for the call; `new_dacl` is a
    // LocalAlloc'd ACL freed below.
    let st = unsafe { SetEntriesInAclW(1, &ea, dacl, &mut new_dacl) };
    if st != 0 {
        local_free(sd);
        return Err(crate::Error::isolation_unavailable(format!(
            "building ACL for {} failed: Win32 error {st}",
            path.display()
        )));
    }
    // SAFETY: `new_dacl` is a valid ACL from SetEntriesInAclW.
    let st = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null(),
        )
    };
    local_free(new_dacl);
    local_free(sd);
    if st != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "writing ACL of {} failed: Win32 error {st}",
            path.display()
        )));
    }
    Ok(())
}

/// Remove every explicit allow ACE for this operation's unique AppContainer
/// SID from one staged path. Cleanup is best-effort from `StagingGrants::drop`.
#[allow(unsafe_code)]
pub(super) fn revoke(path: &Path, sid: PSID) -> crate::Result<()> {
    let path_w = wide(path.as_os_str());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: NUL-terminated path and valid out-pointers; `sd` owns `dacl`.
    let st = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if st != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "reading ACL for cleanup of {} failed: Win32 error {st}",
            path.display()
        )));
    }
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0,
        grfAccessMode: REVOKE_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: valid ACL and explicit-access entry; output is LocalAlloc'd.
    let st = unsafe { SetEntriesInAclW(1, &ea, dacl, &mut new_dacl) };
    if st != 0 {
        local_free(sd);
        return Err(crate::Error::isolation_unavailable(format!(
            "building cleanup ACL for {} failed: Win32 error {st}",
            path.display()
        )));
    }
    // SAFETY: `new_dacl` is valid until freed below.
    let st = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null(),
        )
    };
    local_free(new_dacl);
    local_free(sd);
    if st != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "writing cleanup ACL of {} failed: Win32 error {st}",
            path.display()
        )));
    }
    Ok(())
}

/// The union of allow-ACE masks for `sid` in the DACL of `path`.
#[allow(unsafe_code)]
pub(super) fn allowed_mask(path: &Path, sid: PSID) -> crate::Result<u32> {
    let path_w = wide(path.as_os_str());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: as in `grant`.
    let st = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if st != 0 || dacl.is_null() {
        local_free(sd);
        return Err(crate::Error::isolation_unavailable(
            "reading back staging ACL",
        ));
    }
    let mut mask = 0u32;
    // SAFETY: `info` is a correctly sized out-struct for AclSizeInformation;
    // GetAce returns pointers into `dacl`, which lives until `sd` is freed;
    // allow ACEs carry their SID inline starting at `SidStart`.
    unsafe {
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        if GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) != 0
        {
            for i in 0..info.AceCount {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace) == 0 || ace.is_null() {
                    continue;
                }
                let header = &*(ace as *const ACE_HEADER);
                if header.AceType != 0 {
                    continue; // only ACCESS_ALLOWED_ACE_TYPE
                }
                let allowed = ace as *const ACCESS_ALLOWED_ACE;
                let ace_sid = std::ptr::addr_of!((*allowed).SidStart) as PSID;
                if EqualSid(ace_sid, sid) != 0 {
                    mask |= (*allowed).Mask;
                }
            }
        }
    }
    local_free(sd);
    Ok(mask)
}

/// Job Object owning the sandboxed process tree, with a completion port for
/// limit notifications. Closing it kills every member (KILL_ON_JOB_CLOSE).
pub(super) struct Job {
    handle: OwnedHandle,
    port: OwnedHandle,
}

#[allow(unsafe_code)]
fn set_info<T>(job: HANDLE, class: JOBOBJECTINFOCLASS, info: &T) -> bool {
    // SAFETY: `info` points to a fully initialized struct of the size given
    // that matches `class`.
    unsafe {
        SetInformationJobObject(
            job,
            class,
            (info as *const T).cast(),
            std::mem::size_of::<T>() as u32,
        ) != 0
    }
}

#[allow(unsafe_code)]
fn query_info<T>(job: HANDLE, class: JOBOBJECTINFOCLASS) -> Option<T> {
    // SAFETY: T is a plain C struct for which all-zero is valid; the buffer
    // size matches `class`.
    unsafe {
        let mut info: T = std::mem::zeroed();
        let ok = QueryInformationJobObject(
            job,
            class,
            (&mut info as *mut T).cast(),
            std::mem::size_of::<T>() as u32,
            std::ptr::null_mut(),
        );
        (ok != 0).then_some(info)
    }
}

impl Job {
    #[allow(unsafe_code)]
    pub(super) fn new(max_processes: u32, memory_bytes: u64) -> crate::Result<Job> {
        // SAFETY: unnamed job with default security; the handle is owned.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h.is_null() {
            return Err(unavailable("CreateJobObjectW"));
        }
        let handle = owned(h);
        // SAFETY: creates a new port not associated with a file handle.
        let p = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        if p.is_null() {
            return Err(unavailable("CreateIoCompletionPort"));
        }
        let port = owned(p);
        let assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: JOB_KEY as *mut core::ffi::c_void,
            CompletionPort: raw(&port),
        };
        if !set_info(
            raw(&handle),
            JobObjectAssociateCompletionPortInformation,
            &assoc,
        ) {
            return Err(unavailable("job completion port"));
        }
        // SAFETY: all-zero is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = REQUIRED_LIMIT_FLAGS;
        limits.BasicLimitInformation.ActiveProcessLimit = max_processes;
        limits.JobMemoryLimit = usize::try_from(memory_bytes)
            .map_err(|_| crate::Error::isolation_unavailable("memory limit exceeds usize"))?;
        if !set_info(raw(&handle), JobObjectExtendedLimitInformation, &limits) {
            return Err(unavailable("job limits"));
        }
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: UI_LIMIT_ALL,
        };
        if !set_info(raw(&handle), JobObjectBasicUIRestrictions, &ui) {
            return Err(unavailable("job UI restrictions"));
        }
        Ok(Job { handle, port })
    }

    /// Read the limits back from the kernel and confirm they are exactly
    /// what was requested, with breakaway disallowed.
    pub(super) fn verify(&self, max_processes: u32, memory_bytes: u64) -> crate::Result<()> {
        let limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            query_info(raw(&self.handle), JobObjectExtendedLimitInformation)
                .ok_or_else(|| unavailable("query job limits"))?;
        let ui: JOBOBJECT_BASIC_UI_RESTRICTIONS =
            query_info(raw(&self.handle), JobObjectBasicUIRestrictions)
                .ok_or_else(|| unavailable("query job UI restrictions"))?;
        let flags = limits.BasicLimitInformation.LimitFlags;
        let ok = flags & REQUIRED_LIMIT_FLAGS == REQUIRED_LIMIT_FLAGS
            && flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) == 0
            && limits.BasicLimitInformation.ActiveProcessLimit == max_processes
            && limits.JobMemoryLimit as u64 == memory_bytes
            && ui.UIRestrictionsClass & UI_LIMIT_ALL == UI_LIMIT_ALL;
        if ok {
            Ok(())
        } else {
            Err(crate::Error::isolation_unavailable(
                "job object limits did not read back as requested",
            ))
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn assign(&self, process: &OwnedHandle) -> crate::Result<()> {
        // SAFETY: both handles are live and owned by the caller.
        if unsafe { AssignProcessToJobObject(raw(&self.handle), raw(process)) } == 0 {
            return Err(unavailable("AssignProcessToJobObject"));
        }
        let mut inside = 0;
        // SAFETY: as above; `inside` is a valid out-parameter.
        if unsafe { IsProcessInJob(raw(process), raw(&self.handle), &mut inside) } == 0
            || inside == 0
        {
            return Err(crate::Error::isolation_unavailable(
                "process is not inside the sandbox job",
            ));
        }
        Ok(())
    }

    pub(super) fn active_processes(&self) -> crate::Result<u32> {
        let info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
            query_info(raw(&self.handle), JobObjectBasicAccountingInformation)
                .ok_or_else(|| crate::Error::internal("query job accounting failed"))?;
        Ok(info.ActiveProcesses)
    }

    #[allow(unsafe_code)]
    pub(super) fn terminate(&self) -> bool {
        // SAFETY: live job handle owned by self.
        unsafe { TerminateJobObject(raw(&self.handle), 1) != 0 }
    }

    /// Wait until kernel accounting reports that every process in the job
    /// has exited. Job handles are not waitable objects; waiting directly on
    /// one can block forever even when `ActiveProcesses` is already zero.
    pub(super) fn wait_empty(&self) {
        loop {
            if self.active_processes().is_ok_and(|active| active == 0)
                || self.next_message(25) == Some(MSG_ACTIVE_PROCESS_ZERO)
            {
                return;
            }
        }
    }

    /// Next job notification for this job, waiting at most `ms`.
    #[allow(unsafe_code)]
    pub(super) fn next_message(&self, ms: u32) -> Option<u32> {
        let mut msg = 0u32;
        let mut key = 0usize;
        let mut ov: *mut OVERLAPPED = std::ptr::null_mut();
        // SAFETY: valid port handle and out-parameters; job notifications
        // carry the message id in the byte count and no real OVERLAPPED.
        let ok =
            unsafe { GetQueuedCompletionStatus(raw(&self.port), &mut msg, &mut key, &mut ov, ms) };
        (ok != 0 && key == JOB_KEY).then_some(msg)
    }
}

/// Anonymous pipe: parent read end and child write end (not inheritable).
#[allow(unsafe_code)]
pub(super) fn pipe() -> crate::Result<(File, OwnedHandle)> {
    let mut r: HANDLE = std::ptr::null_mut();
    let mut w: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out-parameters; null attributes = non-inheritable.
    if unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), 0) } == 0 {
        return Err(unavailable("CreatePipe"));
    }
    // SAFETY: `r` is a fresh pipe handle owned by nobody else.
    let read = unsafe { File::from_raw_handle(r as RawHandle) };
    Ok((read, owned(w)))
}

#[allow(unsafe_code)]
fn set_inherit(h: HANDLE, on: bool) -> bool {
    // SAFETY: `h` is a live handle owned by the caller.
    unsafe {
        SetHandleInformation(
            h,
            HANDLE_FLAG_INHERIT,
            if on { HANDLE_FLAG_INHERIT } else { 0 },
        ) != 0
    }
}

pub(super) struct Spawned {
    pub(super) process: OwnedHandle,
    pub(super) thread: OwnedHandle,
}

impl Spawned {
    /// Kill a suspended or running root process and wait for it.
    #[allow(unsafe_code)]
    pub(super) fn kill(&self) {
        // SAFETY: live process handle owned by self.
        unsafe {
            TerminateProcess(raw(&self.process), 1);
            WaitForSingleObject(raw(&self.process), 10_000);
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn resume(&self) -> crate::Result<()> {
        // SAFETY: live primary thread handle from CreateProcessW.
        if unsafe { ResumeThread(raw(&self.thread)) } == u32::MAX {
            return Err(unavailable("ResumeThread"));
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    pub(super) fn exit_code(&self) -> crate::Result<u32> {
        let mut code = 0u32;
        // SAFETY: live process handle; valid out-parameter.
        if unsafe { GetExitCodeProcess(raw(&self.process), &mut code) } == 0 {
            return Err(crate::Error::internal("GetExitCodeProcess failed"));
        }
        Ok(code)
    }
}

/// Create the process suspended inside the AppContainer `sid` with zero
/// capabilities. Only `stdio` handles are inherited (explicit HANDLE_LIST).
#[allow(unsafe_code)]
pub(super) fn spawn_suspended(
    program: &Path,
    cmdline: &mut [u16],
    env_block: &[u16],
    cwd: &Path,
    sid: PSID,
    stdio: [HANDLE; 3],
) -> crate::Result<Spawned> {
    let program_w = wide(program.as_os_str());
    let cwd_w = wide(cwd.as_os_str());
    let caps = SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let handles = stdio;
    let mut size = 0usize;
    // SAFETY: sizing call with a null list is documented to fail and set
    // `size`.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size) };
    // usize-aligned backing storage for the opaque attribute list.
    let mut buf = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    // SAFETY: `buf` is at least `size` bytes and outlives the list.
    if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) } == 0 {
        return Err(unavailable("InitializeProcThreadAttributeList"));
    }
    struct ListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for ListGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: initialized above, deleted exactly once.
            unsafe { DeleteProcThreadAttributeList(self.0) }
        }
    }
    let _list_guard = ListGuard(list);
    // SAFETY: `caps` and `handles` outlive CreateProcessW below; sizes match.
    let ok = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&caps as *const SECURITY_CAPABILITIES).cast(),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        ) != 0
            && UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(&handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) != 0
    };
    if !ok {
        return Err(unavailable("UpdateProcThreadAttribute"));
    }
    // SAFETY: all-zero STARTUPINFOEXW / PROCESS_INFORMATION are valid.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = handles[0];
    si.StartupInfo.hStdOutput = handles[1];
    si.StartupInfo.hStdError = handles[2];
    si.lpAttributeList = list;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let _serial = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !handles.iter().all(|h| set_inherit(*h, true)) {
        handles.iter().for_each(|h| {
            set_inherit(*h, false);
        });
        return Err(unavailable("SetHandleInformation"));
    }
    // SAFETY: every pointer is valid and NUL-terminated where required, the
    // command line buffer is mutable and NUL-terminated, the environment is
    // a double-NUL-terminated UTF-16 block, and the attribute list holds
    // only the AppContainer capabilities and the three stdio handles.
    let created = unsafe {
        CreateProcessW(
            program_w.as_ptr(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_NO_WINDOW,
            env_block.as_ptr().cast(),
            cwd_w.as_ptr(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    // SAFETY: read immediately after the failing call.
    let err = unsafe { GetLastError() };
    handles.iter().for_each(|h| {
        set_inherit(*h, false);
    });
    drop(_serial);
    if created == 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "CreateProcessW in AppContainer failed: {}",
            io::Error::from_raw_os_error(err as i32)
        )));
    }
    Ok(Spawned {
        process: owned(pi.hProcess),
        thread: owned(pi.hThread),
    })
}

#[allow(unsafe_code)]
fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<usize>> {
    let mut needed = 0u32;
    // SAFETY: sizing call with a null buffer.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    // usize-aligned buffer, large enough for the reported size.
    let mut buf = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: `buf` holds at least `needed` bytes.
    let ok =
        unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), needed, &mut needed) };
    (ok != 0).then_some(buf)
}

/// Facts read from a process token by the parent.
pub(super) struct TokenFacts {
    pub(super) is_appcontainer: bool,
    pub(super) sid_matches: bool,
    pub(super) capability_count: u32,
    pub(super) is_lpac: bool,
}

/// Inspect the (suspended) child's primary token from the parent.
#[allow(unsafe_code)]
pub(super) fn token_facts(process: &OwnedHandle, sid: PSID) -> crate::Result<TokenFacts> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: live process handle with full access; `token` is closed via
    // OwnedHandle.
    if unsafe { OpenProcessToken(raw(process), TOKEN_QUERY, &mut token) } == 0 {
        return Err(unavailable("OpenProcessToken(child)"));
    }
    let token = owned(token);
    let t = raw(&token);
    let bool_of = |class| token_info(t, class).map(|b| b[0] as u32 != 0);
    let is_appcontainer = bool_of(TokenIsAppContainer).unwrap_or(false);
    let is_lpac = bool_of(TokenIsLessPrivilegedAppContainer).unwrap_or(false);
    // SAFETY: the buffers hold the documented structures for each class;
    // embedded SID pointers point into the same buffer, alive while used.
    let sid_matches = token_info(t, TokenAppContainerSid)
        .map(|b| unsafe {
            let info = &*(b.as_ptr() as *const TOKEN_APPCONTAINER_INFORMATION);
            !info.TokenAppContainer.is_null() && EqualSid(info.TokenAppContainer, sid) != 0
        })
        .unwrap_or(false);
    let capability_count = match token_info(t, TokenCapabilities) {
        // SAFETY: TOKEN_GROUPS header at the start of the buffer.
        Some(b) => unsafe { (*(b.as_ptr() as *const TOKEN_GROUPS)).GroupCount },
        None => u32::MAX,
    };
    Ok(TokenFacts {
        is_appcontainer,
        sid_matches,
        capability_count,
        is_lpac,
    })
}

/// String SID of the current user (for the tray-style pipe DACL).
#[allow(unsafe_code)]
pub(super) fn current_user_sid() -> crate::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: pseudo-handle for this process; token owned below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(unavailable("OpenProcessToken(self)"));
    }
    let token = owned(token);
    let buf = token_info(raw(&token), TokenUser).ok_or_else(|| unavailable("TokenUser"))?;
    // SAFETY: TOKEN_USER header; its SID points into `buf`.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    sid_to_string(sid)
}

/// A non-blocking named-pipe server, used by the probe as a stand-in for the
/// tray's approval pipe. `sddl = None` uses the default DACL.
#[allow(unsafe_code)]
pub(super) fn listening_pipe(name: &str, sddl: Option<&str>) -> crate::Result<OwnedHandle> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if let Some(s) = sddl {
        let s_w = wide(OsStr::new(s));
        // SAFETY: NUL-terminated SDDL; `sd` is LocalAlloc'd and freed below.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                s_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(unavailable("pipe security descriptor"));
        }
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let name_w = wide(OsStr::new(name));
    // SAFETY: valid name and attributes; returned handle is owned below.
    let h = unsafe {
        CreateNamedPipeW(
            name_w.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            if sd.is_null() { std::ptr::null() } else { &sa },
        )
    };
    local_free(sd);
    if h == INVALID_HANDLE_VALUE {
        return Err(unavailable("CreateNamedPipeW"));
    }
    Ok(owned(h))
}

/// True if any client has opened the non-blocking pipe server `h`.
#[allow(unsafe_code)]
pub(super) fn pipe_has_client(h: &OwnedHandle) -> bool {
    // SAFETY: PIPE_NOWAIT server handle; with no OVERLAPPED the call returns
    // immediately and reports state through GetLastError.
    let ok = unsafe { ConnectNamedPipe(raw(h), std::ptr::null_mut()) };
    // SAFETY: read immediately after the call.
    ok != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED
}
