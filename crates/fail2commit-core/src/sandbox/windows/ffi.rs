//! Narrow Win32 FFI for the AppContainer backend (T-007b, FR-007, SPEC-007).
//!
//! Every function that touches raw Win32 state opts into `unsafe_code`
//! individually and documents why each call is sound. Callers in
//! `windows.rs` stay safe Rust. Every failure here maps to
//! `IsolationUnavailable` because it happens before package code runs.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, SetHandleInformation, ERROR_ACCESS_DENIED, ERROR_PIPE_CONNECTED,
    ERROR_SHARING_VIOLATION, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, REVOKE_ACCESS, SDDL_REVISION_1, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, FreeSid, GetAce, GetAclInformation, GetTokenInformation,
    TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer,
    TokenIsLessPrivilegedAppContainer, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS, WRITE_DAC,
};
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

/// String form of a SID the caller still owns.
pub(super) fn sid_text(sid: PSID) -> crate::Result<String> {
    sid_to_string(sid)
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

/// One staged file or directory, addressed by an open handle.
///
/// Every ACL read and write in this backend runs through a handle opened with
/// `FILE_FLAG_OPEN_REPARSE_POINT`, so a reparse point can never redirect a
/// grant, and the identity of the object is fixed before its DACL is touched.
/// `GetFileInformationByHandle` reports the link count and attribute bits for
/// exactly that object, and `GetFinalPathNameByHandleW` reports where it really
/// lives, which the caller compares against the stage root.
pub(super) struct StagedObject {
    handle: OwnedHandle,
    path: PathBuf,
    attributes: u32,
    links: u32,
}

impl StagedObject {
    /// Open `path` without following a reparse point. `READ_CONTROL` and
    /// `WRITE_DAC` are requested because every ACL call below needs them on
    /// the object itself; `FILE_READ_ATTRIBUTES` feeds
    /// `GetFileInformationByHandle`.
    #[allow(unsafe_code)]
    pub(super) fn open(path: &Path) -> crate::Result<StagedObject> {
        let path_w = wide(path.as_os_str());
        // SAFETY: `path_w` is NUL-terminated; the returned handle is owned by
        // the `OwnedHandle` below and closed exactly once.
        let h = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(crate::Error::isolation_unavailable(format!(
                "opening staged path {} failed: {}",
                path.display(),
                io::Error::last_os_error()
            )));
        }
        let handle = owned(h);
        // SAFETY: `info` is a correctly sized out-struct for the call and the
        // handle is live for the duration.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(raw(&handle), &mut info) } == 0 {
            return Err(unavailable("GetFileInformationByHandle"));
        }
        Ok(StagedObject {
            handle,
            path: path.to_path_buf(),
            attributes: info.dwFileAttributes,
            links: info.nNumberOfLinks,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn is_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub(super) fn is_reparse_point(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Number of directory entries that name this file object. A hard link
    /// makes this exceed one without any reparse attribute.
    pub(super) fn link_count(&self) -> u32 {
        self.links
    }

    /// Canonical path of the object this handle refers to, in the same
    /// extended-length form `std::fs::canonicalize` returns.
    #[allow(unsafe_code)]
    pub(super) fn final_path(&self) -> crate::Result<PathBuf> {
        let mut buf = vec![0u16; 260];
        loop {
            // SAFETY: the buffer is valid for `buf.len()` UTF-16 units and the
            // handle is live; the call writes at most that many units.
            let len = unsafe {
                GetFinalPathNameByHandleW(
                    raw(&self.handle),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            };
            if len == 0 {
                return Err(unavailable("GetFinalPathNameByHandleW"));
            }
            if (len as usize) < buf.len() {
                return Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize])));
            }
            buf.resize(len as usize + 1, 0);
        }
    }

    /// Add an allow ACE for `sid` with `mask` to this object's DACL. A
    /// directory gets an inheritable ACE; the caller also walks children.
    ///
    /// A NULL DACL means "everyone has full access"; adding an explicit entry
    /// would replace that with a package-only list and drop the owner's own
    /// access, so it is refused before anything is written.
    #[allow(unsafe_code)]
    pub(super) fn grant(&self, sid: PSID, mask: u32) -> crate::Result<()> {
        let (sd, dacl) = self.dacl()?;
        if dacl.is_null() {
            local_free(sd);
            return Err(crate::Error::isolation_unavailable(format!(
                "staged path has a NULL DACL (unrestricted access); refusing to replace it: {}",
                self.path.display()
            )));
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: if self.is_dir() {
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
                self.path.display()
            )));
        }
        // SAFETY: `new_dacl` is a valid ACL from SetEntriesInAclW and the
        // handle was opened with WRITE_DAC for exactly this object.
        let st = unsafe {
            SetSecurityInfo(
                raw(&self.handle),
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
                self.path.display()
            )));
        }
        Ok(())
    }

    /// Remove every explicit entry for `sid` from this object's DACL.
    #[allow(unsafe_code)]
    pub(super) fn revoke(&self, sid: PSID) -> crate::Result<()> {
        let (sd, dacl) = self.dacl()?;
        if dacl.is_null() {
            // A NULL DACL names nobody: there is nothing to remove.
            local_free(sd);
            return Ok(());
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
                self.path.display()
            )));
        }
        // SAFETY: `new_dacl` is valid until freed below and the handle was
        // opened with WRITE_DAC for this object.
        let st = unsafe {
            SetSecurityInfo(
                raw(&self.handle),
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
                self.path.display()
            )));
        }
        Ok(())
    }

    /// The union of allow-ACE masks for `sid` in this object's DACL.
    #[allow(unsafe_code)]
    pub(super) fn allowed_mask(&self, sid: PSID) -> crate::Result<u32> {
        let (sd, dacl) = self.dacl()?;
        if dacl.is_null() {
            local_free(sd);
            return Err(crate::Error::isolation_unavailable(format!(
                "staged path has a NULL DACL; access cannot be read back: {}",
                self.path.display()
            )));
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

    /// Read this object's DACL. The returned descriptor owns `dacl` and must be
    /// released with `local_free`.
    #[allow(unsafe_code)]
    fn dacl(&self) -> crate::Result<(PSECURITY_DESCRIPTOR, *mut ACL)> {
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: live handle; every returned pointer belongs to `sd`.
        let st = unsafe {
            GetSecurityInfo(
                raw(&self.handle),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if st != 0 || sd.is_null() {
            local_free(sd);
            return Err(crate::Error::isolation_unavailable(format!(
                "reading ACL of {} failed: Win32 error {st}",
                self.path.display()
            )));
        }
        Ok((sd, dacl))
    }
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

    /// Terminate every process in the job. The result is checked: a failed
    /// termination must not be reported as a clean timeout.
    #[allow(unsafe_code)]
    pub(super) fn terminate(&self) -> crate::Result<()> {
        // SAFETY: live job handle owned by self.
        if unsafe { TerminateJobObject(raw(&self.handle), 1) } == 0 {
            return Err(unavailable("TerminateJobObject"));
        }
        Ok(())
    }

    /// Wait until kernel accounting reports that every process in the job has
    /// exited, giving up at `deadline`. Job handles are not waitable objects;
    /// waiting directly on one can block forever even when `ActiveProcesses`
    /// is already zero. A query error and an expired deadline are errors, so a
    /// caller can never mistake them for a stopped tree.
    pub(super) fn wait_empty(&self, deadline: Instant) -> crate::Result<()> {
        while Instant::now() < deadline {
            if self.active_processes()? == 0 {
                return Ok(());
            }
            if self.next_message(25) == Some(MSG_ACTIVE_PROCESS_ZERO) {
                return Ok(());
            }
        }
        Err(crate::Error::isolation_unavailable(
            "sandbox processes did not stop before the cleanup deadline",
        ))
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
    /// Kill a suspended or running root process and wait for it to exit.
    /// Both results are checked so a leaked process is never silent.
    #[allow(unsafe_code)]
    pub(super) fn kill(&self) -> crate::Result<()> {
        // SAFETY: live process handle owned by self; the error is read
        // immediately after the failing call.
        let terminated = unsafe { TerminateProcess(raw(&self.process), 1) } != 0;
        let err = unsafe { GetLastError() };
        // SAFETY: live process handle; WAIT_OBJECT_0 is 0.
        let waited = unsafe { WaitForSingleObject(raw(&self.process), 5_000) };
        if waited != 0 {
            return Err(crate::Error::isolation_unavailable(format!(
                "waiting for the sandbox root process to stop failed: {}",
                io::Error::from_raw_os_error(err as i32)
            )));
        }
        // ERROR_ACCESS_DENIED means the process had already exited.
        if !terminated && err != ERROR_ACCESS_DENIED {
            return Err(crate::Error::isolation_unavailable(format!(
                "TerminateProcess on the sandbox root process failed: {}",
                io::Error::from_raw_os_error(err as i32)
            )));
        }
        Ok(())
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

// ---------------------------------------------------------------------------
// Operating-system facts. These are resolved from the OS, never from the
// process environment, so a caller-controlled environment cannot steer where a
// grant is written or which binary answers a control question (S7B-002,
// S7B-003). The windows-sys feature set pinned by the coordinator does not
// include `Win32_System_SystemInformation` or `Win32_UI_Shell`, so the four
// entry points are declared here exactly like the `userenv` block above.
// ---------------------------------------------------------------------------

#[link(name = "kernel32")]
extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn LoadLibraryW(name: *const u16) -> HANDLE;
    fn GetProcAddress(module: HANDLE, name: *const u8) -> *mut core::ffi::c_void;
    fn FreeLibrary(module: HANDLE) -> i32;
    fn GetProcessHeap() -> HANDLE;
    fn HeapFree(heap: HANDLE, flags: u32, memory: *mut core::ffi::c_void) -> i32;
}

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/// `FOLDERID_LocalAppData` and `FOLDERID_Profile` (knownfolders.h).
const FOLDERID_LOCAL_APPDATA: Guid = Guid {
    data1: 0xF1B3_2785,
    data2: 0x6FBA,
    data3: 0x4FCF,
    data4: [0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91],
};
const FOLDERID_PROFILE: Guid = Guid {
    data1: 0x5E6C_858F,
    data2: 0x0E22,
    data3: 0x4760,
    data4: [0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73],
};

#[link(name = "shell32")]
extern "system" {
    fn SHGetKnownFolderPath(
        folder: *const Guid,
        flags: u32,
        token: HANDLE,
        path: *mut *mut u16,
    ) -> i32;
}

#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(memory: *mut core::ffi::c_void);
}

/// A `u32` count of UTF-16 units is plenty for any system path.
#[allow(unsafe_code)]
fn system_path(
    call: unsafe extern "system" fn(*mut u16, u32) -> u32,
    what: &str,
) -> crate::Result<PathBuf> {
    let mut buf = vec![0u16; 512];
    // SAFETY: the buffer is valid for `buf.len()` UTF-16 units and the callee
    // writes at most that many; a return value of zero means failure.
    let len = unsafe { call(buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 {
        return Err(unavailable(what));
    }
    let len = len as usize;
    if len > buf.len() {
        return Err(crate::Error::isolation_unavailable(format!(
            "{what} reported an implausible length {len}"
        )));
    }
    Ok(PathBuf::from(OsString::from_wide(&buf[..len])))
}

/// `<Windows>\System32`, as the operating system reports it.
pub(super) fn system_directory() -> crate::Result<PathBuf> {
    system_path(GetSystemDirectoryW, "GetSystemDirectoryW")
}

/// The Windows directory, as the operating system reports it. This is the
/// trusted source for the child's `SystemRoot`.
pub(super) fn windows_directory() -> crate::Result<PathBuf> {
    system_path(GetSystemWindowsDirectoryW, "GetSystemWindowsDirectoryW")
}

#[allow(unsafe_code)]
fn known_folder(folder: &Guid, what: &str) -> crate::Result<PathBuf> {
    let mut raw: *mut u16 = std::ptr::null_mut();
    // SAFETY: `folder` is a valid GUID constant; the callee allocates a
    // NUL-terminated string with CoTaskMemAlloc, freed below.
    let hr = unsafe { SHGetKnownFolderPath(folder, 0, std::ptr::null_mut(), &mut raw) };
    if hr < 0 || raw.is_null() {
        return Err(crate::Error::isolation_unavailable(format!(
            "SHGetKnownFolderPath({what}) failed: HRESULT 0x{:08X}",
            hr as u32
        )));
    }
    let mut len = 0usize;
    // SAFETY: the string is NUL-terminated by the callee.
    let path = unsafe {
        while *raw.add(len) != 0 {
            len += 1;
        }
        PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(raw, len)))
    };
    // SAFETY: `raw` came from CoTaskMemAlloc and is freed exactly once.
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(path)
}

/// The user's `%LOCALAPPDATA%` as a known folder, not as an environment value.
pub(super) fn known_local_app_data() -> crate::Result<PathBuf> {
    known_folder(&FOLDERID_LOCAL_APPDATA, "FOLDERID_LocalAppData")
}

/// The user profile directory as a known folder.
pub(super) fn known_user_profile() -> crate::Result<PathBuf> {
    known_folder(&FOLDERID_PROFILE, "FOLDERID_Profile")
}

/// AppContainer SIDs that the operating system currently allows to send
/// loopback traffic (`NetworkIsolationGetAppContainerConfig` in
/// FirewallAPI.dll, the same configuration `CheckNetIsolation LoopbackExempt`
/// edits). No process is launched and no environment value is consulted; a
/// missing export or a failing call is an error, so the caller fails closed.
#[allow(unsafe_code)]
pub(super) fn loopback_exempt_sids() -> crate::Result<Vec<String>> {
    type GetConfig = unsafe extern "system" fn(*mut u32, *mut *mut SID_AND_ATTRIBUTES) -> u32;
    let library = wide(OsStr::new("FirewallAPI.dll"));
    // SAFETY: NUL-terminated module name; the loaded module is freed below.
    let module = unsafe { LoadLibraryW(library.as_ptr()) };
    if module.is_null() {
        return Err(unavailable("LoadLibraryW(FirewallAPI.dll)"));
    }
    // SAFETY: NUL-terminated export name in a C string literal; the module is
    // still loaded.
    let proc = unsafe {
        GetProcAddress(
            module,
            c"NetworkIsolationGetAppContainerConfig".as_ptr().cast(),
        )
    };
    if proc.is_null() {
        // SAFETY: `module` is a live module handle from LoadLibraryW.
        unsafe { FreeLibrary(module) };
        return Err(crate::Error::isolation_unavailable(
            "FirewallAPI.dll does not export NetworkIsolationGetAppContainerConfig",
        ));
    }
    // SAFETY: the export has the documented signature for this name.
    let get_config: GetConfig = unsafe { std::mem::transmute(proc) };
    let mut count = 0u32;
    let mut sids: *mut SID_AND_ATTRIBUTES = std::ptr::null_mut();
    // SAFETY: both out-parameters are valid; the callee allocates the array
    // from the process heap and every SID inside it.
    let status = unsafe { get_config(&mut count, &mut sids) };
    let mut out = Vec::new();
    if status == 0 && !sids.is_null() {
        // SAFETY: the callee guarantees `count` valid entries when it succeeds.
        for i in 0..count as usize {
            let entry = unsafe { &*sids.add(i) };
            if entry.Sid.is_null() {
                continue;
            }
            if let Ok(sid) = sid_to_string(entry.Sid) {
                out.push(sid);
            }
        }
        // SAFETY: the documented sample frees each SID and then the array with
        // HeapFree(GetProcessHeap(), ...).
        unsafe {
            let heap = GetProcessHeap();
            for i in 0..count as usize {
                let entry = &*sids.add(i);
                if !entry.Sid.is_null() {
                    HeapFree(heap, 0, entry.Sid.cast());
                }
            }
            HeapFree(heap, 0, sids.cast());
        }
    }
    // SAFETY: `module` is a live module handle from LoadLibraryW.
    unsafe { FreeLibrary(module) };
    if status != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "NetworkIsolationGetAppContainerConfig failed: Win32 error {status}"
        )));
    }
    Ok(out)
}

/// A SID owned through `LocalFree`, for SIDs parsed back from a state file.
pub(super) struct OwnedSid(PSID);

impl OwnedSid {
    pub(super) fn as_psid(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.0` came from ConvertStringSidToSidW (LocalAlloc) and is
        // freed exactly once.
        local_free(self.0);
    }
}

/// Parse a string SID (`S-1-15-2-...`).
#[allow(unsafe_code)]
pub(super) fn sid_from_string(text: &str) -> crate::Result<OwnedSid> {
    let text_w = wide(OsStr::new(text));
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: NUL-terminated input; `sid` is a LocalAlloc'd SID owned by the
    // returned `OwnedSid`.
    if unsafe { ConvertStringSidToSidW(text_w.as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return Err(unavailable("ConvertStringSidToSidW"));
    }
    Ok(OwnedSid(sid))
}

/// Open a file read-only with a share mode that keeps the object alive while
/// any other handle (including an inherited one in a child) is open, and with
/// `bInheritHandle` set.
#[allow(unsafe_code)]
pub(super) fn open_inheritable(path: &Path) -> crate::Result<OwnedHandle> {
    let path_w = wide(path.as_os_str());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: NUL-terminated path and valid attributes; the returned handle is
    // owned by the caller and closed once.
    let h = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(crate::Error::isolation_unavailable(format!(
            "opening the inheritance canary {} failed: {}",
            path.display(),
            io::Error::last_os_error()
        )));
    }
    Ok(owned(h))
}

/// True when `path` can be opened exclusively (share mode 0), that is, when no
/// other handle to that file object exists anywhere in the system. A child that
/// inherited an unlisted handle keeps the object open, so this fails with
/// `ERROR_SHARING_VIOLATION`: a direct measurement of the explicit stdio handle
/// list rather than an inference from the spawn call.
#[allow(unsafe_code)]
pub(super) fn exclusive_open_succeeds(path: &Path) -> crate::Result<bool> {
    let path_w = wide(path.as_os_str());
    // SAFETY: NUL-terminated path; a successful handle is closed immediately.
    let h = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            FILE_READ_ATTRIBUTES,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if h != INVALID_HANDLE_VALUE {
        drop(owned(h));
        return Ok(true);
    }
    // SAFETY: read immediately after the failing call.
    let err = unsafe { GetLastError() };
    if err == ERROR_SHARING_VIOLATION {
        return Ok(false);
    }
    Err(crate::Error::isolation_unavailable(format!(
        "exclusive open of {} failed: {}",
        path.display(),
        io::Error::from_raw_os_error(err as i32)
    )))
}

/// Replace a staged object's DACL with a NULL DACL. Test-only: it exists to
/// prove `StagedObject::grant` refuses that case instead of rewriting it
/// (S7B-007). Only ever called on a disposable path inside the stage root.
#[cfg(test)]
#[allow(unsafe_code)]
pub(super) fn set_null_dacl_for_tests(path: &Path) -> crate::Result<()> {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;

    let path_w = wide(path.as_os_str());
    // SAFETY: NUL-terminated path; a null DACL pointer is the documented way to
    // write "no access control", and this is only reachable from tests.
    let st = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    if st != 0 {
        return Err(crate::Error::isolation_unavailable(format!(
            "setting a NULL DACL on {} failed: Win32 error {st}",
            path.display()
        )));
    }
    Ok(())
}
