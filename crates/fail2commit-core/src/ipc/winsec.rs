//! Windows identity and DACL helpers for the approval pipe.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, AddAccessDeniedAce, GetAce, GetKernelObjectSecurity, GetLengthSid,
    GetSecurityDescriptorDacl, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    SetSecurityDescriptorDacl, TokenIsAppContainer, TokenUser, ACL, ACL_REVISION,
    DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// Raw SID bytes (`SID` layout), safe to move and compare.
pub type Sid = Vec<u8>;

/// `S-1-15-2-1` ALL APPLICATION PACKAGES.
pub const ALL_APP_PACKAGES: &str = "S-1-15-2-1";
/// `S-1-15-2-2` ALL RESTRICTED APPLICATION PACKAGES.
pub const ALL_RESTRICTED_APP_PACKAGES: &str = "S-1-15-2-2";

fn last_err(what: &str) -> crate::Error {
    crate::Error::internal(format!("{what}: {}", std::io::Error::last_os_error()))
}

fn own(h: HANDLE) -> OwnedHandle {
    // SAFETY: `h` is a fresh, non-null handle that nothing else owns.
    unsafe { OwnedHandle::from_raw_handle(h as RawHandle) }
}

/// `S-1-<auth>-<sub>...` text for SID bytes.
pub fn sid_string(sid: &[u8]) -> String {
    let count = sid[1] as usize;
    let auth = sid[2..8].iter().fold(0u64, |a, b| (a << 8) | *b as u64);
    let mut s = format!("S-{}-{}", sid[0], auth);
    for i in 0..count {
        let o = 8 + i * 4;
        s.push_str(&format!(
            "-{}",
            u32::from_le_bytes(sid[o..o + 4].try_into().unwrap())
        ));
    }
    s
}

/// Build SID bytes from `S-1-15-2-1` style text (decimal authority only).
pub fn sid_from_string(text: &str) -> Option<Sid> {
    let parts: Vec<&str> = text.strip_prefix("S-")?.split('-').collect();
    if parts.len() < 3 || parts[0] != "1" {
        return None;
    }
    let auth: u64 = parts[1].parse().ok()?;
    let subs: Vec<u32> = parts[2..]
        .iter()
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    let mut out = vec![1u8, subs.len() as u8];
    out.extend_from_slice(&auth.to_be_bytes()[2..]);
    for s in subs {
        out.extend_from_slice(&s.to_le_bytes());
    }
    Some(out)
}

pub struct TokenFacts {
    pub user: Sid,
    pub app_container: bool,
}

fn token_facts(token: &OwnedHandle) -> crate::Result<TokenFacts> {
    let h = token.as_raw_handle() as HANDLE;
    let mut len = 0u32;
    // SAFETY: size query with a null buffer; `len` is a valid out pointer.
    unsafe { GetTokenInformation(h, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 || len > 4096 {
        return Err(last_err("GetTokenInformation(size)"));
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` is at least `len` bytes and 8-byte aligned.
    if unsafe { GetTokenInformation(h, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(last_err("GetTokenInformation(user)"));
    }
    // SAFETY: the buffer now holds a TOKEN_USER whose Sid points into `buf`.
    let user = unsafe {
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let n = GetLengthSid(tu.User.Sid) as usize;
        std::slice::from_raw_parts(tu.User.Sid as *const u8, n).to_vec()
    };
    let mut ac = 0u32;
    // SAFETY: `ac` is a valid 4-byte out buffer for TokenIsAppContainer.
    let ok = unsafe {
        GetTokenInformation(
            h,
            TokenIsAppContainer,
            (&mut ac as *mut u32).cast(),
            4,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(last_err("GetTokenInformation(appcontainer)"));
    }
    Ok(TokenFacts {
        user,
        app_container: ac != 0,
    })
}

/// Token facts of this process.
pub fn current_process_facts() -> crate::Result<TokenFacts> {
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: valid pseudo handle and out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) } == 0 {
        return Err(last_err("OpenProcessToken"));
    }
    token_facts(&own(t))
}

pub fn current_user_sid() -> crate::Result<Sid> {
    Ok(current_process_facts()?.user)
}

/// Token facts of another process by id (callers fail closed on error).
pub fn process_facts(pid: u32) -> crate::Result<TokenFacts> {
    // SAFETY: plain query-rights open of a process by id.
    let p = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if p.is_null() {
        return Err(last_err("OpenProcess"));
    }
    let p = own(p);
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: `p` is a live process handle.
    if unsafe { OpenProcessToken(p.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut t) } == 0 {
        return Err(last_err("OpenProcessToken(peer)"));
    }
    token_facts(&own(t))
}

/// `\\.\pipe\fail2commit-approval-<SID>` for the current user.
pub fn pipe_name() -> crate::Result<String> {
    Ok(format!(
        r"\\.\pipe\fail2commit-approval-{}",
        sid_string(&current_user_sid()?)
    ))
}

/// Owns the DACL memory referenced by the security attributes.
pub struct PipeSecurity {
    _acl: Vec<u64>,
    _sd: Box<SECURITY_DESCRIPTOR>,
    attrs: SECURITY_ATTRIBUTES,
}

// SAFETY: the raw pointers in `attrs` point only into the boxed descriptor and
// ACL buffer owned by this same struct, and nothing mutates them after `new`.
unsafe impl Send for PipeSecurity {}

impl PipeSecurity {
    /// Deny both app-package SIDs, then allow only `user`. No other entry
    /// (administrators and SYSTEM are not granted access either).
    pub fn new(user: &[u8]) -> crate::Result<Self> {
        let denies = [ALL_APP_PACKAGES, ALL_RESTRICTED_APP_PACKAGES]
            .map(|s| sid_from_string(s).expect("constant SID"));
        // ACE = header(4) + mask(4) + SID.
        let total = 8 + denies.iter().map(|s| 8 + s.len()).sum::<usize>() + 8 + user.len();
        let mut acl = vec![0u64; total.div_ceil(8) + 1];
        // SAFETY: `acl` is zeroed, aligned, and large enough for all ACEs.
        unsafe {
            let p = acl.as_mut_ptr() as *mut ACL;
            if InitializeAcl(p, (acl.len() * 8) as u32, ACL_REVISION) == 0 {
                return Err(last_err("InitializeAcl"));
            }
            for d in &denies {
                if AddAccessDeniedAce(p, ACL_REVISION, FILE_ALL_ACCESS, d.as_ptr() as *mut c_void)
                    == 0
                {
                    return Err(last_err("AddAccessDeniedAce"));
                }
            }
            if AddAccessAllowedAce(
                p,
                ACL_REVISION,
                FILE_ALL_ACCESS,
                user.as_ptr() as *mut c_void,
            ) == 0
            {
                return Err(last_err("AddAccessAllowedAce"));
            }
        }
        // SAFETY: SECURITY_DESCRIPTOR is plain data; initialised right below.
        let mut sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        // SAFETY: `sd` and `acl` are owned by the returned struct.
        unsafe {
            let psd = (&mut *sd as *mut SECURITY_DESCRIPTOR).cast::<c_void>();
            if InitializeSecurityDescriptor(psd, 1) == 0
                || SetSecurityDescriptorDacl(psd, 1, acl.as_ptr().cast(), 0) == 0
            {
                return Err(last_err("security descriptor"));
            }
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&*sd as *const SECURITY_DESCRIPTOR).cast_mut().cast(),
            bInheritHandle: 0,
        };
        Ok(PipeSecurity {
            _acl: acl,
            _sd: sd,
            attrs,
        })
    }

    pub fn attributes(&self) -> *const SECURITY_ATTRIBUTES {
        &self.attrs
    }
}

/// `(allow, sid, mask)` entries of a kernel object's DACL, in order.
pub fn dacl_entries(object: &impl AsRawHandle) -> crate::Result<Vec<(bool, String, u32)>> {
    let handle = object.as_raw_handle() as HANDLE;
    let mut need = 0u32;
    // SAFETY: size query.
    unsafe {
        GetKernelObjectSecurity(
            handle,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut need,
        )
    };
    if need == 0 {
        return Err(last_err("GetKernelObjectSecurity(size)"));
    }
    let mut buf = vec![0u64; (need as usize).div_ceil(8)];
    // SAFETY: buffer sized by the query above.
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            DACL_SECURITY_INFORMATION,
            buf.as_mut_ptr().cast(),
            need,
            &mut need,
        )
    } == 0
    {
        return Err(last_err("GetKernelObjectSecurity"));
    }
    let (mut present, mut defaulted) = (0i32, 0i32);
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `buf` holds a self-relative descriptor.
    if unsafe {
        GetSecurityDescriptorDacl(
            buf.as_mut_ptr().cast::<c_void>(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
    {
        return Err(last_err("GetSecurityDescriptorDacl"));
    }
    let mut out = Vec::new();
    if present == 0 || acl.is_null() {
        return Ok(out);
    }
    // SAFETY: `acl` points into `buf`; ACE layout is header(4) mask(4) SID.
    unsafe {
        for i in 0..(*acl).AceCount as u32 {
            let mut ace: *mut c_void = std::ptr::null_mut();
            if GetAce(acl, i, &mut ace) == 0 {
                return Err(last_err("GetAce"));
            }
            let b = ace as *const u8;
            let ty = *b;
            let mask = std::ptr::read_unaligned(b.add(4) as *const u32);
            let sid = b.add(8) as *const c_void;
            let n = GetLengthSid(sid as *mut c_void) as usize;
            let s = sid_string(std::slice::from_raw_parts(sid as *const u8, n));
            match ty {
                ACCESS_ALLOWED_ACE_TYPE => out.push((true, s, mask)),
                ACCESS_DENIED_ACE_TYPE => out.push((false, s, mask)),
                _ => out.push((false, format!("unknown-ace-{ty}"), mask)),
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_text_round_trip() {
        let sid = sid_from_string("S-1-15-2-1").unwrap();
        assert_eq!(sid_string(&sid), "S-1-15-2-1");
        let me = current_user_sid().unwrap();
        assert!(sid_string(&me).starts_with("S-1-5-"));
        assert!(!current_process_facts().unwrap().app_container);
    }
}
