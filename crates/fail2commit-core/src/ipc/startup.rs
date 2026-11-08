//! Sign-in startup for the tray: one value under the HKCU `Run` key, recorded
//! as an owned change with the previous value so uninstall restores it.
//!
//! The key path is injectable so tests use a throw-away
//! `HKCU\Software\fail2commit-test-*` key instead of the real Run key.
#![allow(unsafe_code)]

use crate::integration::{Integration, IntegrationStatus, OwnedChange, SetupCtx};
use serde_json::json;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const VALUE_NAME: &str = "fail2commit-tray";
const ID: &str = "tray-startup";
const TRAY_EXE: &str = "fail2commit-tray.exe";

type Hkey = isize;
const HKEY_CURRENT_USER: Hkey = 0x8000_0001u32 as i32 as isize;
const KEY_READ_WRITE: u32 = 0x20019 | 0x20006;
const REG_SZ: u32 = 1;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;

// Hand-declared: core has no windows-sys registry feature and Cargo.toml is
// coordinator-owned.
#[link(name = "advapi32")]
extern "system" {
    fn RegCreateKeyExW(
        key: Hkey,
        sub: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        sam: u32,
        sa: *const c_void,
        out: *mut Hkey,
        disposition: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        key: Hkey,
        name: *const u16,
        reserved: u32,
        ty: u32,
        data: *const u8,
        len: u32,
    ) -> i32;
    fn RegQueryValueExW(
        key: Hkey,
        name: *const u16,
        reserved: *const u32,
        ty: *mut u32,
        data: *mut u8,
        len: *mut u32,
    ) -> i32;
    fn RegDeleteValueW(key: Hkey, name: *const u16) -> i32;
    fn RegDeleteTreeW(key: Hkey, sub: *const u16) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain([0]).collect()
}

struct Key(Hkey);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: closes a key we opened.
        unsafe { RegCloseKey(self.0) };
    }
}

fn open(sub: &str) -> crate::Result<Key> {
    let w = wide(sub);
    let mut k: Hkey = 0;
    // SAFETY: valid NUL-terminated subkey and out pointer.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            w.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_READ_WRITE,
            std::ptr::null(),
            &mut k,
            std::ptr::null_mut(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(crate::Error::internal(format!(
            "registry open failed ({rc})"
        )));
    }
    Ok(Key(k))
}

fn get(key: &Key, name: &str) -> crate::Result<Option<String>> {
    let n = wide(name);
    let mut len = 0u32;
    let mut ty = 0u32;
    // SAFETY: size query.
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            n.as_ptr(),
            std::ptr::null(),
            &mut ty,
            std::ptr::null_mut(),
            &mut len,
        )
    };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if rc != ERROR_SUCCESS || ty != REG_SZ || len > 64 * 1024 {
        return Err(crate::Error::internal("unexpected Run value type"));
    }
    let mut buf = vec![0u16; (len as usize).div_ceil(2)];
    // SAFETY: buffer is at least `len` bytes.
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            n.as_ptr(),
            std::ptr::null(),
            &mut ty,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(crate::Error::internal(format!(
            "registry read failed ({rc})"
        )));
    }
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(Some(String::from_utf16_lossy(&buf)))
}

fn put(key: &Key, name: &str, value: &str) -> crate::Result<()> {
    let (n, v) = (wide(name), wide(value));
    // SAFETY: `v` is NUL-terminated UTF-16; length is in bytes.
    let rc = unsafe {
        RegSetValueExW(
            key.0,
            n.as_ptr(),
            0,
            REG_SZ,
            v.as_ptr().cast(),
            (v.len() * 2) as u32,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(crate::Error::internal(format!(
            "registry write failed ({rc})"
        )));
    }
    Ok(())
}

fn del(key: &Key, name: &str) -> crate::Result<()> {
    let n = wide(name);
    // SAFETY: valid NUL-terminated name.
    let rc = unsafe { RegDeleteValueW(key.0, n.as_ptr()) };
    if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
        return Err(crate::Error::internal(format!(
            "registry delete failed ({rc})"
        )));
    }
    Ok(())
}

/// Read a value from an HKCU subkey (tests).
pub fn read_value(sub: &str, name: &str) -> Option<String> {
    open(sub).and_then(|k| get(&k, name)).ok().flatten()
}

/// Write a value into an HKCU subkey (tests).
pub fn write_value(sub: &str, name: &str, value: &str) -> crate::Result<()> {
    put(&open(sub)?, name, value)
}

/// Delete a whole HKCU subtree. Tests only; refuses anything but a
/// `Software\fail2commit-test-` key.
pub fn delete_test_tree(sub: &str) {
    if sub.starts_with(r"Software\fail2commit-test-") && !sub.contains("..") {
        let w = wide(sub);
        // SAFETY: valid NUL-terminated subkey under HKCU.
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, w.as_ptr()) };
    }
}

/// Quoted command line stored in the Run value.
fn command_for(exe: &std::path::Path) -> String {
    format!("\"{}\"", exe.with_file_name(TRAY_EXE).display())
}

pub struct StartupIntegration {
    run_key: String,
}

impl Default for StartupIntegration {
    fn default() -> Self {
        Self::with_run_key(RUN_KEY)
    }
}

impl StartupIntegration {
    /// Use another HKCU subkey (tests).
    pub fn with_run_key(run_key: &str) -> Self {
        StartupIntegration {
            run_key: run_key.to_string(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        open(&self.run_key)
            .and_then(|k| get(&k, VALUE_NAME))
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    /// Tray menu toggle. `exe` is the installed `fail2commit.exe` or the
    /// tray itself; the tray path is its sibling.
    pub fn set_enabled(&self, exe: &std::path::Path, on: bool) -> crate::Result<()> {
        let key = open(&self.run_key)?;
        if on {
            put(&key, VALUE_NAME, &command_for(exe))
        } else {
            del(&key, VALUE_NAME)
        }
    }
}

impl Integration for StartupIntegration {
    fn id(&self) -> &'static str {
        ID
    }

    fn install(&self, ctx: &SetupCtx) -> crate::Result<Vec<OwnedChange>> {
        // Without an installed tray there is nothing to start at sign-in.
        if !ctx.exe.with_file_name(TRAY_EXE).is_file() {
            return Ok(vec![]);
        }
        let key = open(&self.run_key)?;
        let previous = get(&key, VALUE_NAME)?;
        if !ctx.dry_run {
            put(&key, VALUE_NAME, &command_for(&ctx.exe))?;
        }
        Ok(vec![OwnedChange {
            integration: ID.into(),
            kind: "run-value".into(),
            path: None,
            detail: json!({ "run_key": self.run_key, "name": VALUE_NAME, "previous": previous }),
        }])
    }

    fn uninstall(&self, _ctx: &SetupCtx, owned: &[OwnedChange]) -> crate::Result<()> {
        for c in owned.iter().filter(|c| c.integration == ID) {
            // Only our own value name, in the key this instance manages.
            if c.detail["name"] != VALUE_NAME || c.detail["run_key"] != self.run_key.as_str() {
                continue;
            }
            let key = open(&self.run_key)?;
            match c.detail["previous"].as_str() {
                Some(prev) => put(&key, VALUE_NAME, prev)?,
                None => del(&key, VALUE_NAME)?,
            }
        }
        Ok(())
    }

    fn status(&self, _ctx: &SetupCtx) -> IntegrationStatus {
        let on = self.is_enabled();
        IntegrationStatus {
            id: ID.into(),
            installed: on,
            detail: if on {
                "tray starts at sign-in".into()
            } else {
                "tray does not start at sign-in".into()
            },
        }
    }
}
