//! Process-environment helpers for setup and status (FR-004, FR-005).
//!
//! - After a PATH edit in the registry, tell running programs (Explorer in
//!   particular) so new terminals see it without signing out.
//! - Find what a bare command name resolves to, so `status` can say when a
//!   machine-wide tool shadows the per-user shim.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// `Command::new(program)` for every helper fail2commit starts (git, node,
/// python, reg). On Windows, when fail2commit itself has no console (started
/// by a GUI program, the tray, VS Code or a detached parent), a console child
/// would otherwise get a new, visible terminal window; it gets
/// `CREATE_NO_WINDOW` instead. With a console, children share it as usual, so
/// interactive prompts keep working.
pub fn command(program: impl AsRef<OsStr>) -> std::process::Command {
    #[allow(unused_mut)]
    let mut c = std::process::Command::new(program);
    #[cfg(windows)]
    if !has_console() {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn has_console() -> bool {
    // SAFETY: no arguments; returns NULL when the process has no console.
    !unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() }.is_null()
}

/// Broadcast `WM_SETTINGCHANGE("Environment")`. Best effort; no-op elsewhere.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn broadcast_environment_change() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };
    let name: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result = 0usize;
    // SAFETY: `name` is a NUL-terminated UTF-16 buffer that outlives the call;
    // `result` is a valid out pointer.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            name.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            2000,
            &mut result,
        );
    }
}

#[cfg(not(windows))]
pub fn broadcast_environment_change() {}

/// The file a shell would run for bare `name`, searching `path` in order:
/// on Windows each directory is tried with `name` plus every PATHEXT
/// extension (cmd.exe's rule); elsewhere the plain name.
pub fn resolve_command(name: &str, path: &OsStr, pathext: &str) -> Option<PathBuf> {
    let exts: Vec<String> = if cfg!(windows) {
        pathext
            .split(';')
            .filter(|e| !e.is_empty())
            .map(|e| e.to_ascii_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(path) {
        if !dir.is_absolute() {
            continue;
        }
        for ext in &exts {
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// The effective PATH a new process gets: the machine PATH then the user
/// PATH on Windows (that order is why a per-user shim can be shadowed);
/// elsewhere the current process PATH.
pub fn effective_path() -> std::ffi::OsString {
    #[cfg(windows)]
    {
        let read = |key: &str| -> String {
            command("reg")
                .args(["query", key, "/v", "Path"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| {
                    String::from_utf8_lossy(&o.stdout).lines().find_map(|l| {
                        let t = l.trim_start().strip_prefix("Path")?.trim_start();
                        t.split_once("    ").map(|(_, v)| v.trim().to_string())
                    })
                })
                .unwrap_or_default()
        };
        let machine = read(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
        let user = read(r"HKCU\Environment");
        expand_env(&format!("{machine};{user}")).into()
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("PATH").unwrap_or_default()
    }
}

/// Expand `%NAME%` references from the current environment (unknown names
/// are kept as written, like Windows does).
pub fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// True when `file` lives directly in one of `dirs` (case-insensitive on
/// Windows, trailing separators ignored).
pub fn is_in_any(file: &Path, dirs: &[&Path]) -> bool {
    let Some(parent) = file.parent() else {
        return false;
    };
    let norm = |p: &Path| {
        let s = p.to_string_lossy();
        let s = s.trim_end_matches(['\\', '/']).to_string();
        if cfg!(windows) {
            s.to_ascii_lowercase()
        } else {
            s
        }
    };
    dirs.iter().any(|d| norm(d) == norm(parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_directory_on_path_wins() {
        let machine = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let ext = if cfg!(windows) { ".cmd" } else { "" };
        let shim_ext = if cfg!(windows) { ".exe" } else { "" };
        std::fs::write(machine.path().join(format!("npm{ext}")), "real").unwrap();
        std::fs::write(user.path().join(format!("npm{shim_ext}")), "shim").unwrap();
        let path = std::env::join_paths([machine.path(), user.path()]).unwrap();
        let hit = resolve_command("npm", &path, ".COM;.EXE;.BAT;.CMD").unwrap();
        assert!(is_in_any(&hit, &[machine.path()]), "{}", hit.display());
        assert!(!is_in_any(&hit, &[user.path()]));
        let path = std::env::join_paths([user.path(), machine.path()]).unwrap();
        let hit = resolve_command("npm", &path, ".COM;.EXE;.BAT;.CMD").unwrap();
        assert!(is_in_any(&hit, &[user.path()]));
    }

    #[test]
    fn expands_known_variables_and_keeps_unknown_ones() {
        let home = std::env::var("PATH").unwrap_or_default();
        assert_eq!(expand_env("%PATH%"), home);
        assert_eq!(
            expand_env(r"%F2C_SURELY_UNSET_X%\bin;50%"),
            r"%F2C_SURELY_UNSET_X%\bin;50%"
        );
    }
}
