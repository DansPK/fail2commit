//! Machine-wide npm / pip shims on Windows (FR-004, FR-005; CR-013).
//!
//! Windows builds a new process's PATH as the machine PATH followed by the
//! user PATH, so the per-user shims that `fail2commit setup` installs never
//! win against a machine-wide Node.js or Python (for example
//! `C:\Program Files\nodejs\npm.cmd`). An administrator can therefore install
//! copies of the CLI named `npm.exe`, `pip.exe` and `pip3.exe` into
//! `<Program Files>\fail2commit\shims` and put that directory first on the
//! machine PATH.
//!
//! Security: the directory is under Program Files, so only administrators can
//! write to it (a user-writable directory early on the machine PATH would let
//! any user plant programs that administrators and services then run). The
//! Program Files location comes from the admin-controlled registry, not from
//! the process environment, and the undo record lives inside that directory.

use crate::{Error, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Copies of the CLI placed in the shim directory. `fail2commit.exe` lets an
/// administrator remove the shims even after the per-user install is gone.
pub const SHIMS: [&str; 4] = ["npm.exe", "pip.exe", "pip3.exe", "fail2commit.exe"];
const STATE: &str = "machine-path.json";

/// `<ProgramFilesDir>\fail2commit\shims`, from
/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ProgramFilesDir`.
pub fn shim_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let out = crate::winenv::command("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion",
                "/v",
                "ProgramFilesDir",
            ])
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let dir = text
            .lines()
            .find_map(|l| {
                let t = l.trim_start().strip_prefix("ProgramFilesDir")?.trim_start();
                t.split_once("    ").map(|(_, v)| v.trim().to_string())
            })
            .filter(|v| Path::new(v).is_absolute())
            .ok_or_else(|| Error::internal("cannot read ProgramFilesDir from the registry"))?;
        Ok(PathBuf::from(dir).join("fail2commit").join("shims"))
    }
    #[cfg(not(windows))]
    {
        Err(Error::invalid("machine-wide shims are Windows-only"))
    }
}

/// Install or refresh the shims from `exe` and put the directory first on the
/// machine PATH. Needs an elevated (administrator) process.
pub fn install(exe: &Path) -> Result<Value> {
    #[cfg(windows)]
    {
        use crate::git::{PathEditor, RegistryEditor};
        let dir = shim_dir()?;
        std::fs::create_dir_all(&dir).map_err(|e| elevation_hint(&dir, e))?;
        for name in SHIMS {
            let target = dir.join(name);
            if same_file(exe, &target) {
                continue; // running from the shim directory itself
            }
            let tmp = dir.join(format!("{name}.tmp"));
            std::fs::copy(exe, &tmp).map_err(|e| elevation_hint(&dir, e))?;
            if let Err(e) = std::fs::rename(&tmp, &target) {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::internal(format!(
                    "cannot replace {} (is it running?): {e}",
                    target.display()
                )));
            }
        }
        let detail = RegistryEditor::machine().add(&dir)?;
        let state = json!({ "version": 1, "dir": dir, "shims": SHIMS, "path": detail });
        let bytes =
            serde_json::to_vec_pretty(&state).map_err(|e| Error::internal(e.to_string()))?;
        std::fs::write(dir.join(STATE), bytes).map_err(|e| elevation_hint(&dir, e))?;
        Ok(json!({ "dir": dir, "shims": SHIMS }))
    }
    #[cfg(not(windows))]
    {
        let _ = exe;
        Err(Error::invalid("machine-wide shims are Windows-only"))
    }
}

/// Take our directory off the machine PATH and delete the shims. Needs an
/// elevated process. Files that are in use are reported, not forced.
pub fn uninstall() -> Result<Value> {
    #[cfg(windows)]
    {
        use crate::git::{PathEditor, RegistryEditor};
        let dir = shim_dir()?;
        let detail = std::fs::read(dir.join(STATE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .map(|v| v["path"].clone())
            .unwrap_or(Value::Null);
        RegistryEditor::machine().remove(&dir, &detail)?;
        let me = std::env::current_exe().ok();
        let mut left = Vec::new();
        for name in SHIMS.iter().copied().chain([STATE]) {
            let p = dir.join(name);
            if !p.exists() {
                continue;
            }
            if me.as_deref().is_some_and(|m| same_file(m, &p)) {
                left.push(p);
                continue;
            }
            if let Err(e) = std::fs::remove_file(&p) {
                if e.kind() == std::io::ErrorKind::PermissionDenied && !is_admin_dir_writable(&dir)
                {
                    return Err(elevation_hint(&dir, e));
                }
                left.push(p);
            }
        }
        if left.is_empty() {
            let _ = std::fs::remove_dir(&dir);
            if let Some(parent) = dir.parent() {
                let _ = std::fs::remove_dir(parent); // only when empty
            }
        }
        Ok(json!({ "dir": dir, "left_in_place": left }))
    }
    #[cfg(not(windows))]
    {
        Err(Error::invalid("machine-wide shims are Windows-only"))
    }
}

/// Whether the shims exist and the directory is on the machine PATH.
pub fn status() -> Value {
    #[cfg(windows)]
    {
        use crate::git::{PathEditor, RegistryEditor};
        let Ok(dir) = shim_dir() else {
            return json!({ "supported": true, "installed": false });
        };
        let files = SHIMS.iter().all(|n| dir.join(n).is_file());
        let on_path = RegistryEditor::machine().contains(&dir);
        json!({
            "supported": true,
            "dir": dir,
            "files": files,
            "on_machine_path": on_path,
            "installed": files && on_path,
        })
    }
    #[cfg(not(windows))]
    {
        json!({ "supported": false, "installed": false })
    }
}

#[cfg(windows)]
fn elevation_hint(dir: &Path, e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        Error::invalid(format!(
            "{} needs administrator rights: run this from an elevated terminal",
            dir.display()
        ))
    } else {
        Error::from(e)
    }
}

#[cfg(windows)]
fn is_admin_dir_writable(dir: &Path) -> bool {
    let probe = dir.join(".f2c-write-probe");
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

#[cfg(windows)]
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn shim_dir_is_under_program_files_from_the_registry() {
        let dir = super::shim_dir().unwrap();
        let pf = std::path::PathBuf::from(std::env::var_os("ProgramW6432").unwrap());
        assert_eq!(dir, pf.join("fail2commit").join("shims"));
    }

    #[cfg(windows)]
    #[test]
    fn shim_names_route_to_the_guarded_commands() {
        // The per-user and machine shims share these names; main.rs routes by
        // file stem, so a rename here must stay in step with shim_argv.
        assert_eq!(super::SHIMS[..3], ["npm.exe", "pip.exe", "pip3.exe"]);
    }

    #[cfg(windows)]
    #[test]
    fn status_reports_not_installed_on_a_clean_machine_or_reports_the_dir() {
        let s = super::status();
        assert_eq!(s["supported"], true);
        assert!(s["dir"].as_str().unwrap().ends_with(r"fail2commit\shims"));
    }
}
