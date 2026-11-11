//! `fail2commit setup` shell integration (FR-004, FR-005; CR-015).
//!
//! PATH shims lose whenever something puts its own directory first: an
//! activated virtualenv (`venv/bin`, `venv\Scripts`), nvm or fnm. A shell
//! function always wins over PATH, so setup adds `pip`, `pip3` and `npm`
//! functions that call the guard, in a marked block of the user's shell
//! startup files: `~/.bashrc` and an existing `~/.zshrc`; on Windows the
//! PowerShell profiles and an existing Git Bash `~/.bashrc`. Inside a venv the
//! guard still installs into that venv: it picks the Python next to the first
//! real `pip` on PATH. Uninstall removes exactly the block (and files that
//! setup created and that are otherwise empty).
//!
//! When `FAIL2COMMIT_PATH_TARGET` redirects PATH edits (tests, containers),
//! the block goes to `<that file>.shellrc` instead, so tests never touch real
//! profiles.

use crate::git::PATH_TARGET_ENV;
use crate::integration::{Integration, IntegrationStatus, OwnedChange, SetupCtx};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub const ID: &str = "shell";
const BEGIN: &str = "# >>> fail2commit shell >>>";
const END: &str = "# <<< fail2commit shell <<<";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    Posix,
    // PowerShell profiles are only targeted on Windows.
    #[cfg_attr(not(windows), allow(dead_code))]
    PowerShell,
}

pub fn integration() -> Option<Box<dyn Integration>> {
    Some(Box::new(ShellIntegration))
}

pub struct ShellIntegration;

/// Startup files to edit: (file, flavor, create when missing).
fn targets() -> Vec<(PathBuf, Flavor, bool)> {
    if let Some(f) = std::env::var_os(PATH_TARGET_ENV).filter(|v| !v.is_empty()) {
        let mut p = f;
        p.push(".shellrc");
        return vec![(PathBuf::from(p), Flavor::Posix, true)];
    }
    let mut out = Vec::new();
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .filter(|h| h.is_absolute());
    if let Some(home) = &home {
        // bash on Linux always; Git Bash on Windows only if already in use.
        out.push((home.join(".bashrc"), Flavor::Posix, !cfg!(windows)));
        out.push((home.join(".zshrc"), Flavor::Posix, false));
    }
    #[cfg(windows)]
    if let Some(docs) = documents_dir() {
        // Windows PowerShell 5.1 and PowerShell 7 read different profiles.
        for sub in ["WindowsPowerShell", "PowerShell"] {
            out.push((docs.join(sub).join("profile.ps1"), Flavor::PowerShell, true));
        }
    }
    out
}

/// The user's Documents folder, which may be redirected (OneDrive).
#[cfg(windows)]
fn documents_dir() -> Option<PathBuf> {
    let out = crate::winenv::command("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            "/v",
            "Personal",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let raw = text.lines().find_map(|l| {
        let t = l.trim_start().strip_prefix("Personal")?.trim_start();
        t.split_once("    ").map(|(_, v)| v.trim().to_string())
    });
    let dir = raw
        .map(|v| PathBuf::from(crate::winenv::expand_env(&v)))
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join("Documents")))?;
    Some(dir)
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// (shell function, fail2commit subcommand). `git` (FR-016) keeps pushes
/// checked when another `git` comes earlier on PATH.
const FUNCTIONS: [(&str, &str); 4] = [
    ("pip", "pip"),
    ("pip3", "pip"),
    ("npm", "npm"),
    ("git", "git"),
];

fn block(flavor: Flavor, exe: &Path) -> String {
    let exe = exe.to_string_lossy();
    let mut b = String::new();
    b.push_str(BEGIN);
    b.push('\n');
    b.push_str("# Shell functions win over PATH, so an activated virtualenv or a Node\n");
    b.push_str("# version manager cannot bypass the guard. `fail2commit uninstall-integrations` removes this.\n");
    match flavor {
        Flavor::Posix => {
            let e = sh_quote(&exe.replace('\\', "/"));
            // CR-021: if fail2commit was removed without uninstall-integrations,
            // fall back to the real command instead of "not found".
            for (f, sub) in FUNCTIONS {
                b.push_str(&format!(
                    "{f}() {{ if [ -x {e} ]; then {e} {sub} \"$@\"; else command {f} \"$@\"; fi; }}\n"
                ));
            }
        }
        Flavor::PowerShell => {
            let e = ps_quote(&exe);
            for (f, sub) in FUNCTIONS {
                b.push_str(&format!(
                    "function {f} {{ if (Test-Path -LiteralPath {e}) {{ & {e} {sub} @args }} else {{ & (Get-Command {f} -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source @args }} }}\n"
                ));
            }
        }
    }
    b.push_str(END);
    b.push('\n');
    b
}

fn strip_block(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in text.split_inclusive('\n') {
        let t = line.trim_end();
        if t == BEGIN {
            inside = true;
        } else if inside && t == END {
            inside = false;
        } else if !inside {
            out.push_str(line);
        }
    }
    out
}

fn has_block(file: &Path) -> bool {
    fs::read(file)
        .map(|b| {
            String::from_utf8_lossy(&b)
                .lines()
                .any(|l| l.trim_end() == BEGIN)
        })
        .unwrap_or(false)
}

impl Integration for ShellIntegration {
    fn id(&self) -> &'static str {
        ID
    }

    fn install(&self, ctx: &SetupCtx) -> crate::Result<Vec<OwnedChange>> {
        let mut changes = Vec::new();
        for (file, flavor, create) in targets() {
            let existed = file.exists();
            if !existed && !create {
                continue;
            }
            let dir_existed = file.parent().is_none_or(Path::exists);
            if !ctx.dry_run {
                let old = if existed {
                    String::from_utf8_lossy(&fs::read(&file)?).into_owned()
                } else {
                    String::new()
                };
                let mut text = strip_block(&old);
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&block(flavor, &ctx.exe));
                if let Some(parent) = file.parent() {
                    fs::create_dir_all(parent)?;
                }
                crate::fsutil::write_user_file(&file, text.as_bytes())?;
            }
            changes.push(OwnedChange {
                integration: ID.into(),
                kind: "shell-block".into(),
                path: Some(file),
                detail: json!({ "existed": existed, "dir_existed": dir_existed }),
            });
        }
        Ok(changes)
    }

    fn uninstall(&self, _ctx: &SetupCtx, owned: &[OwnedChange]) -> crate::Result<()> {
        for c in owned {
            let Some(file) = &c.path else { continue };
            let Ok(old) = fs::read(file) else { continue };
            let text = strip_block(&String::from_utf8_lossy(&old));
            let existed = c.detail["existed"].as_bool().unwrap_or(true);
            if text.trim().is_empty() && !existed {
                fs::remove_file(file)?;
                // A folder setup created (Documents\PowerShell) goes too, if
                // nothing else was put in it; records without the flag keep it.
                if c.detail["dir_existed"] == false {
                    if let Some(dir) = file.parent() {
                        let _ = fs::remove_dir(dir);
                    }
                }
            } else {
                crate::fsutil::write_user_file(file, text.as_bytes())?;
            }
        }
        Ok(())
    }

    fn status(&self, _ctx: &SetupCtx) -> IntegrationStatus {
        let present: Vec<PathBuf> = targets()
            .into_iter()
            .map(|(f, _, _)| f)
            .filter(|f| has_block(f))
            .collect();
        IntegrationStatus {
            id: ID.into(),
            installed: !present.is_empty(),
            detail: if present.is_empty() {
                "no shell startup file has the fail2commit pip/npm functions".into()
            } else {
                format!(
                    "pip/npm functions in {}",
                    present
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_round_trip_keeps_user_lines_and_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let rc = d.path().join("rc");
        fs::write(&rc, "alias ll='ls -l'\nexport A=1").unwrap();
        let exe = Path::new("/opt/it's dir/fail2commit");
        let mut text = strip_block(&fs::read_to_string(&rc).unwrap());
        text.push('\n');
        text.push_str(&block(Flavor::Posix, exe));
        // A second install replaces, never duplicates.
        let mut again = strip_block(&text);
        again.push_str(&block(Flavor::Posix, exe));
        assert_eq!(again.matches(BEGIN).count(), 1);
        assert!(again.contains(
            "pip() { if [ -x '/opt/it'\\''s dir/fail2commit' ]; then '/opt/it'\\''s dir/fail2commit' pip \"$@\"; else command pip \"$@\"; fi; }"
        ));
        assert_eq!(
            strip_block(&again).trim_end(),
            "alias ll='ls -l'\nexport A=1"
        );
    }

    #[test]
    fn uninstall_removes_a_folder_setup_created_only_when_empty() {
        let d = tempfile::tempdir().unwrap();
        let ctx = SetupCtx {
            paths: crate::paths::TrustedPaths::under(d.path()),
            exe: "fail2commit".into(),
            dry_run: false,
        };
        let change = |file: &Path, dir_existed: Option<bool>| {
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, block(Flavor::PowerShell, &ctx.exe)).unwrap();
            let mut detail = json!({ "existed": false });
            if let Some(v) = dir_existed {
                detail["dir_existed"] = v.into();
            }
            OwnedChange {
                integration: ID.into(),
                kind: "shell-block".into(),
                path: Some(file.into()),
                detail,
            }
        };
        let created = d.path().join("PowerShell").join("profile.ps1");
        let shared = d.path().join("Shared").join("profile.ps1");
        let legacy = d.path().join("Legacy").join("profile.ps1");
        let owned = [
            change(&created, Some(false)),
            change(&shared, Some(false)),
            change(&legacy, None),
        ];
        fs::write(d.path().join("Shared").join("user.txt"), "keep").unwrap();
        ShellIntegration.uninstall(&ctx, &owned).unwrap();
        assert!(
            !created.parent().unwrap().exists(),
            "empty folder setup created is removed"
        );
        assert!(!shared.exists() && d.path().join("Shared").join("user.txt").exists());
        assert!(
            !legacy.exists() && legacy.parent().unwrap().exists(),
            "old records keep the folder"
        );
    }

    #[test]
    fn powershell_block_quotes_the_exe() {
        let b = block(
            Flavor::PowerShell,
            Path::new(r"C:\Users\O'Neil\fail2commit.exe"),
        );
        assert!(b.contains(
            r"function npm { if (Test-Path -LiteralPath 'C:\Users\O''Neil\fail2commit.exe') { & 'C:\Users\O''Neil\fail2commit.exe' npm @args }"
        ));
        assert!(b.contains("function pip3 { if "));
        assert!(b.contains("git @args } else { & (Get-Command git -CommandType Application"));
    }

    /// FR-016 / CR-021: the functions route through fail2commit while it
    /// exists and fall back to the real command, silently, once it is gone.
    #[cfg(unix)]
    #[test]
    fn posix_git_function_routes_through_the_guard_and_falls_back() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("f2c");
        std::fs::write(&exe, "#!/bin/sh\necho \"guard $*\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rc = d.path().join("rc");
        std::fs::write(&rc, block(Flavor::Posix, &exe)).unwrap();
        let run = || {
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!(". '{}'; git --version", rc.display()))
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        assert_eq!(run(), "guard git --version\n");
        std::fs::remove_file(&exe).unwrap();
        assert!(run().starts_with("git version"), "real git after removal");
    }
}
