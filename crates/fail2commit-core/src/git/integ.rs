//! `fail2commit setup` for Git: global hooks directory, `git` shim, PATH.
//!
//! Every change is recorded as an [`OwnedChange`] so uninstall restores the
//! recorded previous values and leaves third-party configuration alone.

use super::gitcmd;
use crate::integration::{Integration, IntegrationStatus, OwnedChange, SetupCtx};
use crate::paths::TrustedPaths;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const ID: &str = "git";
const KEY: &str = "core.hooksPath";
const BEGIN: &str = "# >>> fail2commit >>>";
const END: &str = "# <<< fail2commit <<<";
/// Redirects PATH edits to a profile-style file (tests, containers).
pub const PATH_TARGET_ENV: &str = "FAIL2COMMIT_PATH_TARGET";

pub fn hooks_dir(paths: &TrustedPaths) -> PathBuf {
    paths.state_dir.join("hooks")
}

pub fn shim_path(paths: &TrustedPaths) -> PathBuf {
    paths
        .bin_dir
        .join(if cfg!(windows) { "git.exe" } else { "git" })
}

/// Git accepts forward slashes everywhere, including Windows.
fn git_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// The user-scope PATH location. Injectable so tests never touch the
/// registry or the real shell profile.
pub trait PathEditor {
    /// Put `dir` first on the user's PATH; return what uninstall needs.
    fn add(&self, dir: &Path) -> crate::Result<Value>;
    fn remove(&self, dir: &Path, detail: &Value) -> crate::Result<()>;
    fn contains(&self, dir: &Path) -> bool;
}

pub fn default_path_editor() -> Box<dyn PathEditor> {
    if let Some(f) = std::env::var_os(PATH_TARGET_ENV).filter(|v| !v.is_empty()) {
        return Box::new(ProfileEditor { file: f.into() });
    }
    #[cfg(windows)]
    {
        Box::new(RegistryEditor::user())
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        Box::new(ProfileEditor {
            file: home.join(".profile"),
        })
    }
}

/// A marked block in a POSIX shell profile.
pub struct ProfileEditor {
    pub file: PathBuf,
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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

impl PathEditor for ProfileEditor {
    fn add(&self, dir: &Path) -> crate::Result<Value> {
        let existed = self.file.exists();
        let old = if existed {
            String::from_utf8_lossy(&fs::read(&self.file)?).into_owned()
        } else {
            String::new()
        };
        let mut text = strip_block(&old);
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!(
            "{BEGIN}\nexport PATH={}:\"$PATH\"\n{END}\n",
            sh_quote(&git_path(dir))
        ));
        if let Some(parent) = self.file.parent() {
            fs::create_dir_all(parent)?;
        }
        crate::fsutil::atomic_write(&self.file, text.as_bytes())?;
        Ok(json!({ "editor": "profile", "file": self.file, "existed": existed }))
    }

    fn remove(&self, _dir: &Path, detail: &Value) -> crate::Result<()> {
        let Ok(old) = fs::read(&self.file) else {
            return Ok(());
        };
        let text = strip_block(&String::from_utf8_lossy(&old));
        let existed = detail
            .get("existed")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if text.trim().is_empty() && !existed {
            fs::remove_file(&self.file)?;
        } else {
            crate::fsutil::atomic_write(&self.file, text.as_bytes())?;
        }
        Ok(())
    }

    fn contains(&self, dir: &Path) -> bool {
        fs::read_to_string(&self.file)
            .map(|t| t.contains(BEGIN) && t.contains(&sh_quote(&git_path(dir))))
            .unwrap_or(false)
    }
}

/// A `Path` value under an environment registry key, through `reg.exe` (no
/// extra dependencies): the user PATH, or the machine PATH (administrators).
#[cfg(windows)]
pub struct RegistryEditor {
    key: &'static str,
    label: &'static str,
}

#[cfg(windows)]
impl RegistryEditor {
    pub const fn user() -> Self {
        RegistryEditor {
            key: r"HKCU\Environment",
            label: "user",
        }
    }

    pub const fn machine() -> Self {
        RegistryEditor {
            key: r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            label: "machine",
        }
    }

    fn read(&self) -> crate::Result<Option<(String, String)>> {
        let out = crate::winenv::command("reg")
            .args(["query", self.key, "/v", "Path"])
            .output()?;
        if !out.status.success() {
            return Ok(None); // value does not exist yet
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix("Path") {
                let rest = rest.trim_start();
                if let Some((ty, val)) = rest.split_once("    ") {
                    return Ok(Some((ty.trim().to_string(), val.trim().to_string())));
                }
                // empty value
                return Ok(Some((rest.trim().to_string(), String::new())));
            }
        }
        Ok(None)
    }

    fn write(&self, ty: &str, value: &str) -> crate::Result<()> {
        let st = crate::winenv::command("reg")
            .args(["add", self.key, "/v", "Path", "/t", ty, "/d", value, "/f"])
            .output()?;
        if st.status.success() {
            crate::winenv::broadcast_environment_change();
            Ok(())
        } else {
            Err(crate::Error::internal(format!(
                "could not update the {} PATH",
                self.label
            )))
        }
    }

    fn delete(&self) -> crate::Result<()> {
        let _ = crate::winenv::command("reg")
            .args(["delete", self.key, "/v", "Path", "/f"])
            .output()?;
        crate::winenv::broadcast_environment_change();
        Ok(())
    }

    /// `path` with every entry equal to `dir` removed; other entries unchanged.
    fn without(path: &str, dir: &str) -> String {
        path.split(';')
            .filter(|e| !Self::same(e, dir))
            .collect::<Vec<_>>()
            .join(";")
    }

    fn same(a: &str, b: &str) -> bool {
        a.trim_end_matches(['\\', '/'])
            .eq_ignore_ascii_case(b.trim_end_matches(['\\', '/']))
    }
}

#[cfg(windows)]
impl PathEditor for RegistryEditor {
    fn add(&self, dir: &Path) -> crate::Result<Value> {
        let d = dir.to_string_lossy().to_string();
        let prev = self.read()?;
        let (ty, old) = prev
            .clone()
            .unwrap_or_else(|| ("REG_EXPAND_SZ".to_string(), String::new()));
        let rest: Vec<&str> = old
            .split(';')
            .filter(|e| !e.is_empty() && !Self::same(e, &d))
            .collect();
        let new = std::iter::once(d.as_str())
            .chain(rest)
            .collect::<Vec<_>>()
            .join(";");
        self.write(&ty, &new)?;
        // Re-running setup must not record our own entry as "previous", or
        // uninstall would restore it (found on a real PC after a reinstall).
        let previous = prev
            .map(|(t, v)| (t, RegistryEditor::without(&v, &d)))
            .filter(|(_, v)| !v.is_empty());
        Ok(json!({
            "editor": "registry",
            "previous": previous.map(|(t, v)| json!({ "type": t, "value": v })),
            "written": new,
            "type": ty,
        }))
    }

    fn remove(&self, dir: &Path, detail: &Value) -> crate::Result<()> {
        let d = dir.to_string_lossy().to_string();
        let Some((ty, cur)) = self.read()? else {
            return Ok(());
        };
        // The machine PATH is never restored wholesale or deleted: only our
        // entry is taken out, whatever else changed meanwhile.
        if self.label == "user"
            && detail.get("written").and_then(Value::as_str) == Some(cur.as_str())
        {
            return match detail.get("previous").filter(|p| !p.is_null()) {
                Some(p) => self.write(
                    p["type"].as_str().unwrap_or("REG_EXPAND_SZ"),
                    p["value"].as_str().unwrap_or(""),
                ),
                None => self.delete(),
            };
        }
        let kept = Self::without(&cur, &d);
        if kept == cur {
            return Ok(());
        }
        self.write(&ty, &kept)
    }

    fn contains(&self, dir: &Path) -> bool {
        let d = dir.to_string_lossy();
        self.read()
            .ok()
            .flatten()
            .map(|(_, v)| v.split(';').any(|e| Self::same(e, &d)))
            .unwrap_or(false)
    }
}

pub struct GitIntegration {
    editor: Box<dyn PathEditor>,
}

impl GitIntegration {
    pub fn new(editor: Box<dyn PathEditor>) -> Self {
        GitIntegration { editor }
    }

    fn git(&self, ctx: &SetupCtx) -> crate::Result<PathBuf> {
        crate::toolpath::find_real("git", Some(&ctx.paths.bin_dir))
    }
}

fn global_get(git: &Path) -> crate::Result<Option<String>> {
    let o = gitcmd::run(
        git,
        &std::env::current_dir()?,
        &["config", "--global", "--get", KEY],
    )?;
    Ok(o.ok().then(|| o.text()).filter(|s| !s.is_empty()))
}

fn global_set(git: &Path, value: Option<&str>) -> crate::Result<()> {
    let cwd = std::env::current_dir()?;
    let o = match value {
        Some(v) => gitcmd::run(git, &cwd, &["config", "--global", KEY, v])?,
        None => gitcmd::run(git, &cwd, &["config", "--global", "--unset", KEY])?,
    };
    if o.ok() || value.is_none() {
        Ok(())
    } else {
        Err(crate::Error::internal(
            "git config --global core.hooksPath failed",
        ))
    }
}

fn hook_script(exe: &Path) -> String {
    format!(
        r##"#!/bin/sh
# fail2commit managed pre-push hook; `fail2commit uninstall-integrations` removes it.
F2C={exe}
HERE=$(cd "$(dirname "$0")" && pwd -P) || exit 1
tmp=$(mktemp "${{TMPDIR:-/tmp}}/f2c-prepush.XXXXXX") || exit 1
trap 'rm -f "$tmp"' EXIT HUP INT TERM
cat > "$tmp" || exit 1
"$F2C" hook pre-push "$@" < "$tmp" || exit $?
# CR-010: the approval relay capability is for the hook above, never for the chain.
unset FAIL2COMMIT_APPROVAL_RELAY
# Chain what would have run without us: the repository's own hooksPath, else
# the user's previous global hooksPath, else the repository's hooks directory.
dir=$(git config --local --get core.hooksPath)
if [ -z "$dir" ] && [ -s "$HERE/prior-hookspath" ]; then dir=$(cat "$HERE/prior-hookspath"); fi
if [ -z "$dir" ]; then dir="$(git rev-parse --git-common-dir)/hooks"; fi
case "$dir" in "~/"*) dir="$HOME/${{dir#"~/"}}";; esac
if [ -d "$dir" ]; then dir=$(cd "$dir" && pwd -P); fi
if [ "$dir" != "$HERE" ] && [ -f "$dir/pre-push" ] && [ -x "$dir/pre-push" ]; then
  "$dir/pre-push" "$@" < "$tmp"
  exit $?
fi
exit 0
"##,
        exe = sh_quote(&git_path(exe))
    )
}

#[cfg(unix)]
fn make_executable(p: &Path) -> crate::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_: &Path) -> crate::Result<()> {
    Ok(())
}

impl Integration for GitIntegration {
    fn id(&self) -> &'static str {
        ID
    }

    fn install(&self, ctx: &SetupCtx) -> crate::Result<Vec<OwnedChange>> {
        let git = self.git(ctx)?;
        let dir = hooks_dir(&ctx.paths);
        let ours = git_path(&dir);
        let shim = shim_path(&ctx.paths);
        let prior_file = dir.join("prior-hookspath");
        let current = global_get(&git)?;
        // Re-running setup must not record our own value as "previous".
        let previous = if current.as_deref() == Some(ours.as_str()) {
            fs::read_to_string(&prior_file)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        } else {
            current
        };
        let path_detail = if ctx.dry_run {
            json!({ "editor": "dry-run" })
        } else {
            crate::fsutil::ensure_private_dir(&dir)?;
            fs::write(&prior_file, previous.as_deref().unwrap_or(""))?;
            let hook = dir.join("pre-push");
            fs::write(&hook, hook_script(&ctx.exe))?;
            make_executable(&hook)?;
            crate::fsutil::ensure_private_dir(&ctx.paths.bin_dir)?;
            install_shim(&ctx.exe, &shim)?;
            global_set(&git, Some(&ours))?;
            self.editor.add(&ctx.paths.bin_dir)?
        };
        Ok(vec![
            OwnedChange {
                integration: ID.into(),
                kind: "git-config".into(),
                path: None,
                detail: json!({ "key": KEY, "previous": previous, "value": ours }),
            },
            OwnedChange {
                integration: ID.into(),
                kind: "hook-file".into(),
                path: Some(dir),
                detail: Value::Null,
            },
            OwnedChange {
                integration: ID.into(),
                kind: "shim".into(),
                path: Some(shim),
                detail: Value::Null,
            },
            OwnedChange {
                integration: ID.into(),
                kind: "path-entry".into(),
                path: Some(ctx.paths.bin_dir.clone()),
                detail: path_detail,
            },
        ])
    }

    fn uninstall(&self, ctx: &SetupCtx, owned: &[OwnedChange]) -> crate::Result<()> {
        let git = self.git(ctx)?;
        for c in owned {
            match c.kind.as_str() {
                "git-config" => {
                    let ours = c.detail["value"].as_str().unwrap_or_default();
                    // Only roll back while the value is still ours.
                    if global_get(&git)?.as_deref() == Some(ours) {
                        global_set(&git, c.detail["previous"].as_str())?;
                    }
                }
                "hook-file" => {
                    if let Some(dir) = &c.path {
                        for f in ["pre-push", "prior-hookspath"] {
                            let _ = fs::remove_file(dir.join(f));
                        }
                        let _ = fs::remove_dir(dir); // only if empty
                    }
                }
                "shim" => {
                    if let Some(p) = &c.path {
                        let _ = fs::remove_file(p);
                    }
                }
                "path-entry" => {
                    if let Some(dir) = &c.path {
                        self.editor.remove(dir, &c.detail)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn status(&self, ctx: &SetupCtx) -> IntegrationStatus {
        let ours = git_path(&hooks_dir(&ctx.paths));
        let configured = self
            .git(ctx)
            .and_then(|g| global_get(&g))
            .map(|v| v.as_deref() == Some(ours.as_str()))
            .unwrap_or(false);
        let shim = shim_path(&ctx.paths).is_file();
        let on_path = self.editor.contains(&ctx.paths.bin_dir);
        IntegrationStatus {
            id: ID.into(),
            installed: configured && shim,
            detail: format!(
                "hooksPath {}, shim {}, PATH {}",
                if configured { "set" } else { "not set" },
                if shim { "present" } else { "missing" },
                if on_path { "set" } else { "not set" },
            ),
        }
    }
}

/// Copy `exe` to `shim` (replace atomically; a running copy cannot be
/// replaced on Windows, which is reported rather than ignored).
fn install_shim(exe: &Path, shim: &Path) -> crate::Result<()> {
    if exe == shim {
        return Err(crate::Error::invalid(
            "run setup from the fail2commit executable, not the git shim",
        ));
    }
    let tmp = shim.with_extension("tmp");
    fs::copy(exe, &tmp)?;
    make_executable(&tmp)?;
    fs::rename(&tmp, shim).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        crate::Error::internal(format!("cannot install git shim: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_editor_round_trip_keeps_user_lines() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("p");
        fs::write(&f, "export A=1\n").unwrap();
        let e = ProfileEditor { file: f.clone() };
        let dir = Path::new("/x/it's dir/bin");
        let detail = e.add(dir).unwrap();
        e.add(dir).unwrap(); // idempotent
        let t = fs::read_to_string(&f).unwrap();
        assert_eq!(t.matches(BEGIN).count(), 1);
        assert!(t.starts_with("export A=1\n") && e.contains(dir));
        e.remove(dir, &detail).unwrap();
        assert_eq!(fs::read_to_string(&f).unwrap(), "export A=1\n");
        assert!(!e.contains(dir));
    }

    #[test]
    fn profile_editor_removes_file_it_created() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("new");
        let e = ProfileEditor { file: f.clone() };
        let detail = e.add(Path::new("/b")).unwrap();
        e.remove(Path::new("/b"), &detail).unwrap();
        assert!(!f.exists());
    }

    /// A second setup run sees our entry already on the user PATH; "previous"
    /// must not keep it, or uninstall restores it (seen on a real PC).
    #[cfg(windows)]
    #[test]
    fn registry_previous_excludes_our_own_entry() {
        let ours = r"C:\Users\u\AppData\Local\fail2commit\bin";
        let on_path = r"c:\users\u\appdata\local\fail2commit\bin\;C:\Tools;%USERPROFILE%\x";
        assert_eq!(
            RegistryEditor::without(on_path, ours),
            r"C:\Tools;%USERPROFILE%\x"
        );
        assert_eq!(RegistryEditor::without(r"C:\Tools", ours), r"C:\Tools");
        assert_eq!(RegistryEditor::without(ours, ours), "");
    }

    #[test]
    fn script_quotes_exe_with_spaces_and_quotes() {
        let s = hook_script(Path::new("C:\\My Dir\\it's\\f2c.exe"));
        assert!(s.contains("F2C='C:/My Dir/it'\\''s/f2c.exe'"));
    }
}
