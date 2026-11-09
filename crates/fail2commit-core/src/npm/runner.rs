//! Running the real npm (SPEC-004): `node <npm-cli.js>` with structured
//! arguments and a cleared environment. Never a shell, never `npm.cmd`, so
//! user-controlled arguments cannot be interpolated by cmd.exe.

use crate::paths::TrustedPaths;
use crate::{Error, Result};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Toolchain {
    pub node: PathBuf,
    pub npm_cli: PathBuf,
}

pub struct Captured {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Toolchain {
    /// `node` is found on PATH outside the fail2commit shim dir; the npm CLI
    /// entry is located next to it (or via the real `npm` launcher on Unix).
    pub fn resolve(paths: &TrustedPaths) -> Result<Toolchain> {
        let node = crate::toolpath::find_real("node", Some(&paths.bin_dir))?;
        let dir = node.parent().map(Path::to_path_buf).unwrap_or_default();
        let mut cands: Vec<PathBuf> = Vec::new();
        #[cfg(unix)]
        if let Ok(npm) = crate::toolpath::find_real("npm", Some(&paths.bin_dir)) {
            cands.push(npm); // already canonicalized; a symlink to npm-cli.js
        }
        for rel in [
            "node_modules/npm/bin/npm-cli.js",
            "../lib/node_modules/npm/bin/npm-cli.js",
            "../share/nodejs/npm/bin/npm-cli.js",
        ] {
            cands.push(dir.join(rel));
        }
        for c in cands {
            if c.file_name().is_some_and(|n| n == "npm-cli.js") && c.is_file() {
                // Node 22 fails with `lstat 'C:'` on a `\\?\` main script.
                return Ok(Toolchain {
                    node: crate::fsutil::plain_path(&node),
                    npm_cli: crate::fsutil::plain_path(&c.canonicalize().unwrap_or(c)),
                });
            }
        }
        Err(Error::invalid(
            "could not locate npm-cli.js next to node; install a standard Node.js with npm",
        ))
    }

    pub fn node_dir(&self) -> &Path {
        self.node.parent().unwrap_or(Path::new("."))
    }

    /// Root of the npm package (contains `bin/`, `node_modules/node-gyp`).
    pub fn npm_root(&self) -> Option<&Path> {
        self.npm_cli.parent().and_then(Path::parent)
    }

    pub fn npm_version(&self) -> String {
        self.npm_root()
            .and_then(|r| std::fs::read(r.join("package.json")).ok())
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| {
                v.get("version")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "unknown".into())
    }
}

/// The complete environment for a guarded npm child. Nothing is inherited, so
/// `npm_config_*`, `NODE_OPTIONS` and proxy variables cannot steer it.
pub fn clean_env(home: &Path, tc: &Toolchain) -> Vec<(OsString, OsString)> {
    let mut e: Vec<(OsString, OsString)> = Vec::new();
    let mut push = |k: &str, v: OsString| e.push((OsString::from(k), v));
    let tmp = home.join("tmp");
    push("HOME", home.into());
    push("TMPDIR", tmp.clone().into());
    push("TEMP", tmp.clone().into());
    push("TMP", tmp.into());
    #[cfg(windows)]
    {
        push("USERPROFILE", home.into());
        push("APPDATA", home.join("AppData").join("Roaming").into());
        push("LOCALAPPDATA", home.join("AppData").join("Local").into());
        for k in ["SystemRoot", "windir", "PATHEXT"] {
            if let Some(v) = std::env::var_os(k) {
                push(k, v);
            }
        }
        push("PATH", tc.node_dir().into());
    }
    #[cfg(not(windows))]
    {
        let mut path = tc.node_dir().as_os_str().to_owned();
        path.push(":/usr/bin:/bin");
        push("PATH", path);
        push("LANG", "C".into());
    }
    e
}

fn drain(mut r: impl Read + Send + 'static, cap: u64) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let room = (cap as usize).saturating_sub(out.len());
            out.extend_from_slice(&buf[..n.min(room)]);
        }
        out
    })
}

/// Run `cmd` with stdin closed, output capped, and a deadline.
pub fn run_bounded(cmd: &mut Command, timeout: Duration, cap: u64) -> Result<Captured> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::internal(format!("could not start {:?}: {e}", cmd.get_program())))?;
    let out = drain(child.stdout.take().expect("piped"), cap);
    let err = drain(child.stderr.take().expect("piped"), cap);
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::internal("npm timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Ok(Captured {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// Run npm with exactly `args` (already validated by the caller).
pub fn run_npm(
    tc: &Toolchain,
    args: &[OsString],
    cwd: &Path,
    env: &[(OsString, OsString)],
    timeout: Duration,
    cap: u64,
) -> Result<Captured> {
    let mut cmd = crate::winenv::command(&tc.node);
    cmd.arg(&tc.npm_cli)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)));
    run_bounded(&mut cmd, timeout, cap)
}

/// Short, redacted tail of npm output for error messages.
pub fn tail(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let s: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    let s = crate::redact::redact_url_credentials(s.trim());
    let n = s.chars().count();
    if n > 600 {
        s.chars().skip(n - 600).collect()
    } else {
        s
    }
}

/// Run a non-installing command with the real npm and inherited stdio.
pub fn passthrough(paths: &TrustedPaths, args: &[OsString]) -> Result<i32> {
    let tc = Toolchain::resolve(paths)?;
    let status = crate::winenv::command(&tc.node)
        .arg(&tc.npm_cli)
        .args(args)
        .status()
        .map_err(|e| Error::internal(format!("could not start npm: {e}")))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CI regression: Node 22 on Windows exits with `lstat 'C:'` when npm-cli.js
    /// is passed in the `\\?\` form that canonicalize returns.
    #[test]
    fn npm_toolchain_paths_are_plain() {
        let Ok(paths) = crate::paths::TrustedPaths::resolve() else {
            return;
        };
        if let Ok(tc) = Toolchain::resolve(&paths) {
            for p in [&tc.node, &tc.npm_cli] {
                assert!(!p.to_string_lossy().starts_with(r"\\?\"), "{}", p.display());
            }
        }
    }
}
