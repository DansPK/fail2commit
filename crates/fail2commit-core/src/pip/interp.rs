//! Interpreter binding, scrubbed pip invocation and untrusted-config checks.

use super::guard::Guard;
use crate::{Error, Finding, FindingAction, FindingKind, ResultCode};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cooperative cancellation shared with the resolver and apply loops.
pub type Cancel = Arc<AtomicBool>;

/// Facts the plan is bound to. All come from the interpreter itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interpreter {
    /// The path the user selected (spelling kept when it resolves to the same file).
    pub executable: String,
    /// Canonical identity of the environment this interpreter installs into:
    /// implementation, `major.minor` and the real `sys.prefix`, canonicalized
    /// and case-folded on Windows. Journals and the journal gate are keyed by it,
    /// so respelling the interpreter path cannot walk around them (RP-006).
    pub identity: String,
    pub prefix: String,
    pub base_prefix: String,
    pub in_venv: bool,
    pub implementation: String,
    pub python_version: String,
    pub platform: String,
    pub machine: String,
    pub pip_version: String,
    /// Supported tags in priority order (pip's vendored `packaging.tags`).
    pub tags: Vec<String>,
}

/// Prelude of every interpreter fail2commit starts: `python -I -S -c <BOOT...>`.
///
/// `-S` skips `site`, so no `*.pth` import line, `sitecustomize` or
/// `usercustomize` from the target environment (W2-001, CR-001) ever runs in
/// the guard. Without `site` CPython does not notice a venv on older versions,
/// so the prelude does what `site.venv()` does: it reads `<exe dir>/../pyvenv.cfg`
/// (never `<exe dir>/pyvenv.cfg`: that is the wheel `scripts` directory, RP-004)
/// and points `sys.prefix` at it. It then *computes* the environment's
/// `purelib`/`platlib`/`site.getsitepackages()` as `_T`. `_T` is data, not an
/// import location: nothing in it is put on `sys.path` by this prelude.
pub(crate) const BOOT: &str = concat!(
    "import os, sys\n",
    "sys.dont_write_bytecode = True\n",
    "_x = os.path.dirname(sys.executable)\n",
    "_base, _syssite = sys.base_prefix, False\n",
    "_c = os.path.join(os.path.dirname(_x), 'pyvenv.cfg')\n",
    "if os.path.isfile(_c):\n",
    "    sys.prefix = sys.exec_prefix = os.path.dirname(_c)\n",
    "    with open(_c, encoding='utf-8') as _f:\n",
    "        for _l in _f:\n",
    "            _k, _, _v = _l.partition('=')\n",
    "            if _k.strip().lower() == 'include-system-site-packages':\n",
    "                _syssite = _v.strip().lower() == 'true'\n",
    "import sysconfig, site\n",
    "_p = sysconfig.get_paths()\n",
    "_dirs = [_p.get('platlib'), _p.get('purelib')] + list(site.getsitepackages())\n",
    "if _syssite:\n",
    "    _dirs += list(site.getsitepackages([_base]))\n",
    "_T = []\n",
    "for _d in _dirs:\n",
    "    if _d and _d not in _T and os.path.isdir(_d):\n",
    "        _T.append(_d)\n",
);

/// The guard's pip comes from a private snapshot (`guard::Guard`), never from
/// the target environment (RP-003). Only the snapshot and the stdlib are
/// importable. The target's site directories are added to `sys.path` solely so
/// pip can *read installed-distribution metadata*; the finder below refuses to
/// import any module from them, so a wheel's `keyring.py`, `brotli.py` or
/// `pip/` can never run inside the guard.
fn snapshot_tail(snapshot: &Path) -> String {
    let lit = serde_json::to_string(&snapshot.to_string_lossy()).expect("string serializes");
    let body = concat!(
        "sys.path.insert(0, _S)
",
        "sys.path.extend([_d for _d in _T if _d not in sys.path])
",
        "import importlib.machinery as _im
",
        "_N = frozenset(os.path.normcase(os.path.abspath(_d)) for _d in _T)
",
        "class _NoTarget(_im.PathFinder):
",
        "    @classmethod
",
        "    def find_spec(cls, name, path=None, target=None):
",
        "        if path is None:
",
        "            path = [_d for _d in sys.path if os.path.normcase(os.path.abspath(_d)) not in _N]
",
        "        return _im.PathFinder.find_spec(name, path, target)
",
        "sys.meta_path[sys.meta_path.index(_im.PathFinder)] = _NoTarget
",
        "import pip
",
        "if os.path.normcase(os.path.dirname(os.path.dirname(os.path.abspath(pip.__file__)))) != os.path.normcase(os.path.abspath(_S)):
",
        "    raise SystemExit('pip was not loaded from the fail2commit snapshot')
",
    );
    format!(
        "_S = {lit}
{body}"
    )
}

/// Runs pip's `__main__`; pip's arguments follow `-c` as `sys.argv`.
const PIP_MAIN: &str = "import runpy\n\
runpy.run_module('pip', run_name='__main__', alter_sys=True)\n";

/// A command running `body` after the site-free prelude. With `snapshot`,
/// pip is importable from that directory (and only from there).
pub(crate) fn python_c(
    python: impl AsRef<std::ffi::OsStr>,
    snapshot: Option<&Path>,
    body: &str,
) -> Command {
    let tail = snapshot.map(snapshot_tail).unwrap_or_default();
    let mut cmd = crate::winenv::command(python);
    cmd.args(["-I", "-S", "-c"])
        .arg(format!("{BOOT}{tail}{body}"));
    cmd
}

/// `python -I -S` running the snapshot's pip with the given leading flags.
pub(crate) fn pip_command(
    python: impl AsRef<std::ffi::OsStr>,
    snapshot: &Path,
    flags: &[&str],
) -> Command {
    let mut cmd = python_c(python, Some(snapshot), PIP_MAIN);
    cmd.args(flags);
    cmd
}

/// Stage 1: who is this interpreter? Needs nothing from the environment.
const PROBE_BASE: &str = "import json, platform\n\
print(json.dumps({'executable': sys.executable, 'real_prefix': os.path.realpath(sys.prefix), \
'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'in_venv': sys.prefix != sys.base_prefix, \
'implementation': sys.implementation.name, 'python_version': platform.python_version(), \
'platform': sys.platform, 'machine': platform.machine(), 'version': list(sys.version_info[:2]), \
'site_dirs': _T}))";

/// Stage 2, from the snapshot's pip.
const PROBE_PIP: &str = "import json\n\
from pip import __version__ as pv\n\
from pip._vendor.packaging import tags\n\
print(json.dumps({'pip_version': pv, 'tags': [str(t) for t in tags.sys_tags()]}))";

/// Prints `[[name, version], ...]` for every distribution whose `dist-info`
/// is on disk in the environment's site directories. Reads metadata files only.
const LIST_INSTALLED: &str = "import json\n\
from importlib import metadata\n\
print(json.dumps([[d.metadata['Name'] or '', d.version or ''] for d in metadata.distributions(path=list(_T))]))";

#[derive(Deserialize)]
struct Base {
    executable: String,
    real_prefix: String,
    prefix: String,
    base_prefix: String,
    in_venv: bool,
    implementation: String,
    python_version: String,
    platform: String,
    machine: String,
    version: [u32; 2],
    site_dirs: Vec<String>,
}

#[derive(Deserialize)]
struct PipFacts {
    pip_version: String,
    tags: Vec<String>,
}

/// Canonical identity of an environment (RP-006).
fn identity_of(b: &Base) -> String {
    let real = Path::new(&b.real_prefix)
        .canonicalize()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| b.real_prefix.clone());
    let real = real.strip_prefix(r"\\?\").unwrap_or(&real).to_string();
    let real = if cfg!(windows) {
        real.replace('\\', "/").to_lowercase()
    } else {
        real
    };
    format!(
        "{}-{}.{}:{}",
        b.implementation, b.version[0], b.version[1], real
    )
}

impl Interpreter {
    /// Ask `python` who it is, take (or verify) the guard's private pip
    /// snapshot, then ask that pip for the tags. `-I` keeps the workspace and
    /// `PYTHON*` out; nothing from the target environment is imported.
    pub fn probe(
        paths: &crate::paths::TrustedPaths,
        python: &Path,
        limits: &RunLimits,
        cancel: &Cancel,
    ) -> crate::Result<(Interpreter, Guard)> {
        let not_a_target = |why: &str| {
            Error::invalid(format!(
                "cannot use {} as a pip target (pip must be importable): {why}",
                python.display()
            ))
        };
        let mut cmd = python_c(python, None, PROBE_BASE);
        let out = run(&mut cmd, limits, cancel)?;
        if out.status != Some(0) {
            return Err(not_a_target(&tail(&out.stderr)));
        }
        let b: Base = serde_json::from_slice(&out.stdout)
            .map_err(|e| Error::invalid(format!("interpreter probe output invalid: {e}")))?;
        let identity = identity_of(&b);
        let mut executable = b.executable.clone();
        if Path::new(&executable) != python {
            // Keep the path the user selected when it resolves to the same file.
            if let (Ok(a), Ok(c)) = (Path::new(&executable).canonicalize(), python.canonicalize()) {
                if a == c {
                    executable = python.to_string_lossy().into_owned();
                }
            }
        }
        let guard = Guard::ensure(
            paths,
            Path::new(&executable),
            &identity,
            &b.site_dirs,
            limits,
            cancel,
        )
        .map_err(|e| {
            if e.code == ResultCode::InvalidInput {
                not_a_target(&e.message)
            } else {
                e
            }
        })?;
        let mut cmd = guard.python_c(PROBE_PIP)?;
        let out = run(&mut cmd, limits, cancel)?;
        if out.status != Some(0) {
            return Err(not_a_target(&tail(&out.stderr)));
        }
        let f: PipFacts = serde_json::from_slice(&out.stdout)
            .map_err(|e| Error::invalid(format!("interpreter probe output invalid: {e}")))?;
        if f.tags.is_empty() {
            return Err(Error::invalid("interpreter reported no compatible tags"));
        }
        let interp = Interpreter {
            executable,
            identity,
            prefix: b.prefix,
            base_prefix: b.base_prefix,
            in_venv: b.in_venv,
            implementation: b.implementation,
            python_version: b.python_version,
            platform: b.platform,
            machine: b.machine,
            pip_version: f.pip_version,
            tags: f.tags,
        };
        Ok((interp, guard))
    }

    pub fn python(&self) -> PathBuf {
        PathBuf::from(&self.executable)
    }

    /// Installed `(normalized name, version)` pairs, read from the `dist-info`
    /// directories on disk. No package of the environment is imported.
    pub fn installed(
        &self,
        limits: &RunLimits,
        cancel: &Cancel,
    ) -> crate::Result<Vec<(String, String)>> {
        let mut cmd = python_c(&self.executable, None, LIST_INSTALLED);
        let out = run(&mut cmd, limits, cancel)?;
        if out.status != Some(0) {
            return Err(Error::internal(format!(
                "listing installed packages failed: {}",
                tail(&out.stderr)
            )));
        }
        let raw: Vec<(String, String)> = serde_json::from_slice(&out.stdout)
            .map_err(|e| Error::internal(format!("installed list invalid: {e}")))?;
        Ok(raw.into_iter().map(|(n, v)| (normalize(&n), v)).collect())
    }
}

/// PEP 503 normalization.
pub fn normalize(name: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            dash = true;
        } else {
            if dash && !out.is_empty() {
                out.push('-');
            }
            dash = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

#[derive(Clone, Debug)]
pub struct RunLimits {
    pub timeout: Duration,
    pub max_output: usize,
}

impl RunLimits {
    pub fn from_settings(l: &crate::settings::Limits) -> Self {
        RunLimits {
            timeout: Duration::from_secs(l.job_timeout_secs.max(1)),
            max_output: l.job_max_output_bytes.min(64 * 1024 * 1024) as usize,
        }
    }
}

pub struct RunOutput {
    /// `None` when the process was killed by a signal.
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run `cmd` with a scrubbed environment, bounded output and a deadline.
/// Cancellation kills the child and returns `Rejected`.
pub fn run(cmd: &mut Command, limits: &RunLimits, cancel: &Cancel) -> crate::Result<RunOutput> {
    scrub_env(cmd);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::invalid(format!("cannot start {:?}: {e}", cmd.get_program())))?;
    let cap = limits.max_output;
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut r).take(cap as u64).read_to_end(&mut buf);
            // keep draining so the child never blocks on a full pipe
            let _ = std::io::copy(&mut r, &mut std::io::sink());
            buf
        })
    };
    let out_t = drain(Box::new(child.stdout.take().expect("piped")));
    let err_t = drain(Box::new(child.stderr.take().expect("piped")));
    let deadline = Instant::now() + limits.timeout;
    let stop = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Ok(st.code()),
            Ok(None) => {}
            Err(e) => break Err(Error::internal(format!("waiting for child: {e}"))),
        }
        if cancel.load(Ordering::SeqCst) {
            break Err(Error::rejected("canceled"));
        }
        if Instant::now() > deadline {
            break Err(Error::incomplete("command timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if stop.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = out_t.join().unwrap_or_default();
    let stderr = err_t.join().unwrap_or_default();
    Ok(RunOutput {
        status: stop?,
        stdout,
        stderr,
    })
}

/// Only what python/pip need; no `PIP_*`, `PYTHON*`, proxy or credentials.
pub(crate) fn scrub_env(cmd: &mut Command) {
    cmd.env_clear();
    for k in [
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "SYSTEMDRIVE",
        "PROGRAMDATA",
        // platform.machine() on Windows reads these; without them it can fall back
        // to a slow WMI query that sometimes yields "", changing the plan digest.
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_ARCHITEW6432",
        "ALLUSERSPROFILE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
    ] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    cmd.env("PYTHONIOENCODING", "utf-8")
        .env("PIP_NO_INPUT", "1");
}

/// Last lines of command output, safe to show.
pub fn tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().rev().take(6).collect();
    let joined: Vec<&str> = lines.into_iter().rev().collect();
    crate::redact::redact_url_credentials(&joined.join(" | "))
}

// ----------------------------------------------------------------------
// Untrusted pip configuration

const INDEX_KEYS: [&str; 4] = ["index-url", "extra-index-url", "find-links", "trusted-host"];

fn untrusted(source: &str, evidence: String) -> Error {
    Error::new(
        ResultCode::InvalidInput,
        format!("untrusted pip index configuration: {evidence}"),
    )
    .with_findings(vec![Finding::new(
        FindingKind::UnsupportedInput,
        FindingAction::Deny,
        source,
        evidence,
    )])
}

/// `PIP_INDEX_URL`-style variables. A value equal to `pinned` is harmless.
pub fn check_env(vars: impl Iterator<Item = (String, String)>, pinned: &str) -> crate::Result<()> {
    for (k, v) in vars {
        let key = k.to_ascii_uppercase();
        let Some(rest) = key.strip_prefix("PIP_") else {
            continue;
        };
        let norm = rest.to_ascii_lowercase().replace('_', "-");
        if (INDEX_KEYS.contains(&norm.as_str()) || norm == "no-index")
            && !same_index(&norm, &v, pinned)
        {
            return Err(untrusted("pip.env", format!("{k} is set")));
        }
    }
    Ok(())
}

fn same_index(key: &str, value: &str, pinned: &str) -> bool {
    key == "index-url" && value.trim().trim_end_matches('/') == pinned.trim_end_matches('/')
}

/// Scan the pip config files pip itself would read for index directives.
pub fn check_config_files(files: &[PathBuf], pinned: &str) -> crate::Result<()> {
    for f in files {
        let Ok(bytes) = crate::fsutil::read_bounded(f, 64 * 1024) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with(['#', ';', '[']) {
                continue;
            }
            let Some((k, v)) = line.split_once(['=', ':']) else {
                continue;
            };
            let key = k.trim().to_ascii_lowercase().replace('_', "-");
            if (INDEX_KEYS.contains(&key.as_str()) || key == "no-index")
                && !same_index(&key, v, pinned)
            {
                return Err(untrusted("pip.config", format!("{key} in {}", f.display())));
            }
        }
    }
    Ok(())
}

/// Config locations pip reads (user, global, site), plus `PIP_CONFIG_FILE`.
pub fn config_file_candidates(prefix: &str) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = vec![PathBuf::from(prefix)];
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    if cfg!(windows) {
        for k in ["APPDATA", "USERPROFILE", "PROGRAMDATA"] {
            if let Some(d) = env(k) {
                dirs.push(d.join("pip"));
            }
        }
    } else {
        if let Some(h) = env("HOME") {
            dirs.push(h.join(".config").join("pip"));
            dirs.push(h.join(".pip"));
        }
        if let Some(x) = env("XDG_CONFIG_HOME") {
            dirs.push(x.join("pip"));
        }
        dirs.push(PathBuf::from("/etc"));
        dirs.push(PathBuf::from("/etc/xdg/pip"));
    }
    let mut files: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|d| [d.join("pip.conf"), d.join("pip.ini")])
        .collect();
    if let Some(f) = env("PIP_CONFIG_FILE") {
        files.push(f);
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(normalize("Foo_Bar.baz--qux"), "foo-bar-baz-qux");
    }

    #[test]
    fn env_and_config_directives_rejected() {
        let pinned = "https://pypi.org/simple";
        let v = |k: &str, val: &str| vec![(k.to_string(), val.to_string())].into_iter();
        for k in [
            "PIP_INDEX_URL",
            "pip_extra_index_url",
            "PIP_FIND_LINKS",
            "PIP_TRUSTED_HOST",
        ] {
            let e = check_env(v(k, "http://evil.test"), pinned).unwrap_err();
            assert_eq!(e.findings[0].kind, FindingKind::UnsupportedInput);
        }
        assert!(check_env(v("PIP_INDEX_URL", "https://pypi.org/simple/"), pinned).is_ok());
        assert!(check_env(v("PIP_REQUIRE_VIRTUALENV", "1"), pinned).is_ok());

        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("pip.ini");
        std::fs::write(&f, "[global]\nextra-index-url = http://evil.test\n").unwrap();
        assert!(check_config_files(std::slice::from_ref(&f), pinned).is_err());
        std::fs::write(
            &f,
            "[global]\ntimeout = 5\nindex-url = https://pypi.org/simple\n",
        )
        .unwrap();
        assert!(check_config_files(&[f], pinned).is_ok());
    }
}
