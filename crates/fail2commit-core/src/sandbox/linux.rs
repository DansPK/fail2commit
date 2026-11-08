//! Bubblewrap backend (T-007a; FR-007, SPEC-007). Design, threat notes and
//! evidence: docs/sandbox-linux.md.
//!
//! One job is:
//! `[systemd-run --user --scope -p TasksMax= -p MemoryMax= --] bwrap <policy>
//!  -- bash -c WRAPPER f2c-sandbox <nproc|-> <as_kb|-> <program> <args...>`
//!
//! The wrapper runs inside the new user namespace, so RLIMIT_NPROC counts only
//! sandbox processes (set on the outer bwrap it would count every host process
//! of the user). It then writes a launch marker to fd 4, closes it and execs
//! the program. No marker means setup failed and nothing was launched.

// pre_exec fd placement and kill(2) need libc; each block has a SAFETY note.
#![allow(unsafe_code)]

use crate::isolation::{JobLimits, JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend};
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// Trusted bwrap locations. Never PATH, never the repository.
const BWRAP_PATHS: [&str; 2] = ["/usr/bin/bwrap", "/usr/local/bin/bwrap"];
const BASH_PATHS: [&str; 2] = ["/usr/bin/bash", "/bin/bash"];
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";

/// Read-only system trees toolchains need (symlinks on merged-/usr systems).
const SYSTEM_DIRS: [&str; 7] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32",
];
/// The only parts of /etc the sandbox sees.
const ETC_ALLOW: [&str; 11] = [
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/alternatives",
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/ca-certificates",
];
/// A job may never bind these or any directory containing them.
const DENY_ANCESTORS: [&str; 9] = [
    "/home", "/root", "/tmp", "/var/tmp", "/run", "/etc", "/mnt", "/media", "/srv",
];
/// A job may never bind anything inside these (sockets, credentials, kernel).
const DENY_INSIDE: [&str; 6] = ["/run", "/var/run", "/proc", "/sys", "/dev", "/etc"];

const STATUS_FD: i32 = 3;
const MARKER_FD: i32 = 4;

/// `$1` nproc, `$2` address-space KiB (`-` = not set), then the program.
const WRAPPER: &str = r#"if [ "$1" != - ]; then ulimit -S -H -u "$1" || exit 125; fi
if [ "$2" != - ]; then ulimit -S -H -v "$2" || exit 125; fi
shift 2
printf L >&4 || exit 125
exec 4>&-
exec "$@""#;

/// Runs inside a real sandbox during probe; `$1` is the host home.
const PROBE_SCRIPT: &str = r#"for n in user net pid ipc uts mnt; do printf 'ns %s %s\n' "$n" "$(readlink /proc/self/ns/$n)"; done
printf 'nproc %s\n' "$(ulimit -u)"
printf 'as %s\n' "$(ulimit -v)"
for p in /run /var/run "$1"; do if [ -e "$p" ]; then printf 'visible %s\n' "$p"; fi; done
for e in /*; do printf 'root %s\n' "${e#/}"; done
while IFS= read -r -d '' kv; do printf 'env %s\n' "${kv%%=*}"; done < /proc/self/environ
true"#;

/// Reads the scope's own cgroup limits from inside it.
const SCOPE_SCRIPT: &str = r#"while read -r l; do case $l in 0::*) p=${l#0::};; esac; done < /proc/self/cgroup
read -r a < "/sys/fs/cgroup$p/pids.max"; read -r b < "/sys/fs/cgroup$p/memory.max"
printf '%s %s\n' "$a" "$b""#;

const PROBE_NPROC: u32 = 32;
const PROBE_MEMORY: u64 = 256 * 1024 * 1024;
const OPTIONAL_CONTROLS: [&str; 2] = ["cgroup_v2_limits", "process_limit"];

pub struct Bubblewrap {
    bwrap_paths: Vec<PathBuf>,
    cgroup: bool,
    probed: OnceLock<Probed>,
}

struct Probed {
    report: ProbeReport,
    /// Present only when `report.available`.
    tools: Option<Tools>,
}

struct Tools {
    bwrap: PathBuf,
    bash: PathBuf,
    scope: Option<Scope>,
}

/// Delegated cgroup v2 limits through a transient systemd user scope.
struct Scope {
    systemd_run: PathBuf,
    runtime_dir: OsString,
}

impl Default for Bubblewrap {
    fn default() -> Self {
        Bubblewrap {
            bwrap_paths: BWRAP_PATHS.iter().map(PathBuf::from).collect(),
            cgroup: true,
            probed: OnceLock::new(),
        }
    }
}

impl Bubblewrap {
    /// Use only `path` as bwrap. It must still pass the trusted-path checks;
    /// tests use a missing path to simulate an unavailable backend.
    pub fn with_bwrap(path: impl Into<PathBuf>) -> Self {
        Bubblewrap {
            bwrap_paths: vec![path.into()],
            ..Default::default()
        }
    }

    /// Never use cgroup limits, even when delegation works (rlimits only).
    pub fn without_cgroup(mut self) -> Self {
        self.cgroup = false;
        self
    }

    fn probed(&self) -> &Probed {
        self.probed.get_or_init(|| self.probe_now())
    }

    fn probe_now(&self) -> Probed {
        let mut controls: Vec<(String, bool)> = Vec::new();
        let bwrap = self.bwrap_paths.iter().find_map(|p| trusted_exe(p).ok());
        controls.push(("bwrap_trusted_path".into(), bwrap.is_some()));
        let bash = BASH_PATHS
            .iter()
            .find_map(|p| trusted_exe(Path::new(p)).ok());
        controls.push(("wrapper_shell".into(), bash.is_some()));
        let (Some(bwrap), Some(bash)) = (bwrap, bash) else {
            return unavailable(
                controls,
                "no root-owned, non-writable bwrap and bash in /usr/bin or /usr/local/bin".into(),
            );
        };
        let scope = if self.cgroup {
            probe_scope(&bash)
        } else {
            None
        };
        let tools = Tools { bwrap, bash, scope };
        let mut unexpected = String::new();
        match self_test(&tools, &mut unexpected) {
            Ok(list) => controls.extend(list),
            Err(e) => {
                controls.push(("sandbox_self_test".into(), false));
                return unavailable(controls, e.message);
            }
        }
        let available = controls
            .iter()
            .filter(|(n, _)| !OPTIONAL_CONTROLS.contains(&n.as_str()))
            .all(|(_, ok)| *ok);
        let failed: Vec<&str> = controls
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(n, _)| n.as_str())
            .collect();
        let detail = format!(
            "bubblewrap {}; limits via {}{}",
            tools.bwrap.display(),
            if tools.scope.is_some() {
                "cgroup v2 systemd user scope"
            } else {
                "rlimits"
            },
            if failed.is_empty() {
                String::new()
            } else {
                format!(
                    "; not verified: {} (seen inside: {unexpected})",
                    failed.join(", ")
                )
            }
        );
        Probed {
            report: ProbeReport {
                backend: "bubblewrap",
                available,
                detail,
                controls,
            },
            tools: available.then_some(tools),
        }
    }
}

impl SandboxBackend for Bubblewrap {
    fn probe(&self) -> ProbeReport {
        self.probed().report.clone()
    }

    fn run(&self, job: &JobSpec) -> crate::Result<JobOutcome> {
        let p = self.probed();
        match &p.tools {
            Some(tools) => execute(tools, job, &[]),
            None => Err(crate::Error::isolation_unavailable(format!(
                "bubblewrap: {}",
                p.report.detail
            ))),
        }
    }
}

fn unavailable(controls: Vec<(String, bool)>, detail: String) -> Probed {
    Probed {
        report: ProbeReport {
            backend: "bubblewrap",
            available: false,
            detail,
            controls,
        },
        tools: None,
    }
}

/// Canonical path of a root-owned executable in a root-owned directory that
/// neither group nor others can write.
fn trusted_exe(p: &Path) -> crate::Result<PathBuf> {
    let c = p.canonicalize()?;
    let md = fs::metadata(&c)?;
    let dir = fs::metadata(c.parent().unwrap_or(Path::new("/")))?;
    let ok = md.is_file()
        && md.uid() == 0
        && md.mode() & 0o022 == 0
        && md.mode() & 0o111 != 0
        && dir.uid() == 0
        && dir.mode() & 0o022 == 0;
    if ok {
        Ok(c)
    } else {
        Err(crate::Error::isolation_unavailable(format!(
            "{} is not a root-owned, non-writable executable",
            c.display()
        )))
    }
}

fn home_dir() -> Option<PathBuf> {
    let h = PathBuf::from(std::env::var_os("HOME")?);
    h.is_absolute().then(|| h.canonicalize().unwrap_or(h))
}

/// Canonical form of a job path that may be bound into the sandbox.
fn bindable(p: &Path, home: Option<&Path>) -> crate::Result<PathBuf> {
    if !p.is_absolute() {
        return Err(crate::Error::invalid(format!(
            "sandbox path {} is not absolute",
            p.display()
        )));
    }
    let c = p
        .canonicalize()
        .map_err(|e| crate::Error::invalid(format!("sandbox path {}: {e}", p.display())))?;
    let exposes = DENY_ANCESTORS
        .iter()
        .map(Path::new)
        .chain(home)
        .find(|d| d.starts_with(&c));
    let inside = DENY_INSIDE.iter().find(|d| c.starts_with(d));
    if let Some(d) = exposes.map(Path::to_path_buf).or(inside.map(PathBuf::from)) {
        return Err(crate::Error::rejected(format!(
            "refusing to expose {} to the sandbox (covers {})",
            c.display(),
            d.display()
        )));
    }
    Ok(c)
}

fn no_nul(s: &std::ffi::OsStr) -> bool {
    !s.as_bytes().contains(&0)
}

/// Validate the job and build the bwrap argument list. Errors here happen
/// before anything is launched.
fn policy_args(tools: &Tools, job: &JobSpec) -> crate::Result<Vec<OsString>> {
    let home = home_dir();
    let work = bindable(&job.work_dir, home.as_deref())?;
    let ro = job
        .read_only
        .iter()
        .map(|p| bindable(p, home.as_deref()))
        .collect::<crate::Result<Vec<_>>>()?;
    let cwd = job
        .cwd
        .canonicalize()
        .map_err(|e| crate::Error::invalid(format!("sandbox cwd: {e}")))?;
    if !cwd.starts_with(&work) {
        return Err(crate::Error::invalid("sandbox cwd must be inside work_dir"));
    }
    if !job.program.is_absolute() {
        return Err(crate::Error::invalid("sandbox program must be absolute"));
    }
    let program = job
        .program
        .canonicalize()
        .map_err(|e| crate::Error::invalid(format!("sandbox program: {e}")))?;
    let system: Vec<PathBuf> = SYSTEM_DIRS
        .iter()
        .filter_map(|d| Path::new(d).canonicalize().ok())
        .collect();
    if !ro.iter().chain(&system).any(|r| program.starts_with(r)) {
        return Err(crate::Error::invalid(
            "sandbox program must be a system tool or inside a read-only input",
        ));
    }
    let env_ok = job
        .env
        .iter()
        .all(|(k, v)| !k.is_empty() && !k.as_bytes().contains(&b'=') && no_nul(k) && no_nul(v));
    if !env_ok || !job.args.iter().all(|a| no_nul(a)) {
        return Err(crate::Error::invalid("sandbox env or args are malformed"));
    }

    let mut a: Vec<OsString> = Vec::new();
    let mut push = |items: &[&std::ffi::OsStr]| a.extend(items.iter().map(|s| s.to_os_string()));
    push(&[
        "--unshare-all".as_ref(),
        "--die-with-parent".as_ref(),
        "--new-session".as_ref(),
        "--cap-drop".as_ref(),
        "ALL".as_ref(),
        "--clearenv".as_ref(),
    ]);
    for (k, v) in &job.env {
        push(&["--setenv".as_ref(), k, v]);
    }
    for d in SYSTEM_DIRS {
        match fs::symlink_metadata(d) {
            Ok(m) if m.file_type().is_symlink() => {
                let target = fs::read_link(d)?;
                push(&["--symlink".as_ref(), target.as_os_str(), d.as_ref()]);
            }
            Ok(m) if m.is_dir() => push(&["--ro-bind".as_ref(), d.as_ref(), d.as_ref()]),
            _ => {}
        }
    }
    for e in ETC_ALLOW {
        push(&["--ro-bind-try".as_ref(), e.as_ref(), e.as_ref()]);
    }
    push(&[
        "--proc".as_ref(),
        "/proc".as_ref(),
        "--dev".as_ref(),
        "/dev".as_ref(),
        "--tmpfs".as_ref(),
        "/tmp".as_ref(),
    ]);
    for r in &ro {
        push(&["--ro-bind".as_ref(), r.as_os_str(), r.as_os_str()]);
    }
    push(&["--bind".as_ref(), work.as_os_str(), work.as_os_str()]);
    push(&["--chdir".as_ref(), cwd.as_os_str()]);
    push(&["--json-status-fd".as_ref(), "3".as_ref()]);
    let nproc = job
        .limits
        .max_processes
        .map_or("-".to_string(), |n| n.to_string());
    // With a cgroup scope, memory.max bounds real usage; RLIMIT_AS would also
    // break runtimes that reserve large virtual ranges.
    let as_kib = match (&tools.scope, job.limits.memory_bytes) {
        (None, Some(b)) => (b / 1024).max(1).to_string(),
        _ => "-".to_string(),
    };
    push(&[
        "--".as_ref(),
        tools.bash.as_os_str(),
        "-c".as_ref(),
        WRAPPER.as_ref(),
        "f2c-sandbox".as_ref(),
        nproc.as_ref(),
        as_kib.as_ref(),
        job.program.as_os_str(),
    ]);
    for arg in &job.args {
        push(&[arg]);
    }
    Ok(a)
}

fn scope_command(scope: &Scope, limits: &JobLimits) -> Command {
    let mut c = Command::new(&scope.systemd_run);
    // systemd >= 254 expands ${VAR} in the command line by default, which
    // would rewrite job arguments; older versions reject the flag, so the
    // scope probe fails and limits fall back to rlimits.
    c.args([
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "--expand-environment=no",
    ]);
    if let Some(n) = limits.max_processes {
        c.arg("-p").arg(format!("TasksMax={n}"));
    }
    if let Some(m) = limits.memory_bytes {
        c.arg("-p").arg(format!("MemoryMax={m}"));
        c.arg("-p").arg("MemorySwapMax=0");
    }
    c.arg("--");
    c.env_clear().env("XDG_RUNTIME_DIR", &scope.runtime_dir);
    c
}

/// Launch one job and wait for every sandbox process to stop.
/// `host_env` is extra environment for the bwrap process itself (probe
/// canary); `--clearenv` must keep it out of the sandbox.
fn execute(tools: &Tools, job: &JobSpec, host_env: &[(&str, &str)]) -> crate::Result<JobOutcome> {
    let args = policy_args(tools, job)?;
    let (status_r, status_w) = std::io::pipe()?;
    let (mark_r, mark_w) = std::io::pipe()?;
    let mut cmd = match &tools.scope {
        Some(s) => {
            let mut c = scope_command(s, &job.limits);
            c.arg(&tools.bwrap);
            c
        }
        None => {
            let mut c = Command::new(&tools.bwrap);
            c.env_clear();
            c
        }
    };
    cmd.args(&args)
        .envs(host_env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (sw, mw) = (status_w.as_raw_fd(), mark_w.as_raw_fd());
    // SAFETY: runs in the forked child before exec and only calls
    // async-signal-safe fcntl/dup2 on fds this process owns.
    unsafe {
        cmd.pre_exec(move || place_fds(sw, mw));
    }
    let mut child = cmd.spawn().map_err(|e| {
        crate::Error::isolation_unavailable(format!("cannot start bubblewrap: {e}"))
    })?;
    drop((status_w, mark_w, cmd));

    let budget = Arc::new(AtomicU64::new(job.limits.max_output_bytes));
    let out_t = drain(child.stdout.take(), budget.clone());
    let err_t = drain(child.stderr.take(), budget);
    let init_pid = Arc::new(AtomicI32::new(0));
    let status_t = {
        let pid = init_pid.clone();
        thread::spawn(move || read_status(status_r, &pid))
    };
    let mark_t = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = mark_r.take(16).read_to_end(&mut b);
        b
    });

    let deadline = Instant::now() + job.limits.timeout;
    let mut timed_out = false;
    let waited = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Ok(st),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                timed_out = true;
                break kill_tree(&mut child, &init_pid);
            }
            Err(e) => {
                let _ = kill_tree(&mut child, &init_pid);
                break Err(e);
            }
        }
    };
    let (stdout, t1) = out_t.join().unwrap_or_default();
    let (stderr, t2) = err_t.join().unwrap_or_default();
    let _ = status_t.join();
    let launched = mark_t.join().unwrap_or_default() == b"L";
    let status = waited?;
    if !launched {
        return Err(crate::Error::isolation_unavailable(format!(
            "sandbox setup failed before launch: {}",
            first_line(&stderr)
        )));
    }
    let status = if timed_out {
        JobStatus::TimedOut
    } else {
        status.code().map_or(JobStatus::Killed, JobStatus::Exited)
    };
    Ok(JobOutcome {
        status,
        stdout,
        stderr,
        truncated: t1 || t2,
        exported: Vec::new(),
    })
}

/// Place the status and marker pipes at fds 3 and 4 without CLOEXEC.
fn place_fds(status: i32, marker: i32) -> std::io::Result<()> {
    let cvt = |r: i32| {
        if r < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(r)
        }
    };
    // Move both above 4 first so one dup2 cannot clobber the other.
    // SAFETY: plain fd syscalls on fds owned by this process.
    let s = cvt(unsafe { libc::fcntl(status, libc::F_DUPFD_CLOEXEC, 10) })?;
    let m = cvt(unsafe { libc::fcntl(marker, libc::F_DUPFD_CLOEXEC, 10) })?;
    cvt(unsafe { libc::dup2(s, STATUS_FD) })?;
    cvt(unsafe { libc::dup2(m, MARKER_FD) })?;
    Ok(())
}

/// Kill the sandbox's PID-namespace init (the kernel then kills every
/// process in the namespace), then reap bwrap, which exits only after its
/// init is gone.
fn kill_tree(child: &mut Child, init_pid: &AtomicI32) -> std::io::Result<ExitStatus> {
    let pid = init_pid.load(Ordering::SeqCst);
    if pid > 0 && child.try_wait()?.is_none() {
        // SAFETY: kill(2) has no memory-safety preconditions. `pid` is a
        // child of the still-running bwrap, so it is not yet reaped and its
        // pid cannot have been reused.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    } else {
        // Setup not reported yet: --die-with-parent takes the sandbox down.
        let _ = child.kill();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(st);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait();
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Record bwrap's `child-pid` (the sandbox init) from `--json-status-fd`.
fn read_status(r: std::io::PipeReader, pid: &AtomicI32) {
    for line in BufReader::new(r.take(64 * 1024)).lines() {
        let Ok(line) = line else { break };
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(p) = v.get("child-pid").and_then(|p| p.as_i64()) {
                pid.store(i32::try_from(p).unwrap_or(0), Ordering::SeqCst);
            }
        }
    }
}

/// Read a pipe to EOF, keeping at most the shared `budget` bytes; the rest
/// is drained and dropped so the writer never blocks.
fn drain(
    r: Option<impl Read + Send + 'static>,
    budget: Arc<AtomicU64>,
) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let (mut buf, mut truncated) = (Vec::new(), false);
        let Some(mut r) = r else {
            return (buf, truncated);
        };
        let mut chunk = [0u8; 8192];
        loop {
            let n = match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            // Claim up to n bytes of the shared budget.
            let mut left = budget.load(Ordering::SeqCst);
            let take = loop {
                let take = left.min(n as u64);
                match budget.compare_exchange(left, left - take, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => break take,
                    Err(now) => left = now,
                }
            };
            let keep = usize::try_from(take).unwrap_or(0);
            buf.extend_from_slice(&chunk[..keep]);
            truncated |= keep < n;
        }
        (buf, truncated)
    })
}

/// First stderr line, printable ASCII only and bounded, for error messages.
fn first_line(b: &[u8]) -> String {
    let s: String = String::from_utf8_lossy(b)
        .lines()
        .next()
        .unwrap_or("no diagnostic")
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect();
    s
}

/// Run `cmd` with a deadline and return its bounded stdout.
fn output_with_timeout(mut cmd: Command, timeout: Duration) -> Option<String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    child
        .stdout
        .take()?
        .take(4096)
        .read_to_string(&mut out)
        .ok()?;
    Some(out)
}

/// Use a transient systemd user scope when it really applies pids.max and
/// memory.max (cgroup v2 delegation).
fn probe_scope(bash: &Path) -> Option<Scope> {
    let systemd_run = trusted_exe(Path::new(SYSTEMD_RUN)).ok()?;
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| Path::new(d).is_absolute())?;
    let scope = Scope {
        systemd_run,
        runtime_dir,
    };
    let limits = JobLimits {
        timeout: Duration::from_secs(10),
        memory_bytes: Some(64 * 1024 * 1024),
        max_processes: Some(7),
        max_output_bytes: 4096,
    };
    let mut c = scope_command(&scope, &limits);
    c.arg(bash).args(["-c", SCOPE_SCRIPT]);
    let out = output_with_timeout(c, limits.timeout)?;
    (out.trim() == "7 67108864").then_some(scope)
}

/// Run a real sandbox and verify each mandatory control from inside it.
/// `diagnostic` receives any unexpected env keys, root entries or visible
/// host paths, for the probe detail.
fn self_test(tools: &Tools, diagnostic: &mut String) -> crate::Result<Vec<(String, bool)>> {
    let dir = tempfile::tempdir()?;
    let work = dir.path().canonicalize()?;
    let home = home_dir().unwrap_or_else(|| PathBuf::from("/nonexistent-home"));
    let job = JobSpec {
        program: tools.bash.clone(),
        args: vec![
            "-c".into(),
            PROBE_SCRIPT.into(),
            "f2c-probe".into(),
            home.into(),
        ],
        cwd: work.clone(),
        env: vec![("F2C_PROBE".into(), "1".into())],
        read_only: vec![],
        work_dir: work.clone(),
        exports: vec![],
        export_to: None,
        limits: JobLimits {
            timeout: Duration::from_secs(30),
            memory_bytes: Some(PROBE_MEMORY),
            max_processes: Some(PROBE_NPROC),
            max_output_bytes: 64 * 1024,
        },
    };
    let out = execute(tools, &job, &[("F2C_PROBE_CANARY", "host")])?;
    if out.status != JobStatus::Exited(0) {
        return Err(crate::Error::isolation_unavailable(format!(
            "sandbox self-test exited with {:?}: {}",
            out.status,
            first_line(&out.stderr)
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |key: &str| -> Vec<String> {
        text.lines()
            .filter_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
            .map(str::to_string)
            .collect()
    };
    let mut controls = Vec::new();
    for ns in field("ns") {
        let (name, inside) = ns.split_once(' ').unwrap_or((&ns, ""));
        let host = fs::read_link(format!("/proc/self/ns/{name}"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let label = if name == "mnt" { "mount" } else { name };
        controls.push((
            format!("{label}_namespace"),
            !inside.is_empty() && !host.is_empty() && inside != host,
        ));
    }
    if controls.len() != 6 {
        return Err(crate::Error::isolation_unavailable(
            "sandbox self-test output is incomplete",
        ));
    }
    let allowed_env = ["F2C_PROBE", "PWD", "SHLVL", "_", "OLDPWD"];
    let mut unexpected: Vec<String> = field("env")
        .into_iter()
        .filter(|k| !allowed_env.contains(&k.as_str()))
        .map(|k| format!("env {k}"))
        .collect();
    controls.push(("clean_env".into(), unexpected.is_empty()));
    let top = work
        .components()
        .nth(1)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_default();
    let mounts_before = unexpected.len();
    unexpected.extend(
        field("root")
            .into_iter()
            .filter(|e| {
                e != &top
                    && !["etc", "proc", "dev", "tmp"].contains(&e.as_str())
                    && !SYSTEM_DIRS.iter().any(|d| d.trim_start_matches('/') == e)
            })
            .map(|e| format!("/{e}")),
    );
    unexpected.extend(field("visible"));
    controls.push(("mount_policy".into(), unexpected.len() == mounts_before));
    *diagnostic = unexpected.join(", ");
    // Real root bypasses RLIMIT_NPROC, so it bounds nothing without a cgroup.
    let is_root = fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(true);
    let nproc_ok = field("nproc") == [PROBE_NPROC.to_string()];
    controls.push((
        "process_limit".into(),
        tools.scope.is_some() || (nproc_ok && !is_root),
    ));
    let as_ok = field("as") == [(PROBE_MEMORY / 1024).to_string()];
    controls.push(("memory_limit".into(), tools.scope.is_some() || as_ok));
    controls.push(("cgroup_v2_limits".into(), tools.scope.is_some()));
    Ok(controls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindable_refuses_home_root_and_sockets() {
        let home = Path::new("/home/someone");
        for bad in ["/", "/home", "/run", "/proc/self", "/dev", "/etc", "/tmp"] {
            assert!(bindable(Path::new(bad), Some(home)).is_err(), "{bad}");
        }
        assert!(bindable(Path::new("relative"), None).is_err());
        let d = tempfile::tempdir().unwrap();
        let ok = bindable(d.path(), Some(home)).unwrap();
        assert!(bindable(&ok, Some(&ok)).is_err(), "the host home itself");
        assert!(
            bindable(&ok, Some(&ok.join("child"))).is_err(),
            "an ancestor of home"
        );
    }

    #[test]
    fn untrusted_executables_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("bwrap");
        fs::write(&f, b"#!/bin/sh\n").unwrap();
        assert!(trusted_exe(&f).is_err(), "user- or tmp-owned file");
        assert!(trusted_exe(Path::new("/nonexistent/bwrap")).is_err());
        let b = Bubblewrap::with_bwrap(&f);
        let p = b.probe();
        assert!(!p.available);
        assert!(p.controls.contains(&("bwrap_trusted_path".into(), false)));
    }

    #[test]
    fn output_budget_is_shared_and_drains() {
        let budget = Arc::new(AtomicU64::new(10));
        let a = drain(Some(&b"0123456789abcdef"[..]), budget.clone())
            .join()
            .unwrap();
        let b = drain(Some(&b"xyz"[..]), budget).join().unwrap();
        assert_eq!(a, (b"0123456789".to_vec(), true));
        assert_eq!(b, (Vec::new(), true));
    }
}
