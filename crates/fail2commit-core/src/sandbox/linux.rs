//! Bubblewrap backend (T-007a; FR-007, SPEC-007; 0.1.4: SPEC-013).
//!
//! Design, threat notes and evidence: docs/sandbox-linux.md. 0.1.4 adds FR-023 (public-internet
//! only, through an egress proxy), FR-024 (bait credentials and their watchers), FR-026 (activity
//! report) and the containment rows of FR-020 that bwrap alone cannot cover (seccomp deny-list,
//! disk meter).
//!
//! One job is:
//! `[systemd-run --user --scope -p TasksMax= -p MemoryMax= --] bwrap <policy>
//!  -- bash -c WRAPPER f2c-sandbox <limits> <relay> <setpriv> <filter> <program> <args...>`
//!
//! The wrapper runs inside the new user namespace, so RLIMIT_NPROC counts only sandbox processes
//! (set on the outer bwrap it would count every host process of the user). It then writes a launch
//! marker to fd 4, closes it and execs the program. No marker means setup failed and nothing was
//! launched.
//!
//! 0.1.4 keeps `--unshare-all` in both network modes: the sandbox has no route to anything, so
//! `internet` is the egress proxy reached through the relay bound at `/f2c`, and `none` has no
//! socket at all.

// pre_exec fd placement and kill(2) need libc; each block has a SAFETY note.
#![allow(unsafe_code)]

mod baitwatch;
mod proxy;
mod relay;
mod seccomp;

pub(crate) use proxy::Watch;

/// Entry point for the `f2c-sandbox-relay` binary (SPEC-013 §4; FR-023).
pub fn relay_main() -> std::io::Result<()> {
    relay::main_from_args()
}

use crate::isolation::{
    ActivityKind, ActivityReport, JobLimits, JobOutcome, JobSpec, JobStatus, NetworkMode,
    ProbeReport, SandboxBackend,
};
use crate::sandbox::bait::BaitSet;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// Trusted bwrap locations. Never PATH, never the repository.
const BWRAP_PATHS: [&str; 2] = ["/usr/bin/bwrap", "/usr/local/bin/bwrap"];
const BASH_PATHS: [&str; 2] = ["/usr/bin/bash", "/bin/bash"];
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SETPRIV_PATHS: [&str; 2] = ["/usr/bin/setpriv", "/bin/setpriv"];

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

/// `$1` nproc, `$2` address-space KiB, `$3` file-size KiB, `$4` relay program (`-` for none),
/// `$5` relay socket, `$6` reserved, `$7` relay ready file, `$8` setpriv (`-` for none),
/// `$9` seccomp filter file, then the program and its arguments.
///
/// The relay is started before the launch marker so a job never runs without its only network path
/// (fail closed). The marker is written immediately before each `exec`, so a missing marker means
/// setup failed and nothing from the job was executed.
const WRAPPER: &str = r#"if [ "$1" != - ]; then ulimit -S -H -u "$1" || exit 125; fi
if [ "$2" != - ]; then ulimit -S -H -v "$2" || exit 125; fi
if [ "$3" != - ]; then ulimit -S -H -f "$3" || exit 125; fi
if [ "$4" != - ]; then
  "$4" --socket "$5" --ready "$7" >/dev/null 2>&1 &
  n=0
  while [ ! -e "$7" ]; do n=$((n + 1)); if [ "$n" -gt 100 ]; then exit 125; fi; sleep 0.05; done
  p=$(cat "$7" 2>/dev/null)
  if [ -z "$p" ]; then exit 125; fi
  export HTTP_PROXY="http://127.0.0.1:$p" HTTPS_PROXY="http://127.0.0.1:$p" ALL_PROXY="http://127.0.0.1:$p" NO_PROXY=
  export http_proxy="$HTTP_PROXY" https_proxy="$HTTP_PROXY" all_proxy="$HTTP_PROXY" no_proxy=
  export npm_config_proxy="$HTTP_PROXY" npm_config_https_proxy="$HTTP_PROXY"
fi
if [ "$8" != - ]; then
  sp=$8; fl=$9; shift 9
  printf L >&4 || exit 125
  exec 4>&-
  exec "$sp" --seccomp-filter "$fl" --no-new-privs -- "$@"
fi
shift 9
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
    parent_cgroup_limits: bool,
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
    /// Applies the seccomp deny-list inside the sandbox (SPEC-013 §6).
    setpriv: PathBuf,
    scope: Option<Scope>,
    /// Running under the hardened service (system scope, service-owned stages).
    hardened: bool,
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
            parent_cgroup_limits: false,
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

    /// The hardened service places this launcher in a system-scope cgroup
    /// with per-job limits before invoking it. This prevents the normal
    /// per-user systemd scope wrapper from nesting another cgroup.
    pub(crate) fn under_hardened_cgroup(mut self) -> Self {
        self.cgroup = false;
        self.parent_cgroup_limits = true;
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
        let setpriv = SETPRIV_PATHS
            .iter()
            .find_map(|p| trusted_exe(Path::new(p)).ok());
        controls.push(("seccomp_wrapper".into(), setpriv.is_some()));
        let (Some(bwrap), Some(bash), Some(setpriv)) = (bwrap, bash, setpriv) else {
            return unavailable(
                controls,
                "no root-owned, non-writable bwrap, bash and setpriv in /usr/bin, /usr/local/bin or /bin"
                    .into(),
            );
        };
        let scope = if self.cgroup {
            probe_scope(&bash)
        } else {
            None
        };
        let tools = Tools {
            bwrap,
            bash,
            setpriv,
            scope,
            hardened: self.parent_cgroup_limits,
        };
        let mut unexpected = String::new();
        match self_test(&tools, self.parent_cgroup_limits, &mut unexpected) {
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

fn in_hardened_system_scope(kind: &str) -> bool {
    hardened_scope_cgroup_path(kind).is_some()
}

fn hardened_scope_cgroup_path(kind: &str) -> Option<String> {
    let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup") else {
        return None;
    };
    cgroup.lines().find_map(|line| {
        let path = line.strip_prefix("0::/")?;
        let component = path.strip_prefix("system.slice/")?;
        if valid_hardened_scope_name(component, kind) {
            Some(component.to_owned())
        } else {
            None
        }
    })
}

fn hardened_cgroup_limits_fit(job: &JobSpec) -> bool {
    let Some(unit) = hardened_scope_cgroup_path("job") else {
        return false;
    };
    let root = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    let Some(memory) = read_numeric_limit(&root.join("memory.max")) else {
        return false;
    };
    let Some(tasks) = read_numeric_limit(&root.join("pids.max")) else {
        return false;
    };
    let Some(swap) = read_numeric_limit(&root.join("memory.swap.max")) else {
        return false;
    };
    cgroup_limits_fit(memory, tasks, swap, job)
}

fn cgroup_limits_fit(memory: u64, tasks: u64, swap: u64, job: &JobSpec) -> bool {
    let memory_limit = job
        .limits
        .memory_bytes
        .unwrap_or(1024 * 1024 * 1024)
        .max(64 * 1024 * 1024);
    let task_limit = job.limits.max_processes.unwrap_or(256).clamp(1, 32768) as u64;
    memory > 0 && memory <= memory_limit && tasks > 0 && tasks <= task_limit && swap == 0
}

fn read_numeric_limit(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn valid_hardened_scope_name(name: &str, kind: &str) -> bool {
    let prefix = format!("f2c-hardened-{kind}-");
    name.strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix(".scope"))
        .is_some_and(|random| random.len() == 32 && random.bytes().all(|b| b.is_ascii_hexdigit()))
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

/// Whether `c` sits inside the denied directory `d`. The service's own probe stages (strictly
/// below `/run/fail2commit-hardened/probe-stages`) are the one exception to the `/run` rule: they
/// are created, owned and removed by the hardened service for its mandatory effect probes.
fn denied_inside(c: &Path, d: &str, hardened: bool) -> bool {
    let stages = Path::new(crate::sandbox::hardened::PROBE_STAGES_DIR);
    c.starts_with(d) && !(hardened && c != stages && c.starts_with(stages))
}

/// Canonical form of a job path that may be bound into the sandbox.
fn bindable(p: &Path, home: Option<&Path>, hardened: bool) -> crate::Result<PathBuf> {
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
    let inside = DENY_INSIDE.iter().find(|d| denied_inside(&c, d, hardened));
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

/// Sandbox path of the job's control directory (SPEC-013 §3).
const CTL_MOUNT: &str = "/f2c";

/// Everything one job needs outside its own tree: the control directory (relay, seccomp filter,
/// egress socket, bait home) and the watchers that fill the FR-026 report.
struct JobCtl {
    dir: tempfile::TempDir,
    /// Effective environment: `job.env` with the fake home and the bait variables applied.
    env: Vec<(OsString, OsString)>,
    relay: Option<PathBuf>,
    /// Sandbox path of the seccomp filter, or `-` when none was written.
    filter: String,
    watch: Arc<Watch>,
    egress: Option<proxy::Egress>,
    bait_watcher: Option<baitwatch::BaitWatcher>,
    meter_stop: Arc<AtomicBool>,
    meter: Option<thread::JoinHandle<()>>,
}

impl JobCtl {
    fn create(job: &JobSpec) -> crate::Result<JobCtl> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        let watch = Arc::new(Watch::default());
        // seccomp: mandatory containment (SPEC-013 §6).
        let filter_host = root.join("seccomp.bpf");
        seccomp::write_filter(&filter_host)?;
        // Bait home: the job's HOME, never inside the verified/exported tree.
        let mut bait_set = None;
        let mut bait_watcher = None;
        let mut env: Vec<(OsString, OsString)> = job.env.clone();
        let mut home = None;
        if job.bait {
            let set = BaitSet::generate()?;
            let bait_home = root.join("home");
            fs::create_dir(&bait_home)?;
            let files = set.write_into(&bait_home)?;
            env.retain(|(k, _)| k != "HOME");
            env.push(("HOME".into(), format!("{CTL_MOUNT}/home").into()));
            for (k, v) in &set.env {
                env.retain(|(name, _)| name != k.as_str());
                env.push((k.as_str().into(), v.as_str().into()));
            }
            bait_watcher = Some(baitwatch::BaitWatcher::start(
                &bait_home,
                &files,
                Arc::clone(&watch),
            )?);
            bait_set = Some(Arc::new(set));
            home = Some(bait_home);
        }
        // Network: `internet` is the egress proxy behind the relay; `none` is no path at all.
        let mut relay = None;
        let mut egress = None;
        if job.network == NetworkMode::Internet {
            let program = relay::locate().ok_or_else(|| {
                crate::Error::isolation_unavailable(
                    "sandbox network: no f2c-sandbox-relay next to the executable (FR-023)",
                )
            })?;
            let staged = root.join("relay");
            fs::copy(&program, &staged)?;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o555))?;
            egress = Some(proxy::start(&root, Arc::clone(&watch), bait_set.clone())?);
            relay = Some(PathBuf::from(format!("{CTL_MOUNT}/relay")));
        }
        let metered: Vec<PathBuf> = std::iter::once(job.work_dir.clone())
            .chain(home.clone())
            .collect();
        let meter_stop = Arc::new(AtomicBool::new(false));
        let meter = job
            .limits
            .disk_bytes
            .map(|limit| meter_thread(metered, limit, Arc::clone(&watch), meter_stop.clone()));
        Ok(JobCtl {
            dir,
            env,
            relay,
            filter: format!("{CTL_MOUNT}/seccomp.bpf"),
            watch,
            egress,
            bait_watcher,
            meter_stop,
            meter,
        })
    }
}

impl Drop for JobCtl {
    fn drop(&mut self) {
        self.meter_stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.meter.take() {
            let _ = t.join();
        }
        drop(self.egress.take());
        drop(self.bait_watcher.take());
        let _ = &self.dir;
    }
}

/// Sample the stage and the bait home; stop the job when it writes past `limit`.
fn meter_thread(
    paths: Vec<PathBuf>,
    limit: u64,
    watch: Arc<Watch>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
            let used: u64 = paths.iter().map(|p| tree_bytes(p)).sum();
            if used > limit {
                watch.trip(ActivityKind::Limit, format!("disk {used} > {limit} bytes"));
                return;
            }
        }
    })
}

/// Bytes below `root`, not following links and never failing the job on an I/O error.
fn tree_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(e.path());
            } else if md.is_file() {
                total += md.len();
            }
        }
    }
    total
}
/// Validate the job and build the bwrap argument list. Errors here happen
/// before anything is launched.
fn policy_args(tools: &Tools, job: &JobSpec, ctl: &JobCtl) -> crate::Result<Vec<OsString>> {
    let home = home_dir();
    let work = bindable(&job.work_dir, home.as_deref(), tools.hardened)?;
    let ro = job
        .read_only
        .iter()
        .map(|p| bindable(p, home.as_deref(), tools.hardened))
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
    for (k, v) in &ctl.env {
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
    // The job's control directory: relay, seccomp filter, egress socket and the bait home.
    push(&[
        "--bind".as_ref(),
        ctl.dir.path().as_os_str(),
        CTL_MOUNT.as_ref(),
    ]);
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
    // RLIMIT_FSIZE (1024-byte blocks) bounds one file; the meter bounds the whole stage.
    let fsize_kib = job
        .limits
        .disk_bytes
        .map_or("-".to_string(), |b| (b / 1024).max(1).to_string());
    let relay = ctl
        .relay
        .as_ref()
        .map_or_else(|| "-".to_string(), |p| p.display().to_string());
    push(&[
        "--".as_ref(),
        tools.bash.as_os_str(),
        "-c".as_ref(),
        WRAPPER.as_ref(),
        "f2c-sandbox".as_ref(),
        nproc.as_ref(),
        as_kib.as_ref(),
        fsize_kib.as_ref(),
        relay.as_ref(),
        format!("{CTL_MOUNT}/egress.sock").as_ref(),
        "-".as_ref(),
        format!("{CTL_MOUNT}/ready").as_ref(),
        tools.setpriv.as_os_str(),
        ctl.filter.as_ref(),
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
    execute_controlled(tools, job, host_env, None, None)
}

fn execute_controlled(
    tools: &Tools,
    job: &JobSpec,
    host_env: &[(&str, &str)],
    watchdog_closed: Option<&AtomicBool>,
    on_launched: Option<Box<dyn FnOnce() + Send>>,
) -> crate::Result<JobOutcome> {
    let ctl = JobCtl::create(job)?;
    let args = policy_args(tools, job, &ctl)?;
    ctl.watch.record(
        ActivityKind::Process,
        job.program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "program".into()),
    );
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
        let mut mark_r = mark_r;
        let mut b = Vec::new();
        let mut first = [0u8; 1];
        if matches!(mark_r.read(&mut first), Ok(1)) {
            b.push(first[0]);
            // The marker is written only once the payload is about to exec.
            if let Some(callback) = on_launched {
                callback();
            }
        }
        let _ = mark_r.take(15).read_to_end(&mut b);
        b
    });

    let deadline = Instant::now() + job.limits.timeout;
    let mut timed_out = false;
    let mut tripped = false;
    let waited = loop {
        match child.try_wait() {
            // A proxy/watchdog event is authoritative even if the child exits
            // after receiving the refusal response but before this poll.
            Ok(Some(st)) if ctl.watch.tripped() => {
                tripped = true;
                break Ok(st);
            }
            Ok(Some(st)) => break Ok(st),
            Ok(None) if watchdog_closed.is_some_and(|closed| closed.load(Ordering::SeqCst)) => {
                tripped = true;
                break kill_tree(&mut child, &init_pid);
            }
            Ok(None) if ctl.watch.tripped() => {
                // A bait touch or a hard limit: stop the job now (FR-024, FR-020).
                tripped = true;
                break kill_tree(&mut child, &init_pid);
            }
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
    let mut report: ActivityReport = ctl.watch.take_report();
    if timed_out {
        report.push(ActivityKind::Limit, "timeout");
    }
    if t1 || t2 {
        report.push(ActivityKind::Limit, "output");
    }
    if status.signal() == Some(libc::SIGXFSZ) {
        report.push(ActivityKind::Limit, "disk");
    }
    let status = if timed_out {
        JobStatus::TimedOut
    } else if tripped {
        JobStatus::Killed
    } else {
        status.code().map_or(JobStatus::Killed, JobStatus::Exited)
    };
    Ok(JobOutcome {
        status,
        stdout,
        stderr,
        truncated: t1 || t2,
        exported: Vec::new(),
        report,
    })
}

/// Watches the service's watchdog pipe. The service never writes to it, so EOF, an error and any
/// byte (including a single 0x00) all mean "closed" and cancel the job.
fn spawn_watchdog_monitor(
    watchdog: std::fs::File,
    closed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("f2c-hardened-watchdog".into())
        .spawn(move || {
            use std::os::fd::AsRawFd;
            let fd = watchdog.as_raw_fd();
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            while !stop.load(Ordering::Acquire) {
                // SAFETY: pollfd points to one live descriptor and has the
                // correct count for the duration of this bounded wait.
                let result = unsafe { libc::poll(&mut pollfd, 1, 50) };
                if result < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    closed.store(true, Ordering::SeqCst);
                    return;
                }
                if result == 0 {
                    continue;
                }
                // POLLIN (any data), POLLHUP, POLLERR and POLLNVAL all end the job.
                closed.store(true, Ordering::SeqCst);
                return;
            }
        })
}

/// Run an immutable service snapshot under the dedicated system account. The
/// caller supplies the inherited watchdog read descriptor; this path never
/// creates the user-scope wrapper used by the ordinary per-user backend.
#[cfg(target_os = "linux")]
pub(crate) fn run_hardened(job: &JobSpec, watchdog_fd: i32) -> crate::Result<JobOutcome> {
    run_hardened_with_ready(job, watchdog_fd, || Ok(()))
}

#[cfg(target_os = "linux")]
pub(crate) fn run_hardened_with_ready(
    job: &JobSpec,
    watchdog_fd: i32,
    ready: impl FnOnce() -> crate::Result<()> + Send + 'static,
) -> crate::Result<JobOutcome> {
    use std::os::fd::FromRawFd;

    if watchdog_fd < 0 || unsafe { libc::fcntl(watchdog_fd, libc::F_GETFD) } < 0 {
        return Err(crate::Error::rejected(
            "hardened launcher watchdog descriptor is invalid",
        ));
    }
    // SAFETY: geteuid has no preconditions and returns the effective uid.
    if unsafe { libc::geteuid() } == 0 {
        return Err(crate::Error::rejected(
            "hardened launcher must run as an unprivileged system account",
        ));
    }
    if !in_hardened_system_scope("job") {
        return Err(crate::Error::rejected(
            "hardened Linux launcher is outside its service-owned system scope",
        ));
    }
    if !hardened_cgroup_limits_fit(job) {
        return Err(crate::Error::rejected(
            "hardened Linux system-scope cgroup limits do not match the immutable job snapshot",
        ));
    }

    let watchdog = unsafe { std::fs::File::from_raw_fd(watchdog_fd) };
    let watchdog_closed = Arc::new(AtomicBool::new(false));
    let monitor_stop = Arc::new(AtomicBool::new(false));
    let monitor = spawn_watchdog_monitor(
        watchdog,
        Arc::clone(&watchdog_closed),
        Arc::clone(&monitor_stop),
    )?;

    let backend = Bubblewrap::default().under_hardened_cgroup();
    let probed = backend.probe_now();
    let result = match probed.tools {
        Some(tools) if !watchdog_closed.load(Ordering::SeqCst) => {
            // `ready` fires after the payload has launched, so a watchdog EOF that the
            // caller sends in response always meets a running process tree.
            execute_controlled(
                &tools,
                job,
                &[],
                Some(&watchdog_closed),
                Some(Box::new(move || {
                    let _ = ready();
                })),
            )
        }
        Some(_) => Err(crate::Error::isolation_unavailable(
            "service watchdog closed during hardened control probes",
        )),
        None => Err(crate::Error::isolation_unavailable(format!(
            "hardened Linux controls are unavailable: {}",
            probed.report.detail
        ))),
    };
    monitor_stop.store(true, Ordering::Release);
    monitor
        .join()
        .map_err(|_| crate::Error::internal("hardened watchdog monitor panicked"))?;
    match result {
        Ok(mut outcome) if watchdog_closed.load(Ordering::SeqCst) => {
            outcome.status = JobStatus::Killed;
            outcome
                .report
                .push(ActivityKind::Blocked, "service watchdog closed");
            Ok(outcome)
        }
        other => other,
    }
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
        disk_bytes: None,
    };
    let mut c = scope_command(&scope, &limits);
    c.arg(bash).args(["-c", SCOPE_SCRIPT]);
    let out = output_with_timeout(c, limits.timeout)?;
    (out.trim() == "7 67108864").then_some(scope)
}

/// Run a real sandbox and verify each mandatory control from inside it.
/// `diagnostic` receives any unexpected env keys, root entries or visible
/// host paths, for the probe detail.
fn self_test(
    tools: &Tools,
    parent_cgroup_limits: bool,
    diagnostic: &mut String,
) -> crate::Result<Vec<(String, bool)>> {
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
            disk_bytes: None,
        },
        network: crate::isolation::NetworkMode::None,
        bait: false,
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
                    && !["etc", "proc", "dev", "tmp", "f2c"].contains(&e.as_str())
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
        tools.scope.is_some() || parent_cgroup_limits || (nproc_ok && !is_root),
    ));
    let as_ok = field("as") == [(PROBE_MEMORY / 1024).to_string()];
    controls.push((
        "memory_limit".into(),
        tools.scope.is_some() || parent_cgroup_limits || as_ok,
    ));
    controls.push((
        "cgroup_v2_limits".into(),
        tools.scope.is_some() || parent_cgroup_limits,
    ));
    Ok(controls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_monitor_treats_any_byte_as_closed() {
        use std::io::Write;
        use std::os::fd::{FromRawFd, IntoRawFd};
        let (r, w) = std::io::pipe().unwrap();
        // SAFETY: the raw fd comes from a pipe end this test owns and gives up.
        let file = unsafe { std::fs::File::from_raw_fd(r.into_raw_fd()) };
        let closed = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_watchdog_monitor(file, closed.clone(), stop.clone()).unwrap();
        thread::sleep(Duration::from_millis(120));
        assert!(!closed.load(Ordering::SeqCst), "an idle open pipe is alive");
        (&w).write_all(&[0]).unwrap();
        handle.join().unwrap();
        assert!(
            closed.load(Ordering::SeqCst),
            "a 0x00 byte must close the job"
        );
    }

    #[test]
    fn only_service_probe_stages_escape_the_run_deny_rule() {
        let stage = "/run/fail2commit-hardened/probe-stages/probe-abc/work";
        assert!(!denied_inside(Path::new(stage), "/run", true));
        assert!(
            denied_inside(Path::new(stage), "/run", false),
            "the carve-out is hardened-only"
        );
        for still_denied in [
            "/run/fail2commit-hardened/probe-stages",
            "/run/fail2commit-hardened/probe-stagesX/work",
            "/run/fail2commit-hardened/jobs/job-abc/input",
            "/run/fail2commit-hardened/sock",
            "/run/docker.sock",
        ] {
            assert!(
                denied_inside(Path::new(still_denied), "/run", true),
                "{still_denied}"
            );
        }
    }

    #[test]
    fn bindable_refuses_home_root_and_sockets() {
        let home = Path::new("/home/someone");
        for bad in ["/", "/home", "/run", "/proc/self", "/dev", "/etc", "/tmp"] {
            assert!(
                bindable(Path::new(bad), Some(home), false).is_err(),
                "{bad}"
            );
        }
        assert!(bindable(Path::new("relative"), None, false).is_err());
        let d = tempfile::tempdir().unwrap();
        let ok = bindable(d.path(), Some(home), false).unwrap();
        assert!(
            bindable(&ok, Some(&ok), false).is_err(),
            "the host home itself"
        );
        assert!(
            bindable(&ok, Some(&ok.join("child")), false).is_err(),
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

    #[test]
    fn hardened_scope_probe_rejects_user_scopes_and_malformed_names() {
        assert!(valid_hardened_scope_name(
            "f2c-hardened-job-0123456789abcdef0123456789abcdef.scope",
            "job"
        ));
        assert!(valid_hardened_scope_name(
            "f2c-hardened-probe-0123456789abcdef0123456789abcdef.scope",
            "probe"
        ));
        for invalid in [
            "f2c-hardened-job-0123456789abcdef0123456789abcdef.scope.extra",
            "f2c-hardened-job-0123456789abcdef0123456789abcdeg.scope",
            "f2c-hardened-probe-0123456789abcdef0123456789abcdef.scope",
        ] {
            assert!(!valid_hardened_scope_name(invalid, "job"), "{invalid}");
        }
    }

    #[test]
    fn hardened_job_scope_limits_must_fit_the_snapshot_and_disable_swap() {
        let td = tempfile::tempdir().unwrap();
        let mut spec = JobSpec {
            program: PathBuf::from("/bin/true"),
            args: Vec::new(),
            cwd: td.path().to_path_buf(),
            env: Vec::new(),
            read_only: Vec::new(),
            work_dir: td.path().to_path_buf(),
            exports: Vec::new(),
            export_to: None,
            limits: JobLimits {
                timeout: Duration::from_secs(1),
                memory_bytes: Some(128 * 1024 * 1024),
                max_processes: Some(16),
                max_output_bytes: 1024,
                disk_bytes: None,
            },
            network: NetworkMode::None,
            bait: false,
        };
        assert!(cgroup_limits_fit(128 * 1024 * 1024, 16, 0, &spec));
        assert!(cgroup_limits_fit(64 * 1024 * 1024, 8, 0, &spec));
        assert!(!cgroup_limits_fit(129 * 1024 * 1024, 16, 0, &spec));
        assert!(!cgroup_limits_fit(128 * 1024 * 1024, 17, 0, &spec));
        assert!(!cgroup_limits_fit(128 * 1024 * 1024, 16, 1, &spec));
        spec.limits.memory_bytes = None;
        spec.limits.max_processes = None;
        assert!(cgroup_limits_fit(1024 * 1024 * 1024, 256, 0, &spec));
        assert!(!cgroup_limits_fit(1024 * 1024 * 1024 + 1, 256, 0, &spec));
    }

    #[test]
    fn cgroup_limit_parser_rejects_unlimited_and_malformed_values() {
        assert_eq!("536870912".parse::<u64>().ok(), Some(536870912));
        assert_eq!("max".parse::<u64>().ok(), None);
        assert_eq!("".parse::<u64>().ok(), None);
        assert_eq!("-1".parse::<u64>().ok(), None);
    }
}
