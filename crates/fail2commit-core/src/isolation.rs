//! Sandbox backend contract (CHORE-001, frozen; SPEC-007 semantics).
//!
//! Backends live in `crate::sandbox` (T-007). Network is `None` unless the job
//! asks for `Internet` (FR-023, CR-022): public internet addresses only, never
//! loopback, private, link-local, metadata or local IPC. Paths are host paths;
//! Linux binds them at the same location, Windows grants AppContainer ACLs on
//! them. 0.1.4 additions (frozen by the coordinator): `JobSpec::network`,
//! `JobSpec::bait`, `JobOutcome::report`.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobLimits {
    pub timeout: Duration,
    pub memory_bytes: Option<u64>,
    pub max_processes: Option<u32>,
    /// Combined stdout+stderr cap; excess is dropped and `truncated` set.
    pub max_output_bytes: u64,
    /// Bytes the job may write into its stage (0.1.4, FR-020 HB-053); `None`
    /// means no disk limit.
    pub disk_bytes: Option<u64>,
}

impl JobLimits {
    pub fn from_settings(l: &crate::settings::Limits) -> Self {
        JobLimits {
            timeout: Duration::from_secs(l.job_timeout_secs),
            memory_bytes: Some(l.job_memory_mb.saturating_mul(1024 * 1024)),
            max_processes: Some(l.job_max_processes),
            max_output_bytes: l.job_max_output_bytes,
            disk_bytes: Some(l.job_disk_mb.saturating_mul(1024 * 1024)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSpec {
    /// Absolute path to a staged, trusted executable.
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// Working directory; must be inside `work_dir`.
    pub cwd: PathBuf,
    /// The complete environment. Everything else is cleared.
    pub env: Vec<(OsString, OsString)>,
    /// Read-only inputs: staged toolchain and reviewed package files.
    pub read_only: Vec<PathBuf>,
    /// Disposable writable directory for this job only.
    pub work_dir: PathBuf,
    /// Paths relative to `work_dir` that may be copied out on success.
    pub exports: Vec<PathBuf>,
    /// Destination for exports; `None` exports nothing.
    pub export_to: Option<PathBuf>,
    pub limits: JobLimits,
    /// FR-023: what the job may reach. Backends that cannot enforce
    /// `Internet` exactly must refuse the job (`IsolationUnavailable`).
    pub network: NetworkMode,
    /// FR-024: place per-job bait credentials and stop the job on a touch.
    pub bait: bool,
}

pub use crate::settings::NetworkMode;

/// FR-026: what the sandbox observed. Entries are untrusted, bounded
/// ([`MAX_ACTIVITY`]) and must be redacted before display.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ActivityReport {
    pub events: Vec<Activity>,
    /// More events happened than were kept.
    pub truncated: bool,
}

pub const MAX_ACTIVITY: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Activity {
    pub kind: ActivityKind,
    /// Path, destination (`host:port` or address), command line or limit name.
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    /// Access outside the grants was refused.
    FileDenied,
    /// Outbound connection that was allowed (public internet).
    NetAllowed,
    /// Connection, listen or name lookup that was refused.
    NetRefused,
    /// A process the job started.
    Process,
    /// A bait credential was opened or a bait value was seen leaving (FR-024).
    /// The backend stops the job when it records this.
    Bait,
    /// A resource limit was hit (processes, memory, time, disk, output).
    Limit,
    /// A system call or API the policy blocks (seccomp, mitigation policy).
    Blocked,
}

impl ActivityReport {
    /// Append, keeping at most [`MAX_ACTIVITY`] entries.
    pub fn push(&mut self, kind: ActivityKind, detail: impl Into<String>) {
        if self.events.len() < MAX_ACTIVITY {
            self.events.push(Activity {
                kind,
                detail: detail.into(),
            });
        } else {
            self.truncated = true;
        }
    }

    pub fn bait_touched(&self) -> bool {
        self.events.iter().any(|e| e.kind == ActivityKind::Bait)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    /// `bubblewrap`, `appcontainer`, or `unavailable`.
    pub backend: &'static str,
    /// True only when every mandatory control below is enforced.
    pub available: bool,
    pub detail: String,
    /// Named mandatory controls and whether each was verified.
    pub controls: Vec<(String, bool)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Exited(i32),
    TimedOut,
    /// Killed by a resource limit or cleanup.
    Killed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobOutcome {
    pub status: JobStatus,
    /// Untrusted bytes; display only after sanitizing.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    /// Destination paths actually exported (empty unless Exited(0)).
    pub exported: Vec<PathBuf>,
    /// FR-026: observed activity (empty when the backend records none).
    pub report: ActivityReport,
}

pub trait SandboxBackend: Send + Sync {
    /// Capability check run before any package code starts. Cheap enough to
    /// call per operation; no long-lived sandbox process.
    fn probe(&self) -> ProbeReport;

    /// Run one job and wait for every child to stop. Must return
    /// `IsolationUnavailable` and launch nothing if any mandatory control
    /// cannot be applied. Backends never export; `sandbox::run_job` copies
    /// `exports` only after `Exited(0)`.
    fn run(&self, job: &JobSpec) -> crate::Result<JobOutcome>;
}
