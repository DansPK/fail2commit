//! Sandbox backend contract (CHORE-001, frozen; SPEC-007 semantics).
//!
//! Backends live in `crate::sandbox` (T-007). Network is never granted, so
//! there is no network field. Paths are host paths; Linux binds them at the
//! same location, Windows grants AppContainer ACLs on them.

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
}

impl JobLimits {
    pub fn from_settings(l: &crate::settings::Limits) -> Self {
        JobLimits {
            timeout: Duration::from_secs(l.job_timeout_secs),
            memory_bytes: Some(l.job_memory_mb.saturating_mul(1024 * 1024)),
            max_processes: Some(l.job_max_processes),
            max_output_bytes: l.job_max_output_bytes,
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
