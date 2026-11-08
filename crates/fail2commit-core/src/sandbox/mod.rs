//! T-007 (FR-007, SPEC-007) owns this directory. Split ownership:
//! `linux.rs`, this `mod.rs` and the export step: T-007a (Bubblewrap).
//! `windows.rs`: T-007b (sandboxrs-windows AppContainer).
//!
//! Frozen API: [`platform_backend`], [`run_job`].

use crate::isolation::{JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// The backend for this platform. Unsupported platforms get a backend whose
/// probe reports unavailable, so callers fail closed.
pub fn platform_backend() -> Box<dyn SandboxBackend> {
    #[cfg(target_os = "linux")]
    return Box::new(linux::Bubblewrap);
    #[cfg(windows)]
    return Box::new(windows::AppContainer);
    #[allow(unreachable_code)]
    Box::new(Unavailable)
}

/// Probe, run, then export declared paths only after a clean exit.
/// Backends never export themselves.
pub fn run_job(backend: &dyn SandboxBackend, job: &JobSpec) -> crate::Result<JobOutcome> {
    let probe = backend.probe();
    if !probe.available {
        return Err(crate::Error::isolation_unavailable(format!(
            "{}: {}",
            probe.backend, probe.detail
        )));
    }
    let mut outcome = backend.run(job)?;
    if outcome.status == JobStatus::Exited(0) && job.export_to.is_some() && !job.exports.is_empty()
    {
        outcome.exported = export(job)?;
    }
    Ok(outcome)
}

/// Copy `job.exports` from `job.work_dir` to `job.export_to`, rejecting
/// links, reparse points, paths escaping the work dir and oversized output.
fn export(job: &JobSpec) -> crate::Result<Vec<std::path::PathBuf>> {
    let _ = job;
    Err(crate::Error::not_implemented("sandbox export"))
}

/// Fallback backend: never runs anything.
pub struct Unavailable;

impl SandboxBackend for Unavailable {
    fn probe(&self) -> ProbeReport {
        ProbeReport {
            backend: "unavailable",
            available: false,
            detail: "no sandbox backend for this platform".into(),
            controls: vec![],
        }
    }
    fn run(&self, _job: &JobSpec) -> crate::Result<JobOutcome> {
        Err(crate::Error::isolation_unavailable(
            "no sandbox backend for this platform",
        ))
    }
}
