//! Optional disposable VM backend selection (FR-029, SPEC-019).

use crate::isolation::{JobOutcome, JobSpec, ProbeReport, SandboxBackend};

#[cfg(windows)]
mod windows;

pub(crate) fn selected() -> Box<dyn SandboxBackend> {
    #[cfg(windows)]
    return windows::selected();

    #[cfg(not(windows))]
    Box::new(UnavailableVm)
}

/// A documented absence falls back to the platform backend. Every other probe
/// failure stays selected and is reported as unavailable by that VM backend.
pub(crate) struct PlatformFallback {
    backend: Box<dyn SandboxBackend>,
    reason: String,
}

impl PlatformFallback {
    #[cfg(any(windows, test))]
    fn new(backend: Box<dyn SandboxBackend>, reason: impl Into<String>) -> Self {
        Self {
            backend,
            reason: reason.into(),
        }
    }
}

impl SandboxBackend for PlatformFallback {
    fn probe(&self) -> ProbeReport {
        let mut report = self.backend.probe();
        report.detail = format!("VM fallback: {}; {}", self.reason, report.detail);
        report
            .controls
            .push(("vm_fallback_to_platform".into(), true));
        report
    }

    fn run(&self, job: &JobSpec) -> crate::Result<JobOutcome> {
        self.backend.run(job)
    }
}

#[cfg(not(windows))]
struct UnavailableVm;

#[cfg(not(windows))]
impl SandboxBackend for UnavailableVm {
    fn probe(&self) -> ProbeReport {
        ProbeReport {
            backend: "vm",
            available: false,
            detail: "the VM backend is not implemented for this platform".into(),
            controls: vec![("vm_platform_backend".into(), false)],
        }
    }

    fn run(&self, _job: &JobSpec) -> crate::Result<JobOutcome> {
        Err(crate::Error::isolation_unavailable(
            "the VM backend is not implemented for this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::{ActivityReport, JobOutcome, JobStatus};

    struct Fake;

    impl SandboxBackend for Fake {
        fn probe(&self) -> ProbeReport {
            ProbeReport {
                backend: "platform-test",
                available: true,
                detail: "platform ready".into(),
                controls: vec![],
            }
        }

        fn run(&self, _job: &JobSpec) -> crate::Result<JobOutcome> {
            Ok(JobOutcome {
                status: JobStatus::Exited(0),
                stdout: vec![],
                stderr: vec![],
                truncated: false,
                exported: vec![],
                report: ActivityReport::default(),
            })
        }
    }

    #[test]
    fn platform_fallback_reports_reason_and_delegates_probe() {
        let backend = PlatformFallback::new(Box::new(Fake), "Windows Sandbox feature is disabled");
        let probe = backend.probe();
        assert_eq!(probe.backend, "platform-test");
        assert!(probe.available);
        assert!(probe.detail.contains("feature is disabled"));
        assert!(probe
            .controls
            .contains(&("vm_fallback_to_platform".into(), true)));
    }
}
