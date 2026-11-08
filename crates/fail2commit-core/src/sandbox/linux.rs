//! T-007a owns this file. Stub: reports unavailable until implemented.

use crate::isolation::{JobOutcome, JobSpec, ProbeReport, SandboxBackend};

#[derive(Default)]
pub struct Bubblewrap;

impl SandboxBackend for Bubblewrap {
    fn probe(&self) -> ProbeReport {
        ProbeReport {
            backend: "bubblewrap",
            available: false,
            detail: "backend not implemented".into(),
            controls: vec![],
        }
    }
    fn run(&self, _job: &JobSpec) -> crate::Result<JobOutcome> {
        Err(crate::Error::isolation_unavailable(
            "backend not implemented",
        ))
    }
}
