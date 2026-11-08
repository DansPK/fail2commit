//! Error type carrying a stable [`ResultCode`] (CHORE-001, frozen).

use crate::protocol::{Finding, ResultCode};
use std::fmt;

#[derive(Debug, Clone)]
pub struct Error {
    pub code: ResultCode,
    /// Redacted, user-facing message.
    pub message: String,
    pub findings: Vec<Finding>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(code: ResultCode, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
            findings: Vec::new(),
        }
    }
    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }
    pub fn rejected(m: impl Into<String>) -> Self {
        Self::new(ResultCode::Rejected, m)
    }
    pub fn invalid(m: impl Into<String>) -> Self {
        Self::new(ResultCode::InvalidInput, m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(ResultCode::Internal, m)
    }
    pub fn approval_unavailable(m: impl Into<String>) -> Self {
        Self::new(ResultCode::ApprovalUnavailable, m)
    }
    pub fn isolation_unavailable(m: impl Into<String>) -> Self {
        Self::new(ResultCode::IsolationUnavailable, m)
    }
    pub fn integrity(m: impl Into<String>) -> Self {
        Self::new(ResultCode::IntegrityFailure, m)
    }
    pub fn incomplete(m: impl Into<String>) -> Self {
        Self::new(ResultCode::IncompleteScan, m)
    }
    /// Placeholder used by area stubs until the owning task lands.
    pub fn not_implemented(what: &str) -> Self {
        Self::internal(format!("{what} is not implemented in this build"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::internal(format!("I/O error: {e}"))
    }
}
