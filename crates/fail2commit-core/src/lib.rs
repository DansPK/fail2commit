//! Shared policy and integration code for fail2commit.
//!
//! CHORE-001 contract layout. Coordinator-owned (frozen, change only via the
//! coordinator): `protocol`, `digest`, `error`, `paths`, `fsutil`, `settings`,
//! `policy`, `approver`, `isolation`, `integration`, `redact`, `toolpath`.
//!
//! Area modules are owned by their task worker, who must keep the public
//! signatures marked "frozen" in each area `mod.rs`:
//! `git` (T-001), `approval` (T-002), `server` (T-003), `npm` (T-004),
//! `pip` (T-005), `scan` (T-006), `sandbox` (T-007), `ipc` (T-009).

// Unsafe is denied crate-wide; FFI modules (Windows ACLs, pipes, sandbox
// backends) opt in locally with `#[allow(unsafe_code)]` and a SAFETY comment.
#![deny(unsafe_code)]

pub mod approver;
pub mod digest;
pub mod error;
pub mod fsutil;
pub mod integration;
pub mod isolation;
pub mod paths;
pub mod policy;
pub mod protocol;
pub mod redact;
pub mod settings;
pub mod toolpath;

pub mod approval;
pub mod git;
pub mod ipc;
pub mod npm;
pub mod pip;
pub mod sandbox;
pub mod scan;
pub mod server;

pub use error::{Error, Result};
pub use protocol::{Finding, FindingAction, FindingKind, ResultCode};
