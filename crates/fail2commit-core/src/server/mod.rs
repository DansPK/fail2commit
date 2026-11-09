//! T-003 (FR-003, SPEC-003): pre-receive enforcement and the trusted
//! maintainer-side approval issuer. Server policy and approval verifiers live
//! in a server home that is never inside a repository (see docs/server.md).

mod approvals;
mod config;
mod install;
mod receive;

pub use approvals::{issue, updates_digest, Issued};
pub use config::{ServerConfig, ServerHome};
pub use install::install;
pub use receive::{parse_updates, pre_receive, repo_id, ReceiveInput};
