//! T-005 (FR-005, SPEC-005) owns this directory.
//!
//! Frozen API: [`integration`]. Resolver, staging, verification and fixtures
//! are the worker's choice; use `crate::scan`, `crate::policy` and
//! `crate::approval` through their frozen APIs.

use crate::integration::Integration;

/// pip shim integration for `fail2commit setup`.
pub fn integration() -> Option<Box<dyn Integration>> {
    None
}
