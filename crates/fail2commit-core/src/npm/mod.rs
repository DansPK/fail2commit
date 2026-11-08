//! T-004 (FR-004, SPEC-004) owns this directory.
//!
//! Frozen API: [`integration`]. Resolver, staging, apply and fixtures are
//! the worker's choice; use `crate::scan`, `crate::sandbox`, `crate::policy`
//! and `crate::approval` through their frozen APIs.

use crate::integration::Integration;

/// npm shim integration for `fail2commit setup`.
pub fn integration() -> Option<Box<dyn Integration>> {
    None
}
