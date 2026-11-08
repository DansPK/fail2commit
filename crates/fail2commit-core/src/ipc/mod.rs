//! T-009 (FR-009, SPEC-009) owns this directory: the same-user Windows
//! named-pipe approval channel (client side) and tray startup integration.
//!
//! Frozen API: [`tray_approver`], [`integration`].

use crate::approver::Approver;
use crate::integration::Integration;

/// Approver that forwards to a running tray, or `None` when no tray is
/// reachable (callers then fall back to the terminal or fail closed).
pub fn tray_approver() -> Option<Box<dyn Approver>> {
    None
}

/// Tray sign-in startup integration for `fail2commit setup`.
pub fn integration() -> Option<Box<dyn Integration>> {
    None
}
