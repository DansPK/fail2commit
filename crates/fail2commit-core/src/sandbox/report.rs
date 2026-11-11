//! FR-026: turn a job's [`ActivityReport`] into findings (coordinator-owned).
//!
//! A bait touch (FR-024) is a hard denial; refused access, blocked calls and
//! limits are information shown with the result. Details come from inside the
//! sandbox, so they are bounded and cleaned here before any message.

use crate::isolation::{ActivityKind, ActivityReport};
use crate::protocol::{Finding, FindingAction, FindingKind};

const MAX_DETAIL_CHARS: usize = 200;

fn clean(detail: &str) -> String {
    crate::redact::redact_url_credentials(detail)
        .chars()
        .filter(|c| !crate::redact::is_invisible_or_bidi(*c))
        .take(MAX_DETAIL_CHARS)
        .collect()
}

/// Findings for one job; `target` names what ran (`npm:pkg@1.0.0`), and
/// `script` the lifecycle event.
pub fn findings(report: &ActivityReport, target: &str, script: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in &report.events {
        let (kind, action, what) = match e.kind {
            ActivityKind::Bait => (
                FindingKind::BaitTouched,
                FindingAction::Deny,
                "touched a bait credential",
            ),
            ActivityKind::FileDenied => (
                FindingKind::SandboxActivity,
                FindingAction::Info,
                "was refused file access",
            ),
            ActivityKind::NetRefused => (
                FindingKind::SandboxActivity,
                FindingAction::Info,
                "was refused a connection",
            ),
            ActivityKind::Limit => (
                FindingKind::SandboxActivity,
                FindingAction::Info,
                "hit a sandbox limit",
            ),
            ActivityKind::Blocked => (
                FindingKind::SandboxActivity,
                FindingAction::Info,
                "was blocked by the sandbox policy",
            ),
            ActivityKind::NetAllowed => (
                FindingKind::SandboxActivity,
                FindingAction::Info,
                "connected to",
            ),
            ActivityKind::Process => continue,
        };
        out.push(
            Finding::new(
                kind,
                action,
                "sandbox.activity",
                format!("{script} {what}: {}", clean(&e.detail)),
            )
            .target(target)
            .location(script),
        );
    }
    if report.truncated {
        out.push(
            Finding::new(
                FindingKind::SandboxActivity,
                FindingAction::Info,
                "sandbox.activity",
                format!("{script}: more sandbox activity than the report keeps"),
            )
            .target(target)
            .location(script),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bait_denies_and_other_entries_inform() {
        let mut r = ActivityReport::default();
        r.push(ActivityKind::Bait, ".npmrc opened");
        r.push(ActivityKind::NetRefused, "127.0.0.1:22");
        r.push(ActivityKind::Process, "node build.js");
        r.push(
            ActivityKind::NetAllowed,
            "https://user:tok@registry.npmjs.org:443",
        );
        let f = findings(&r, "npm:x@1.0.0", "postinstall");
        assert_eq!(f.len(), 3);
        assert_eq!(
            (f[0].kind, f[0].action),
            (FindingKind::BaitTouched, FindingAction::Deny)
        );
        assert!(f[1..].iter().all(|x| x.action == FindingAction::Info));
        assert!(!f[2].evidence.contains("tok"), "{}", f[2].evidence);
    }
}
