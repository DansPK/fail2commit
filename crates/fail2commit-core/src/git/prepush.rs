//! Pre-push review: parse what Git is about to send, collect findings and
//! bind one approval request to the exact tuples observed.

use super::RefUpdate;
use crate::approver;
use crate::digest::Digest;
use crate::protocol::{
    ApprovalKind, ApprovalRequest, Decision, Finding, FindingAction, FindingKind,
};
use crate::redact::redact_url_credentials;
use crate::settings::Limits;
use serde::Serialize;
use std::io::Read;
use std::path::Path;

/// Set by the shim for the hook it triggers: JSON array of reason strings.
/// Untrusted by design: it can only add confirmation, never remove it.
pub const INTENT_ENV: &str = "FAIL2COMMIT_PUSH_INTENT";

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_UPDATES: usize = 100_000;

/// Parse pre-push stdin: `<local ref> <local oid> <remote ref> <remote oid>`.
pub fn parse_hook_input(r: impl Read) -> crate::Result<Vec<RefUpdate>> {
    let mut buf = Vec::new();
    r.take(MAX_INPUT_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_INPUT_BYTES {
        return Err(crate::Error::incomplete("pre-push input is too large"));
    }
    let text = String::from_utf8_lossy(&buf);
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() != 4 || !super::gitcmd::valid_oid(f[1]) || !super::gitcmd::valid_oid(f[3]) {
            return Err(crate::Error::invalid("malformed pre-push input line"));
        }
        out.push(RefUpdate {
            refname: f[2].to_string(),
            old: f[3].to_string(),
            new: f[1].to_string(),
        });
        if out.len() > MAX_UPDATES {
            return Err(crate::Error::incomplete("too many ref updates to review"));
        }
    }
    Ok(out)
}

/// Reasons the shim recorded, ignoring anything malformed.
pub fn intent_from_env() -> Vec<String> {
    std::env::var(INTENT_ENV)
        .ok()
        .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
        .unwrap_or_default()
}

pub fn intent_finding(reasons: &[String]) -> Option<Finding> {
    if reasons.is_empty() {
        return None;
    }
    Some(Finding::new(
        FindingKind::ForceIntent,
        FindingAction::Approve,
        "git.shim",
        format!("explicit force intent: {}", reasons.join(", ")),
    ))
}

/// All findings for a push: intent, classification, secrets.
pub fn review(
    git: &Path,
    repo: &Path,
    remote: &str,
    updates: &[RefUpdate],
    intent: &[String],
    limits: &Limits,
) -> crate::Result<Vec<Finding>> {
    let mut findings: Vec<Finding> = intent_finding(intent).into_iter().collect();
    findings.extend(super::classify::classify(git, repo, updates)?);
    findings.extend(super::scan::scan(git, repo, updates, Some(remote), limits)?);
    Ok(findings)
}

#[derive(Serialize)]
struct Plan<'a> {
    remote: &'a str,
    url: &'a str,
    updates: &'a [RefUpdate],
    findings: &'a [Finding],
    intent: &'a [String],
}

/// Whether a plan needs the force-push password (when one is configured).
/// Every destructive update counts, whether or not the shim recorded intent.
pub fn needs_password(findings: &[Finding]) -> bool {
    findings.iter().any(|f| {
        matches!(
            f.kind,
            FindingKind::ForceIntent
                | FindingKind::RefRewrite
                | FindingKind::TagReplacement
                | FindingKind::RefDeletion
        )
    })
}

/// Build the single request, bound to remote, url, every tuple and every
/// finding. A changed plan changes the digest and voids any approval.
#[allow(clippy::too_many_arguments)]
pub fn build_request(
    remote: &str,
    url: &str,
    updates: &[RefUpdate],
    findings: &[Finding],
    intent: &[String],
    ttl_secs: u64,
    password_required: bool,
) -> crate::Result<ApprovalRequest> {
    let url = redact_url_credentials(url);
    let digest = Digest::of(
        "git.push",
        &Plan {
            remote,
            url: &url,
            updates,
            findings,
            intent,
        },
    )?;
    let details = updates
        .iter()
        .map(|u| format!("{} {} -> {}", u.refname, short(&u.old), short(&u.new)))
        .collect();
    approver::new_request(
        ApprovalKind::Operation,
        &digest,
        format!(
            "git push to {remote} ({url}): {} finding(s)",
            findings.len()
        ),
        details,
        findings.to_vec(),
        ttl_secs,
        password_required,
        vec![Decision::ApproveOnce],
    )
}

fn short(oid: &str) -> &str {
    &oid[..oid.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;

    const Z: &str = "0000000000000000000000000000000000000000";
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn parses_tuples() {
        let input = format!("refs/heads/a {A} refs/heads/b {Z}\n(delete) {Z} refs/heads/c {A}\n");
        let u = parse_hook_input(input.as_bytes()).unwrap();
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].refname, "refs/heads/b");
        assert_eq!(u[1].new, Z);
        assert!(parse_hook_input("a b c\n".as_bytes()).is_err());
    }

    #[test]
    fn digest_changes_with_any_tuple_or_finding() {
        let u = |new: &str| {
            vec![RefUpdate {
                refname: "refs/heads/m".into(),
                old: Z.into(),
                new: new.into(),
            }]
        };
        let r1 = build_request("o", "u", &u(A), &[], &[], 60, false).unwrap();
        let r2 = build_request("o", "u", &u(&"b".repeat(40)), &[], &[], 60, false).unwrap();
        let f = vec![Finding::new(
            FindingKind::RefRewrite,
            FindingAction::Approve,
            "t",
            "e",
        )];
        let r3 = build_request("o", "u", &u(A), &f, &[], 60, false).unwrap();
        assert_ne!(r1.digest, r2.digest);
        assert_ne!(r1.digest, r3.digest);
    }
}
