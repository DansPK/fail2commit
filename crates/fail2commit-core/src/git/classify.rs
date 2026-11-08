//! Ref update classification: rewrites, deletions, tag replacement.

use super::gitcmd::{self, check_oid};
use super::RefUpdate;
use crate::protocol::{Finding, FindingAction, FindingKind};
use std::path::Path;

const SRC: &str = "git.pre-push";

pub fn classify(git: &Path, repo: &Path, updates: &[RefUpdate]) -> crate::Result<Vec<Finding>> {
    let mut out = Vec::new();
    for u in updates {
        check_oid(&u.old)?;
        check_oid(&u.new)?;
        let target = u.refname.as_str();
        let f = |kind, ev: &str| Finding::new(kind, FindingAction::Approve, SRC, ev).target(target);
        if RefUpdate::is_zero(&u.new) {
            if !RefUpdate::is_zero(&u.old) {
                out.push(f(FindingKind::RefDeletion, "push deletes this remote ref"));
            }
            continue;
        }
        if RefUpdate::is_zero(&u.old) || u.old == u.new {
            continue;
        }
        if u.refname.starts_with("refs/tags/") {
            out.push(f(
                FindingKind::TagReplacement,
                "push replaces an existing tag with a different object",
            ));
            continue;
        }
        match gitcmd::object_type(git, repo, &u.old)? {
            None => out.push(f(
                FindingKind::IncompleteScan,
                "remote's current commit is not in this repository (shallow or stale); cannot prove a fast-forward",
            )),
            Some(t) if t != "commit" => out.push(f(
                FindingKind::RefRewrite,
                "remote ref points at a non-commit object that would be replaced",
            )),
            Some(_) => {
                let r = gitcmd::run(git, repo, &["merge-base", "--is-ancestor", &u.old, &u.new])?;
                match r.status {
                    Some(0) => {}
                    Some(1) => out.push(f(
                        FindingKind::RefRewrite,
                        "non-fast-forward update: remote history would be rewritten",
                    )),
                    _ => out.push(f(
                        FindingKind::IncompleteScan,
                        "ancestry check failed; cannot prove a fast-forward",
                    )),
                }
            }
        }
    }
    Ok(out)
}
