//! FR-001, FR-002 end to end: a guarded `git push --force` driven through the
//! real `fail2commit api` stdio channel into the installed pre-push hook,
//! against a disposable bare remote and a configured password.

mod e2e_support;

use e2e_support::approval::{answer, pw};
use e2e_support::World;
use fail2commit_core::digest::Digest;
use fail2commit_core::protocol::{ClientMessage, Decision, ResultCode};
use std::path::PathBuf;

/// Repo + remote with one pushed commit, hooks installed, password set, and a
/// rewritten local `main` whose force push needs approval.
fn rewritten() -> (World, PathBuf, PathBuf, String, String) {
    let w = World::new();
    let (work, remote) = w.env.repo_with_remote("repo");
    w.env.setup();
    w.set_password("push");
    let old = w.env.head_of(&work, "HEAD");
    w.env.git(&work, &["commit", "-q", "--amend", "-m", "rewritten"]);
    let new = w.env.head_of(&work, "HEAD");
    assert_ne!(old, new);
    (w, work, remote, old, new)
}

/// Start the guarded force push and return its approval request.
fn start(w: &World, work: &std::path::Path) -> (e2e_support::ApiClient, fail2commit_core::protocol::ApprovalRequest) {
    let mut api = w.api(work, &["git", "push", "--force", "origin", "main"]);
    let req = api.approval_request();
    assert!(req.password_required, "a force push asks for the password");
    assert_eq!(req.allowed, vec![Decision::ApproveOnce]);
    assert!(!req.findings.is_empty());
    (api, req)
}

#[test]
fn approve_with_the_password_pushes() {
    let (w, work, remote, old, new) = rewritten();
    let (mut api, req) = start(&w, &work);
    api.send(&answer(&req, Decision::ApproveOnce, Some(&pw("push"))));
    let (resp, exit, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Ok, "{}
{out}", resp.message);
    assert_eq!((exit, resp.tool_exit), (0, Some(0)));
    assert_eq!(w.env.head_of(&remote, "refs/heads/main"), new);
    assert_ne!(old, new);
    assert!(!out.contains(&pw("push")), "the password must not appear in any output");
}

#[test]
fn wrong_password_is_refused_and_the_remote_keeps_its_commit() {
    let (w, work, remote, old, _) = rewritten();
    let (mut api, req) = start(&w, &work);
    api.send(&answer(&req, Decision::ApproveOnce, Some(&pw("wrong"))));
    let (resp, _, out) = api.finish();
    assert_eq!(resp.tool_exit, Some(1), "git must abort the push: {out}");
    assert_eq!(w.env.head_of(&remote, "refs/heads/main"), old);
    assert!(!out.contains(&pw("wrong")) && !out.contains(&pw("push")));
    assert!(out.contains("wrong password"), "{out}");
}

#[test]
fn cancel_aborts_the_push() {
    let (w, work, remote, old, _) = rewritten();
    let (mut api, req) = start(&w, &work);
    api.send(&ClientMessage::Cancel {
        request_id: req.request_id.clone(),
    });
    let (resp, _, out) = api.finish();
    assert_eq!(resp.tool_exit, Some(1), "{out}");
    assert_eq!(w.env.head_of(&remote, "refs/heads/main"), old);
    assert!(out.contains("canceled"), "{out}");
}

#[test]
fn an_answer_for_a_changed_tuple_is_refused() {
    let (w, work, remote, old, new) = rewritten();
    let (mut api, req) = start(&w, &work);
    let other = Digest::of(
        "git.push",
        &serde_json::json!([["refs/heads/main", old, "2".repeat(new.len())]]),
    )
    .unwrap()
    .to_string();
    assert_ne!(other, req.digest);
    let ClientMessage::ApprovalResponse(mut r) = answer(&req, Decision::ApproveOnce, Some(&pw("push"))) else {
        unreachable!()
    };
    r.digest = other;
    api.send(&ClientMessage::ApprovalResponse(r));
    let (resp, _, out) = api.finish();
    assert_eq!(resp.tool_exit, Some(1), "{out}");
    assert_eq!(w.env.head_of(&remote, "refs/heads/main"), old);
    assert!(out.contains("operation changed"), "{out}");
}

#[test]
fn unattended_force_push_fails_closed() {
    let (w, work, remote, old, _) = rewritten();
    let r = w.run(&work, &["--json", "--approver", "none", "git", "push", "--force", "origin", "main"]);
    // `fail2commit git` returns git's own status; the hook says why it stopped.
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stderr.contains("running unattended"), "{}", r.stderr);
    assert_eq!(w.env.head_of(&remote, "refs/heads/main"), old);
}
