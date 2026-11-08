//! FR-002, FR-004, FR-006 end to end: an npm install whose graph has an
//! advisory finding (offline OSV stub through the trusted `advisories.osv_url`
//! setting) asks on the real `fail2commit api` stdio channel; the test client
//! plays approve, cancel and a changed plan. Unattended runs fail closed.

mod e2e_support;

use e2e_support::approval::answer;
use e2e_support::npm::{assert_no_scratch, require_node, snapshot, Pkg};
use e2e_support::npm_world::NpmWorld;
use fail2commit_core::protocol::{ClientMessage, Decision, FindingKind, ResultCode};

const ADVISED: &[&str] = &["advised"];

fn world() -> NpmWorld {
    let n = NpmWorld::new(ADVISED, true);
    n.reg
        .publish(&Pkg::new("advised", "1.0.0").file("index.js", "module.exports = 1;"));
    n
}

#[test]
fn approve_installs_exactly_the_approved_plan() {
    require_node();
    let n = world();
    let mut api = n.w.api(&n.project, &["npm", "install", "advised"]);
    let req = api.approval_request();
    assert!(
        req.findings.iter().any(|f| f.kind == FindingKind::Advisory),
        "{:?}",
        req.findings
    );
    assert_eq!(req.allowed, vec![Decision::ApproveOnce]);
    assert_eq!(req.digest.len(), 64);
    api.send(&answer(&req, Decision::ApproveOnce, None));
    let (resp, exit, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Ok, "{out}");
    assert_eq!(exit, 0);
    assert!(n.project.join("node_modules/advised/index.js").is_file());
    assert_eq!(resp.data["digest"], req.digest, "the applied plan is the approved plan");
    assert_no_scratch(&n.project);
}

#[test]
fn cancel_changes_nothing() {
    require_node();
    let n = world();
    let before = snapshot(&n.project);
    let mut api = n.w.api(&n.project, &["npm", "install", "advised"]);
    let req = api.approval_request();
    api.send(&ClientMessage::Cancel {
        request_id: req.request_id.clone(),
    });
    let (resp, exit, _) = api.finish();
    assert_eq!(resp.code, ResultCode::Rejected);
    assert_eq!(exit, 10);
    assert_eq!(snapshot(&n.project), before);
    assert_no_scratch(&n.project);
}

#[test]
fn changed_plan_digest_is_rejected() {
    require_node();
    let n = world();
    let before = snapshot(&n.project);
    let mut api = n.w.api(&n.project, &["npm", "install", "advised"]);
    let req = api.approval_request();
    let ClientMessage::ApprovalResponse(mut r) = answer(&req, Decision::ApproveOnce, None) else {
        unreachable!()
    };
    r.digest = "0".repeat(64);
    api.send(&ClientMessage::ApprovalResponse(r));
    let (resp, exit, _) = api.finish();
    assert_eq!(resp.code, ResultCode::Rejected);
    assert!(resp.message.contains("operation changed"), "{}", resp.message);
    assert_eq!(exit, 10);
    assert_eq!(snapshot(&n.project), before);
}

#[test]
fn unattended_fails_closed_with_exit_11() {
    require_node();
    let n = world();
    let before = snapshot(&n.project);
    let r = n.w.run(&n.project, &["--json", "--approver", "none", "npm", "install", "advised"]);
    assert_eq!(r.code, 11, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["code"], "approval_unavailable");
    assert_eq!(snapshot(&n.project), before);
    assert_no_scratch(&n.project);
}
