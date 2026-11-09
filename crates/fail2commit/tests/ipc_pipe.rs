//! TC-009 pipe tests (FR-009): same-user round trip with a scripted UI seam,
//! request bounds and session validation, DACL contents, single instance and
//! the tray-closed fallback. Windows only; the pipe is disposable and named
//! uniquely per test.
#![cfg(windows)]

use fail2commit_core::approver::{new_request, now_secs, validate_response, Approver};
use fail2commit_core::digest::{random_hex32, Digest};
use fail2commit_core::ipc::pipe::{probe, PipeServer, Prompter, Reply};
use fail2commit_core::ipc::winsec;
use fail2commit_core::protocol::{
    ApprovalKind, ApprovalRequest, ClientMessage, Decision, ServerMessage, MAX_MESSAGE_BYTES,
};
use fail2commit_core::ResultCode;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Script {
    calls: AtomicUsize,
    seen: Mutex<Vec<ApprovalRequest>>,
    reply: fn() -> Reply,
}

impl Script {
    fn new(reply: fn() -> Reply) -> Arc<Script> {
        Arc::new(Script {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(vec![]),
            reply,
        })
    }
}

impl Prompter for Script {
    fn prompt(&self, req: ApprovalRequest) -> Reply {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(req);
        (self.reply)()
    }
}

fn unique_name() -> String {
    format!(r"\\.\pipe\fail2commit-test-{}", random_hex32().unwrap())
}

fn request(password: bool, allowed: Vec<Decision>) -> ApprovalRequest {
    let d = Digest::of("test", &["refs/heads/main", "a", "b"]).unwrap();
    new_request(
        ApprovalKind::Operation,
        &d,
        "git push --force origin main",
        vec!["refs/heads/main a..b".into()],
        vec![],
        60,
        password,
        allowed,
    )
    .unwrap()
}

fn approver_for(name: &str) -> Box<dyn Approver> {
    probe(name).expect("pipe is listening")
}

#[test]
fn round_trip_approve_once_with_password() {
    let name = unique_name();
    let ui = Script::new(|| Reply::Decide {
        decision: Decision::ApproveOnce,
        password: Some(["pass", "word", "-synthetic"].concat()),
    });
    let server = PipeServer::start(&name, ui.clone()).unwrap();
    let req = request(true, vec![Decision::ApproveOnce]);
    let resp = approver_for(&name).ask(&req).unwrap();
    assert_eq!(
        validate_response(&req, &resp, now_secs()).unwrap(),
        Decision::ApproveOnce
    );
    assert_eq!(resp.password.as_deref(), Some("password-synthetic"));
    assert_eq!(ui.seen.lock().unwrap()[0], req);
    server.shutdown();
}

#[test]
fn cancel_and_unoffered_decision_both_cancel() {
    let name = unique_name();
    let server = PipeServer::start(&name, Script::new(|| Reply::Cancel)).unwrap();
    let req = request(false, vec![Decision::ApproveOnce]);
    let resp = approver_for(&name).ask(&req).unwrap();
    assert_eq!(resp.decision, Decision::Cancel);
    server.shutdown();

    // UI answers RunOnHostOnce but the request never offered it.
    let name = unique_name();
    let server = PipeServer::start(
        &name,
        Script::new(|| Reply::Decide {
            decision: Decision::RunOnHostOnce,
            password: None,
        }),
    )
    .unwrap();
    let resp = approver_for(&name).ask(&req).unwrap();
    assert_eq!(resp.decision, Decision::Cancel);
    server.shutdown();
}

/// Send raw bytes; return what the server wrote back before closing.
fn raw_exchange(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(name)
        .unwrap();
    // The server may close while we are still writing an oversized payload.
    let _ = f.write_all(bytes);
    let mut out = Vec::new();
    let _ = f.read_to_end(&mut out);
    out
}

#[test]
fn oversized_and_malformed_requests_never_reach_the_ui() {
    let name = unique_name();
    let ui = Script::new(|| Reply::Cancel);
    let server = PipeServer::start(&name, ui.clone()).unwrap();

    let big = vec![b'a'; MAX_MESSAGE_BYTES + 10];
    assert!(raw_exchange(&name, &big).is_empty());
    assert!(raw_exchange(&name, b"{not json}\n").is_empty());
    // A client message is not an approval request.
    let wrong = serde_json::to_string(&ClientMessage::Cancel {
        request_id: "x".into(),
    })
    .unwrap();
    assert!(raw_exchange(&name, format!("{wrong}\n").as_bytes()).is_empty());
    assert_eq!(ui.calls.load(Ordering::SeqCst), 0);
    server.shutdown();
}

#[test]
fn invalid_fields_and_sessions_are_rejected() {
    let name = unique_name();
    let ui = Script::new(|| Reply::Cancel);
    let server = PipeServer::start(&name, ui.clone()).unwrap();

    let mut cases: Vec<ApprovalRequest> = Vec::new();
    let base = request(false, vec![Decision::ApproveOnce]);
    let mut r = base.clone();
    r.session = "evil session \u{1b}[2J".into();
    cases.push(r);
    let mut r = base.clone();
    r.session = String::new();
    cases.push(r);
    let mut r = base.clone();
    r.expires_at = now_secs().saturating_sub(5);
    cases.push(r);
    let mut r = base.clone();
    r.details = vec!["x".repeat(5000)];
    cases.push(r);
    let mut r = base.clone();
    r.version = 99;
    cases.push(r);
    for r in cases {
        let line = serde_json::to_string(&ServerMessage::ApprovalRequest(r)).unwrap();
        assert!(raw_exchange(&name, format!("{line}\n").as_bytes()).is_empty());
    }
    assert_eq!(ui.calls.load(Ordering::SeqCst), 0);

    // The client side reports a closed pipe as unavailable/rejected, never approval.
    let mut bad = base.clone();
    bad.session = "bad session".into();
    let err = approver_for(&name).ask(&bad).unwrap_err();
    assert!(matches!(
        err.code,
        ResultCode::ApprovalUnavailable | ResultCode::Rejected
    ));
    server.shutdown();
}

#[test]
fn reply_for_another_request_is_refused_by_the_client() {
    // A hostile same-user server answering with the wrong nonce must not
    // yield an approval: the client validates the binding itself.
    let req = request(false, vec![Decision::ApproveOnce]);
    let mut resp = fail2commit_core::approver::Scripted {
        decision: Decision::ApproveOnce,
        password: None,
    }
    .ask(&req)
    .unwrap();
    resp.nonce = "00".repeat(32);
    assert!(validate_response(&req, &resp, now_secs()).is_err());
}

#[test]
fn dacl_allows_only_current_user_and_denies_app_packages() {
    let name = unique_name();
    let server = PipeServer::start(&name, Script::new(|| Reply::Cancel)).unwrap();
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&name)
        .unwrap();
    let entries = winsec::dacl_entries(&f).unwrap();
    let me = winsec::sid_string(&winsec::current_user_sid().unwrap());
    let shape: Vec<(bool, String)> = entries.iter().map(|(a, s, _)| (*a, s.clone())).collect();
    assert_eq!(
        shape,
        vec![
            (false, winsec::ALL_APP_PACKAGES.to_string()),
            (false, winsec::ALL_RESTRICTED_APP_PACKAGES.to_string()),
            (true, me),
        ]
    );
    drop(f);
    server.shutdown();
}

#[test]
fn second_server_on_the_same_name_is_refused() {
    let name = unique_name();
    let server = PipeServer::start(&name, Script::new(|| Reply::Cancel)).unwrap();
    // FILE_FLAG_FIRST_PIPE_INSTANCE: squatting / a second tray fails.
    assert!(PipeServer::start(&name, Script::new(|| Reply::Cancel)).is_err());
    server.shutdown();
}

#[test]
fn tray_closed_means_no_approver() {
    let name = unique_name();
    assert!(probe(&name).is_none());
    // After a tray exits the pipe disappears and the probe turns None again.
    let server = PipeServer::start(&name, Script::new(|| Reply::Cancel)).unwrap();
    assert!(probe(&name).is_some());
    server.shutdown();
    // Instances still held by in-flight handlers are gone once threads end.
    let mut gone = false;
    for _ in 0..50 {
        if probe(&name).is_none() {
            gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(gone, "pipe still present after shutdown");

    // The real per-user pipe: None unless a real tray happens to be running.
    let real = winsec::pipe_name().unwrap();
    if probe(&real).is_none() {
        assert!(fail2commit_core::ipc::tray_approver().is_none());
    }
}
