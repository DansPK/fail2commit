//! TC-002 end to end over the VS Code stdio channel (`fail2commit api`):
//! the CLI child mints the request, the test plays the client.

mod approval_support;

use approval_support::*;
use fail2commit_core::digest::Digest;
use fail2commit_core::protocol::{ClientMessage, Decision, ResultCode};

const VERIFY: &[&str] = &["password", "verify"];

fn no_secret(h: &Home, text: &str, secrets: &[String]) {
    let state = h.all_state_text();
    for s in secrets {
        assert!(!text.contains(s.as_str()), "secret in process output");
        assert!(!state.contains(s.as_str()), "secret in trusted state files");
    }
}

#[test]
fn correct_password_approves_and_request_is_bound() {
    let h = home();
    let code = h.set_password(&pw("a"));
    let mut api = Api::start(&h, VERIFY);
    let req = api.approval_request();
    assert!(req.password_required);
    assert_eq!(req.allowed, vec![Decision::ApproveOnce]);
    assert_eq!(req.nonce.len(), 64);
    assert!(req.expires_at > fail2commit_core::approver::now_secs());
    api.send(&answer(&req, Decision::ApproveOnce, Some(&pw("a"))));
    let (resp, exit, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Ok, "{}", resp.message);
    assert_eq!(exit, 0);
    no_secret(&h, &out, &[pw("a"), code]);
}

#[test]
fn wrong_password_denies() {
    let h = home();
    h.set_password(&pw("a"));
    let mut api = Api::start(&h, VERIFY);
    let req = api.approval_request();
    api.send(&answer(&req, Decision::ApproveOnce, Some(&pw("wrong"))));
    let (resp, exit, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Rejected);
    assert_eq!(resp.message, "wrong password");
    assert_eq!(exit, 10);
    no_secret(&h, &out, &[pw("a"), pw("wrong")]);
}

#[test]
fn rate_limit_persists_across_processes() {
    let h = home();
    h.set_password(&pw("a"));
    for _ in 0..fail2commit_core::approval::password::FREE_ATTEMPTS {
        let mut api = Api::start(&h, VERIFY);
        let req = api.approval_request();
        api.send(&answer(&req, Decision::ApproveOnce, Some(&pw("wrong"))));
        assert_eq!(api.finish().0.message, "wrong password");
    }
    let mut api = Api::start(&h, VERIFY);
    let req = api.approval_request();
    api.send(&answer(&req, Decision::ApproveOnce, Some(&pw("a"))));
    let (resp, _, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Rejected);
    assert!(
        resp.message.contains("too many failed attempts"),
        "{}",
        resp.message
    );
    no_secret(&h, &out, &[pw("a"), pw("wrong")]);

    let st = run(h.cmd(&["--json", "password", "status"]));
    let v: serde_json::Value = serde_json::from_str(st.stdout.trim()).unwrap();
    assert_eq!(v["data"]["failed_attempts"], 3);
    assert!(v["data"]["locked_for_secs"].as_u64().unwrap() > 0);
}

#[test]
fn cancel_eof_empty_and_garbage_cancel() {
    let h = home();
    h.set_password(&pw("a"));
    type Reply = fn(&mut Api, &fail2commit_core::protocol::ApprovalRequest);
    let cases: [Reply; 5] = [
        |api, req| {
            api.send(&ClientMessage::Cancel {
                request_id: req.request_id.clone(),
            })
        },
        |api, _| api.close_stdin(),
        |api, _| api.send_raw(""),
        |api, _| api.send_raw("{\"type\":\"approve_everything\"}"),
        |api, req| {
            // Over-long line (password padded past MAX_MESSAGE_BYTES).
            let big = "x".repeat(fail2commit_core::protocol::MAX_MESSAGE_BYTES + 10);
            api.send(&answer(req, Decision::ApproveOnce, Some(&big)))
        },
    ];
    for reply in cases {
        let mut api = Api::start(&h, VERIFY);
        let req = api.approval_request();
        reply(&mut api, &req);
        let (resp, exit, _) = api.finish();
        assert_eq!(resp.code, ResultCode::Rejected);
        assert_eq!(resp.message, "approval canceled");
        assert_eq!(exit, 10);
    }
    // Cancels never count as failed password attempts.
    let st = fail2commit_core::approval::password::status(&h.paths).unwrap();
    assert_eq!(st.failed_attempts, 0);
}

#[test]
fn changed_digest_nonce_or_request_id_is_rejected() {
    let h = home();
    h.set_password(&pw("a"));
    let tuples = |new: &str| {
        Digest::of(
            "git.push",
            &serde_json::json!([["refs/heads/main", "1111", new], ["refs/tags/v1", "3", "4"]]),
        )
        .unwrap()
        .to_string()
    };
    for (field, expect) in [
        ("digest", "operation changed"),
        ("nonce", "nonce"),
        ("request_id", "request id"),
    ] {
        let mut api = Api::start(&h, VERIFY);
        let req = api.approval_request();
        let ClientMessage::ApprovalResponse(mut r) =
            answer(&req, Decision::ApproveOnce, Some(&pw("a")))
        else {
            unreachable!()
        };
        match field {
            "digest" => r.digest = tuples("2222"),
            "nonce" => r.nonce = "ab".repeat(32),
            _ => r.request_id = "0".repeat(32),
        }
        api.send(&ClientMessage::ApprovalResponse(r));
        let (resp, _, _) = api.finish();
        assert_eq!(resp.code, ResultCode::Rejected);
        assert!(resp.message.contains(expect), "{field}: {}", resp.message);
    }
    // A different multi-ref set produces a different digest.
    assert_ne!(tuples("2222"), tuples("2223"));
}

#[test]
fn decision_not_offered_is_rejected() {
    let h = home();
    h.set_password(&pw("a"));
    let mut api = Api::start(&h, VERIFY);
    let req = api.approval_request();
    api.send(&answer(&req, Decision::RunOnHostOnce, Some(&pw("a"))));
    let (resp, _, _) = api.finish();
    assert_eq!(resp.code, ResultCode::Rejected);
    assert!(resp.message.contains("not offered"));
}

#[test]
fn late_reply_after_expiry_is_not_an_approval() {
    let h = home();
    h.set_password(&pw("a"));
    h.ttl(1);
    let mut api = Api::start(&h, VERIFY);
    let req = api.approval_request();
    std::thread::sleep(std::time::Duration::from_millis(2500));
    // The channel already timed out (Cancel); a late reply changes nothing.
    api.send(&answer(&req, Decision::ApproveOnce, Some(&pw("a"))));
    let (resp, exit, _) = api.finish();
    assert_eq!(resp.code, ResultCode::Rejected);
    assert_eq!(exit, 10);
}

#[test]
fn api_cannot_pick_its_approver() {
    let h = home();
    h.set_password(&pw("a"));
    let api = Api::start(&h, &["--approver", "none", "password", "verify"]);
    let (resp, _, _) = api.finish();
    assert_eq!(resp.code, ResultCode::InvalidInput);
}
