//! Re-review of the CR-010 approval relay (docs/verify/REREVIEW-2026-11-09-relay.md).
//! RR-001..RR-003 are regression tests for the fixes (the reproductions were
//! inverted); RR-004 stays a reproduction of accepted residual risk (CR-011).
//! Synthetic values only.

mod e2e_support;

use e2e_support::approval::{answer, pw};
use e2e_support::World;
use fail2commit_core::approval::relay;
use fail2commit_core::approval::relay::Expected;
use fail2commit_core::approver::new_request;
use fail2commit_core::digest::Digest;
use fail2commit_core::protocol::{ApprovalKind, ApprovalRequest, Decision, ResultCode};
use sha2::{Digest as _, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn expected() -> Expected {
    Expected {
        remote: "origin".into(),
        url: "file:///r".into(),
        ttl_secs: 300,
    }
}

/// A summary that names the push the host runs.
fn ours(tag: &str) -> String {
    format!("git push to origin (file:///r): {tag}")
}

fn req(tag: &str, summary: &str, password: bool, allowed: Vec<Decision>) -> ApprovalRequest {
    new_request(
        ApprovalKind::Operation,
        &Digest::of("git.push", &serde_json::json!([tag])).unwrap(),
        summary.to_string(),
        vec![],
        vec![],
        60,
        password,
        allowed,
    )
    .unwrap()
}

/// HMAC-SHA-256, the same construction as relay.rs (the attacker knows it).
fn hmac(key: &[u8], parts: &[&[u8]]) -> String {
    let mut k = [0u8; 64];
    k[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            inner.update([0u8]);
        }
        inner.update(p);
    }
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    hex::encode(outer.finalize())
}

fn request_mac(token: &str, json: &str) -> String {
    hmac(
        token.as_bytes(),
        &[b"fail2commit-relay-request", json.as_bytes()],
    )
}

/// A token holder's authenticated request line; returns the reply line, if any.
fn send_authenticated(addr: &str, token: &str, r: &ApprovalRequest) -> Option<String> {
    let mut c = TcpStream::connect(addr).ok()?;
    let json = serde_json::to_string(r).unwrap();
    let msg = serde_json::json!({"request": json, "mac": request_mac(token, &json)});
    writeln!(c, "{msg}").ok()?;
    c.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut line = String::new();
    BufReader::new(c).read_line(&mut line).ok()?;
    (!line.is_empty()).then_some(line)
}

/// RR-001 (fixed): burning the slot with a valid, bound request leaves the
/// listener bound, so the port cannot be rebound and the real hook gets Cancel.
#[test]
fn rr001_burned_slot_keeps_the_port_and_the_hook_gets_cancel() {
    let host_ran = Arc::new(Mutex::new(0u32));
    let h = host_ran.clone();
    let r = relay::start(expected(), move |_| {
        *h.lock().unwrap() += 1;
        Ok(Decision::Cancel)
    })
    .unwrap();
    let target = r.env_value().to_string();
    let (addr, token) = target.split_once('/').unwrap();
    let (addr, token) = (addr.to_string(), token.to_string());

    // Token holder burns the slot with a request for this push.
    let burn = req("burn", &ours("burn"), false, vec![Decision::ApproveOnce]);
    assert!(send_authenticated(&addr, &token, &burn).is_some());
    assert_eq!(*host_ran.lock().unwrap(), 1);
    // The port stays taken for as long as the Relay lives.
    for _ in 0..25 {
        assert!(TcpListener::bind(&addr).is_err(), "the port was rebound");
        std::thread::sleep(Duration::from_millis(20));
    }
    // Used slot: connections are accepted and closed without a reply.
    assert!(send_authenticated(&addr, &token, &burn).is_none());

    let real = req("real", &ours("real"), true, vec![Decision::ApproveOnce]);
    assert_eq!(relay::forward(&real, &target), Decision::Cancel);
    assert_eq!(*host_ran.lock().unwrap(), 1, "the host served twice");
    drop(r);
}

/// RR-002 (fixed): token-less connections no longer end the relay (even 300 of
/// them), and the real hook is still answered afterwards.
#[test]
fn rr002_tokenless_connections_do_not_kill_the_relay() {
    let r = relay::start(expected(), |_| Ok(Decision::ApproveOnce)).unwrap();
    let addr = r.env_value().split_once('/').unwrap().0.to_string();
    let _junk: Vec<TcpStream> = (0..300)
        .filter_map(|_| TcpStream::connect(&addr).ok())
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        TcpStream::connect(&addr).is_ok(),
        "the relay stopped listening"
    );
    drop(_junk);
    std::thread::sleep(Duration::from_millis(2500)); // pre-auth deadline frees them
    let real = req("real", &ours("real"), false, vec![Decision::ApproveOnce]);
    assert_eq!(relay::forward(&real, r.env_value()), Decision::ApproveOnce);
}

/// RR-003 (fixed): a request for another remote or URL, another kind of
/// summary or extra decisions is dropped without using the slot; a matching one
/// is served with `expires_at` clamped to now plus the host's TTL.
#[test]
fn rr003_relay_binds_requests_to_the_host_push() {
    let seen: Arc<Mutex<Vec<ApprovalRequest>>> = Default::default();
    let s = seen.clone();
    let r = relay::start(expected(), move |q| {
        s.lock().unwrap().push(q.clone());
        Ok(Decision::ApproveOnce)
    })
    .unwrap();
    let (addr, token) = r.env_value().split_once('/').unwrap();
    let forged = [
        "Session expired: re-enter your force-push password".to_string(),
        "git push to evil (file:///r): x".to_string(),
        "git push to origin (https://evil.test/r): x".to_string(),
    ];
    for f in &forged {
        let q = req("x", f, true, vec![Decision::ApproveOnce]);
        assert!(send_authenticated(addr, token, &q).is_none(), "{f}");
    }
    let wide = req(
        "x",
        &ours("x"),
        false,
        vec![Decision::ApproveOnce, Decision::RunOnHostOnce],
    );
    assert!(send_authenticated(addr, token, &wide).is_none());
    assert!(
        seen.lock().unwrap().is_empty(),
        "a forged request reached the host"
    );

    // Control: the matching request is served, and its expiry is clamped.
    let mut ok = req("ok", &ours("ok"), false, vec![Decision::ApproveOnce]);
    ok.expires_at = u64::MAX / 2;
    assert!(send_authenticated(addr, token, &ok).is_some());
    let got = seen.lock().unwrap();
    assert_eq!(got.len(), 1);
    let now = fail2commit_core::approver::now_secs();
    assert!(
        got[0].expires_at <= now + 300 && got[0].expires_at > now,
        "{}",
        got[0].expires_at
    );
}

/// RR-004 (CONFIRMED): git children other than the fail2commit hook inherit the
/// token. `remote.origin.receivepack` runs before pre-push and records it.
/// Control: the push still works and the chained hook sees nothing.
#[test]
fn rr004_receive_pack_child_inherits_the_relay_token() {
    let w = World::new();
    let (work, _remote) = w.env.repo_with_remote("repo");
    w.setup();
    w.set_password("push");
    w.env
        .git(&work, &["commit", "-q", "--amend", "-m", "rewritten"]);
    let seen = w.env.root.join("rp-seen.txt");
    let wrapper = w.env.root.join("rp.sh");
    let fwd = |p: &std::path::Path| p.to_string_lossy().replace('\\', "/");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf '%s' \"${{FAIL2COMMIT_APPROVAL_RELAY-UNSET}}\" > '{}'\nexec git-receive-pack \"$@\"\n",
            fwd(&seen)
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let rp = format!("sh '{}'", fwd(&wrapper));
    w.env
        .git(&work, &["config", "remote.origin.receivepack", &rp]);

    let mut api = w.api(&work, &["git", "push", "--force", "origin", "main"]);
    let real = api.approval_request();
    api.send(&answer(&real, Decision::ApproveOnce, Some(&pw("push"))));
    let (resp, _, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Ok, "{out}");
    let v = std::fs::read_to_string(&seen).expect("receive-pack wrapper ran");
    assert!(
        v.starts_with("127.0.0.1:") && v.contains('/'),
        "the git child did not see the token: {v:?}"
    );
}
