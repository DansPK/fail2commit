//! Regression tests for the independent review of CR-009 (ER-001..ER-003) and
//! its CR-010 redesign: the password never crosses the relay, the relay is
//! single use and bounded, the token never reaches a chained hook, and only the
//! Git hook is a relay client. See docs/verify/reviews/REVIEW-2026-11-09-e2e-relay.md.

mod e2e_support;

use e2e_support::approval::{answer, pw};
use e2e_support::npm::{require_node, Pkg};
use e2e_support::npm_world::NpmWorld;
use e2e_support::{ApiClient, World};
use fail2commit_core::approval::relay;
use fail2commit_core::approver::new_request;
use fail2commit_core::digest::Digest;
use fail2commit_core::protocol::{ApprovalKind, ApprovalRequest, Decision, ResultCode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn fwd(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn request(tag: &str, password: bool) -> ApprovalRequest {
    new_request(
        ApprovalKind::Operation,
        &Digest::of("git.push", &serde_json::json!([tag])).unwrap(),
        format!("git push to origin (file:///r): {tag}"),
        vec![],
        vec![],
        60,
        password,
        vec![Decision::ApproveOnce],
    )
    .unwrap()
}

pub fn expected() -> relay::Expected {
    relay::Expected {
        remote: "origin".into(),
        url: "file:///r".into(),
        ttl_secs: 300,
    }
}

/// A relay whose host decision is `ApproveOnce`, counting how often it ran.
fn counting_relay() -> (relay::Relay, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let r = relay::start(expected(), move |_| {
        n2.fetch_add(1, Ordering::SeqCst);
        Ok(Decision::ApproveOnce)
    })
    .unwrap();
    (r, n)
}

fn addr_of(r: &relay::Relay) -> String {
    r.env_value().split_once('/').unwrap().0.to_string()
}

/// ER-001: a repository-controlled chained hook inherits no relay variable, so it
/// cannot reach the relay. Control: the fail2commit hook itself did use the relay
/// (the api client was asked) and the chained hook really ran.
#[test]
fn er001_chained_hook_has_no_relay_variable() {
    let w = World::new();
    let (work, remote) = w.env.repo_with_remote("repo");
    w.setup();
    w.set_password("push");
    let old = w.env.head_of(&work, "HEAD");
    w.env
        .git(&work, &["commit", "-q", "--amend", "-m", "rewritten"]);

    let seen = w.env.root.join("relay-seen.txt");
    let hook = work.join(".git").join("hooks").join("pre-push");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nprintf 'ran:%s' \"${{FAIL2COMMIT_APPROVAL_RELAY-UNSET}}\" > '{s}'\nexit 0\n",
            s = fwd(&seen),
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut api = w.api(&work, &["git", "push", "--force", "origin", "main"]);
    let real = api.approval_request(); // the relay path worked for the real hook
    api.send(&answer(&real, Decision::ApproveOnce, Some(&pw("push"))));
    let (resp, _, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Ok, "{out}");
    assert_ne!(w.env.head_of(&remote, "refs/heads/main"), old);
    assert_eq!(
        std::fs::read_to_string(&seen).expect("the chained hook ran"),
        "ran:UNSET",
        "the chained hook must not see the relay variable"
    );
    assert!(!out.contains(&pw("push")), "the password reached an output");
}

/// ER-001: a forged request (wrong token, so no valid MAC) gets nothing and never
/// reaches the host's approval; a valid request is answered once; a replay of it
/// is refused. A reply carries only a decision, never a password.
#[test]
fn er001_forged_and_replayed_requests_are_refused() {
    let (r, ran) = counting_relay();
    let target = r.env_value().to_string();
    let (addr, token) = target.split_once('/').unwrap();

    // Forged password-required request with the right address, wrong token.
    let forged = request("forged", true);
    assert_eq!(
        relay::forward(&forged, &format!("{addr}/{}", "0".repeat(token.len()))),
        Decision::Cancel
    );
    // Malformed junk and a silent peer.
    let mut junk = TcpStream::connect(addr).unwrap();
    writeln!(junk, "not json").unwrap();
    let _silent = TcpStream::connect(addr).unwrap();
    assert_eq!(ran.load(Ordering::SeqCst), 0, "a forgery reached the host");

    // Control: none of that used the slot; the real request is answered.
    let real = request("real", false);
    assert_eq!(relay::forward(&real, &target), Decision::ApproveOnce);
    assert_eq!(ran.load(Ordering::SeqCst), 1);

    // Replay of the same authenticated request (and a fresh one): refused.
    assert_eq!(relay::forward(&real, &target), Decision::Cancel);
    assert_eq!(
        relay::forward(&request("later", false), &target),
        Decision::Cancel
    );
    assert_eq!(ran.load(Ordering::SeqCst), 1, "the relay served twice");
}

/// The hook rejects a reply it cannot authenticate or that is for another
/// request. Control: the real relay with the same request is accepted.
#[test]
fn er001_hook_rejects_unauthenticated_or_mismatched_replies() {
    let req = request("mac", false);
    let (r, _) = counting_relay();
    assert_eq!(relay::forward(&req, r.env_value()), Decision::ApproveOnce);

    for bad_mac in [true, false] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let r2 = req.clone();
        let peer = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            let mut out = c.try_clone().unwrap();
            let mut line = String::new();
            BufReader::new(c).read_line(&mut line).unwrap();
            // An impostor host without the token: right fields, made-up MAC
            // (or, second round, a reply for another request).
            let id = if bad_mac {
                r2.request_id.clone()
            } else {
                "other".into()
            };
            let reply = serde_json::json!({
                "request_id": id, "nonce": r2.nonce, "digest": r2.digest,
                "decision": "approve_once", "mac": "0".repeat(64),
            });
            writeln!(out, "{reply}").unwrap();
        });
        assert_eq!(
            relay::forward(&req, &format!("127.0.0.1:{port}/{}", "a".repeat(64))),
            Decision::Cancel,
            "bad_mac={bad_mac}"
        );
        peer.join().unwrap();
    }
}

/// ER-002: the generic stdio approver (here `api` running npm) ignores the relay
/// variable: the api client is asked, and a listener on that address is never
/// contacted. Control: the same listener does accept a connection.
#[test]
fn er002_npm_stdio_approval_ignores_the_relay_variable() {
    require_node();
    let n = NpmWorld::new(&["advised"], true);
    n.reg
        .publish(&Pkg::new("advised", "1.0.0").file("index.js", "module.exports = 1;"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut c = n.w.cmd(&n.project);
    c.arg("api")
        .env(relay::ENV, format!("127.0.0.1:{port}/any-token"));
    let mut api = ApiClient::spawn(c, &n.project, &["npm", "install", "advised"]);
    let req = api.approval_request(); // the real client is asked
    api.send(&answer(&req, Decision::ApproveOnce, None));
    let (resp, exit, out) = api.finish();
    assert_eq!((resp.code, exit), (ResultCode::Ok, 0), "{out}");
    assert!(n.project.join("node_modules/advised/index.js").is_file());

    let diverted = listener.accept().is_ok();
    assert!(!diverted, "the approval was sent to the relay address");
    let _probe = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let t0 = Instant::now();
    while listener.accept().is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "control: listener dead"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// ER-003: silent loopback peers neither delay nor consume the hook's request.
#[test]
fn er003_silent_peers_cannot_delay_or_consume_the_request() {
    let (r, ran) = counting_relay();
    let addr = addr_of(&r);
    let _silent: Vec<TcpStream> = (0..4).map(|_| TcpStream::connect(&addr).unwrap()).collect();
    let t = Instant::now();
    assert_eq!(
        relay::forward(&request("quick", false), r.env_value()),
        Decision::ApproveOnce
    );
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

/// RR-002: silent peers are dropped after a short pre-auth deadline, and many
/// token-less connections do not end the relay; the real request is answered.
#[test]
fn tokenless_connections_neither_use_the_slot_nor_stop_the_relay() {
    let (r, ran) = counting_relay();
    let addr = addr_of(&r);
    let mut silent = TcpStream::connect(&addr).unwrap();
    silent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let t = Instant::now();
    let mut b = Vec::new();
    let _ = silent.read_to_end(&mut b);
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    let _junk: Vec<TcpStream> = (0..40)
        .filter_map(|_| TcpStream::connect(&addr).ok())
        .collect();
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(
        relay::forward(&request("late", false), r.env_value()),
        Decision::ApproveOnce
    );
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

/// The relay stops when its owner (the push) ends.
#[test]
fn relay_closes_when_the_push_ends() {
    let (r, _) = counting_relay();
    let (value, addr) = (r.env_value().to_string(), addr_of(&r));
    assert!(TcpStream::connect(&addr).is_ok(), "control: listening");
    drop(r);
    let t0 = Instant::now();
    while TcpStream::connect(&addr).is_ok() {
        assert!(t0.elapsed() < Duration::from_secs(5), "still listening");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        relay::forward(&request("after", false), &value),
        Decision::Cancel
    );
}
