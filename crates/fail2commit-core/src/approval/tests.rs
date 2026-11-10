//! TC-002 unit coverage (FR-002): policy half of `approve` with scripted
//! channels, password state, rate limits, recovery, replay, concurrency.

use super::*;
use crate::approver::{new_request, Scripted};
use crate::digest::Digest;
use crate::protocol::{ApprovalKind, ApprovalResponse, ResultCode};
use std::sync::Arc;

fn pw(tag: &str) -> String {
    // Synthetic secrets are built at runtime.
    format!("{}-{}-{}", "synthetic", "pw", tag)
}

struct Home {
    _dir: tempfile::TempDir,
    paths: TrustedPaths,
    settings: Settings,
}

fn home() -> Home {
    let dir = tempfile::tempdir().unwrap();
    let paths = TrustedPaths::under(dir.path());
    Home {
        _dir: dir,
        paths,
        settings: Settings::default(),
    }
}

impl Home {
    fn ctx(&self) -> ApprovalCtx<'_> {
        ApprovalCtx {
            paths: &self.paths,
            settings: &self.settings,
            choice: ApproverChoice::Stdio,
        }
    }
}

fn tuples(new_main: &str) -> Digest {
    Digest::of(
        "git.push",
        &serde_json::json!([
            ["refs/heads/main", "1111", new_main],
            ["refs/tags/v1", "3333", "4444"],
        ]),
    )
    .unwrap()
}

fn request(password_required: bool, ttl: u64) -> ApprovalRequest {
    new_request(
        ApprovalKind::Operation,
        &tuples("2222"),
        "git push --force origin main v1",
        vec!["refs/heads/main 1111 -> 2222".into()],
        vec![],
        ttl,
        password_required,
        vec![Decision::ApproveOnce],
    )
    .unwrap()
}

fn says(decision: Decision, password: Option<&str>) -> Scripted {
    Scripted {
        decision,
        password: password.map(String::from),
    }
}

/// Channel returning a fixed, possibly tampered, response.
struct Fixed(ApprovalResponse);
impl Approver for Fixed {
    fn name(&self) -> &'static str {
        "fixed"
    }
    fn ask(&self, _: &ApprovalRequest) -> crate::Result<ApprovalResponse> {
        Ok(self.0.clone())
    }
}

/// Channel that runs `f` while "the user is looking at the prompt".
struct During<F: Fn()>(F, Scripted);
impl<F: Fn()> Approver for During<F> {
    fn name(&self) -> &'static str {
        "during"
    }
    fn ask(&self, req: &ApprovalRequest) -> crate::Result<ApprovalResponse> {
        (self.0)();
        self.1.ask(req)
    }
}

struct Failing(ResultCode);
impl Approver for Failing {
    fn name(&self) -> &'static str {
        "failing"
    }
    fn ask(&self, _: &ApprovalRequest) -> crate::Result<ApprovalResponse> {
        Err(crate::Error::new(self.0, "channel broke"))
    }
}

fn code(r: crate::Result<Decision>) -> ResultCode {
    r.unwrap_err().code
}

fn msg(r: crate::Result<Decision>) -> String {
    r.unwrap_err().message
}

#[test]
fn approves_without_password_and_cancel_is_default() {
    let h = home();
    let r = request(false, 60);
    assert_eq!(
        approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, None)).unwrap(),
        Decision::ApproveOnce
    );
    let r = request(false, 60);
    assert_eq!(
        approve_with(&h.ctx(), &r, &says(Decision::Cancel, None)).unwrap(),
        Decision::Cancel
    );
    // A broken channel cancels; it never approves.
    let r = request(false, 60);
    assert_eq!(
        approve_with(&h.ctx(), &r, &Failing(ResultCode::Internal)).unwrap(),
        Decision::Cancel
    );
    let r = request(false, 60);
    assert_eq!(
        code(approve_with(
            &h.ctx(),
            &r,
            &Failing(ResultCode::ApprovalUnavailable)
        )),
        ResultCode::ApprovalUnavailable
    );
}

#[test]
fn unattended_and_missing_tray_fail_closed() {
    let h = home();
    for choice in [ApproverChoice::None, ApproverChoice::Tray] {
        let ctx = ApprovalCtx { choice, ..h.ctx() };
        assert_eq!(
            code(approve(&ctx, &request(false, 60))),
            ResultCode::ApprovalUnavailable
        );
    }
}

#[test]
fn wrong_password_denies_and_right_one_approves() {
    let h = home();
    password::set(&h.paths, &pw("a")).unwrap();
    assert!(password_required(&h.paths).unwrap());

    let r = request(true, 60);
    let e = approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, Some(&pw("x"))));
    assert_eq!(msg(e), "wrong password");

    let r = request(true, 60);
    let e = approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, None));
    assert!(msg(e).contains("password required"));

    let r = request(true, 60);
    assert_eq!(
        approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, Some(&pw("a")))).unwrap(),
        Decision::ApproveOnce
    );
}

#[test]
fn rate_limit_engages_persists_and_expires() {
    let h = home();
    password::set(&h.paths, &pw("a")).unwrap();
    for _ in 0..password::FREE_ATTEMPTS {
        let r = request(true, 60);
        let e = approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, Some(&pw("x"))));
        assert_eq!(msg(e), "wrong password");
    }
    // Locked out: even the right password is refused, and the lock is in
    // the state file (shared by every process).
    let r = request(true, 60);
    let e = approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, Some(&pw("a"))));
    assert!(msg(e).contains("too many failed attempts"));
    let st = password::status(&h.paths).unwrap();
    assert_eq!(st.failed_attempts, password::FREE_ATTEMPTS);
    assert!(st.locked_for_secs > 0 && st.locked_for_secs <= password::BASE_LOCKOUT_SECS);
    assert!(password::change(&h.paths, &pw("a"), &pw("b")).is_err());
    assert!(password::disable(&h.paths, &pw("a")).is_err());

    // Once the backoff elapses the right password works and resets it.
    password::force_lock(&h.paths, 0);
    let r = request(true, 60);
    assert_eq!(
        approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, Some(&pw("a")))).unwrap(),
        Decision::ApproveOnce
    );
    assert_eq!(password::status(&h.paths).unwrap().failed_attempts, 0);
}

#[test]
fn backoff_doubles_and_caps() {
    use password::{BASE_LOCKOUT_SECS, FREE_ATTEMPTS, MAX_LOCKOUT_SECS};
    let h = home();
    password::set(&h.paths, &pw("a")).unwrap();
    let mut last = 0;
    for i in 0..(FREE_ATTEMPTS + 8) {
        password::force_lock(&h.paths, 0);
        assert!(password::disable(&h.paths, &pw("x")).is_err());
        let st = password::status(&h.paths).unwrap();
        assert_eq!(st.failed_attempts, i + 1);
        if i + 1 >= FREE_ATTEMPTS {
            assert!(st.locked_for_secs >= last.min(MAX_LOCKOUT_SECS - 1));
            assert!(st.locked_for_secs <= MAX_LOCKOUT_SECS);
            last = st.locked_for_secs;
        }
    }
    assert!(last >= MAX_LOCKOUT_SECS - 1 && BASE_LOCKOUT_SECS < MAX_LOCKOUT_SECS);
}

#[test]
fn reset_rotates_recovery_code_and_invalidates_pending() {
    let h = home();
    let first = password::set(&h.paths, &pw("a")).unwrap();
    let code1 = first.expose().to_string();
    assert_eq!(code1.len(), 39, "32 chars in 8 groups of 4");
    assert!(!format!("{first:?}").contains(&code1));

    // A request minted (password_required observed) before the reset ...
    assert!(password_required(&h.paths).unwrap());
    let before = request(true, 60);

    let second = password::reset(&h.paths, &code1.to_lowercase(), &pw("b")).unwrap();
    let code2 = second.expose().to_string();
    assert_ne!(code1, code2);

    // ... cannot be approved after it, even with the new password.
    let e = approve_with(
        &h.ctx(),
        &before,
        &says(Decision::ApproveOnce, Some(&pw("b"))),
    );
    assert!(msg(e).contains("password state changed"));

    // The old recovery code is rejected; the new one works.
    let e = password::reset(&h.paths, &code1, &pw("c")).unwrap_err();
    assert_eq!(e.message, "wrong recovery code");
    password::reset(&h.paths, &code2, &pw("c")).unwrap();
    assert!(password::change(&h.paths, &pw("b"), &pw("d")).is_err());
}

#[test]
fn reset_during_prompt_invalidates_the_pending_request() {
    let h = home();
    let code = password::set(&h.paths, &pw("a")).unwrap();
    let code = code.expose().to_string();
    let paths = h.paths.clone();
    let r = request(true, 60);
    let ch = During(
        move || {
            password::reset(&paths, &code, &pw("b")).unwrap();
        },
        says(Decision::ApproveOnce, Some(&pw("b"))),
    );
    let e = approve_with(&h.ctx(), &r, &ch);
    assert!(msg(e).contains("password state changed"));
}

#[test]
fn change_and_disable_need_current_password() {
    let h = home();
    password::set(&h.paths, &pw("a")).unwrap();
    assert!(password::set(&h.paths, &pw("z")).is_err(), "set twice");
    assert_eq!(
        password::change(&h.paths, &pw("x"), &pw("b"))
            .unwrap_err()
            .message,
        "wrong password"
    );
    password::change(&h.paths, &pw("a"), &pw("b")).unwrap();
    assert!(password::disable(&h.paths, &pw("a")).is_err());
    password::disable(&h.paths, &pw("b")).unwrap();
    assert!(!password_required(&h.paths).unwrap());
    assert!(password::change(&h.paths, &pw("b"), &pw("c")).is_err());
    assert!(password::set(&h.paths, "short").is_err());
}

#[test]
fn recovery_code_normalization() {
    let c = password::set(&home().paths, &pw("a")).unwrap();
    let canon = password::normalize_for_test(c.expose()).unwrap();
    assert_eq!(canon.len(), 32);
    let sloppy = format!(" {} ", c.expose().to_lowercase().replace('-', " "));
    assert_eq!(password::normalize_for_test(&sloppy).unwrap(), canon);
    assert_eq!(password::normalize_for_test("0OIL").as_deref(), None);
    assert_eq!(
        password::normalize_for_test(&"OIL1".repeat(8)).unwrap(),
        "0111".repeat(8)
    );
    assert!(password::normalize_for_test(&"U".repeat(32)).is_none());
}

#[test]
fn changed_multi_ref_tuples_and_mismatches_are_rejected() {
    let h = home();
    let base = request(false, 60);
    let ok = says(Decision::ApproveOnce, None).ask(&base).unwrap();

    let mut changed = ok.clone();
    changed.digest = tuples("5555").to_string();
    let e = approve_with(&h.ctx(), &base, &Fixed(changed));
    assert!(msg(e).contains("operation changed"));

    let r = request(false, 60);
    let mut other_nonce = says(Decision::ApproveOnce, None).ask(&r).unwrap();
    other_nonce.nonce = "ab".repeat(32);
    assert!(msg(approve_with(&h.ctx(), &r, &Fixed(other_nonce))).contains("nonce"));

    let r = request(false, 60);
    let mut not_offered = says(Decision::ApproveOnce, None).ask(&r).unwrap();
    not_offered.decision = Decision::RunOnHostOnce;
    assert!(msg(approve_with(&h.ctx(), &r, &Fixed(not_offered))).contains("not offered"));

    // A reply for request A cannot answer request B.
    let r = request(false, 60);
    let e = approve_with(&h.ctx(), &r, &Fixed(ok));
    assert!(msg(e).contains("request id"));
}

#[test]
fn expiry_before_and_during_prompt() {
    let h = home();
    let mut r = request(false, 60);
    r.expires_at = crate::approver::now_secs() - 1;
    assert!(msg(approve_with(
        &h.ctx(),
        &r,
        &says(Decision::ApproveOnce, None)
    ))
    .contains("expired"));

    let r = request(false, 1);
    let slow = During(
        || std::thread::sleep(std::time::Duration::from_millis(2100)),
        says(Decision::ApproveOnce, None),
    );
    assert!(msg(approve_with(&h.ctx(), &r, &slow)).contains("expired"));
}

#[test]
fn foreign_session_and_reprompt_are_rejected() {
    let h = home();
    let mut r = request(false, 60);
    r.session = "someone-else".into();
    assert!(msg(approve_with(
        &h.ctx(),
        &r,
        &says(Decision::ApproveOnce, None)
    ))
    .contains("session"));

    let r = request(false, 60);
    approve_with(&h.ctx(), &r, &says(Decision::Cancel, None)).unwrap();
    assert!(msg(approve_with(
        &h.ctx(),
        &r,
        &says(Decision::ApproveOnce, None)
    ))
    .contains("already answered"));
}

#[test]
fn replayed_reply_is_rejected_across_processes() {
    let h = home();
    let r = request(false, 60);
    // Another process (e.g. a tray answering twice) consumed this nonce.
    replay::consume(&h.paths, &r.nonce, r.expires_at).unwrap();
    assert!(msg(approve_with(
        &h.ctx(),
        &r,
        &says(Decision::ApproveOnce, None)
    ))
    .contains("already answered"));
    assert!(replay::consume(&h.paths, &r.nonce, r.expires_at).is_err());
    // Expired entries are pruned.
    let old = "cd".repeat(32);
    replay::consume(&h.paths, &old, 1).unwrap();
    replay::consume(&h.paths, &"ef".repeat(32), u64::MAX).unwrap();
    replay::ensure_unused(&h.paths, &old).unwrap();
}

#[test]
fn concurrent_replies_and_attempts_serialize() {
    let h = Arc::new(home());
    let nonce = "12".repeat(32);
    let wins: usize = (0..8)
        .map(|_| {
            let h = h.clone();
            let n = nonce.clone();
            std::thread::spawn(move || replay::consume(&h.paths, &n, u64::MAX).is_ok())
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().unwrap() as usize)
        .sum();
    assert_eq!(wins, 1, "exactly one consumer of a nonce");

    password::set(&h.paths, &pw("a")).unwrap();
    let results: Vec<String> = (0..8)
        .map(|_| {
            let h = h.clone();
            std::thread::spawn(move || password::disable(&h.paths, &pw("x")).unwrap_err().message)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect();
    let wrong = results.iter().filter(|m| *m == "wrong password").count();
    assert_eq!(wrong, password::FREE_ATTEMPTS as usize, "{results:?}");
    assert_eq!(
        password::status(&h.paths).unwrap().failed_attempts,
        password::FREE_ATTEMPTS
    );
}

#[test]
fn state_files_hold_no_plaintext_secrets() {
    let h = home();
    let code = password::set(&h.paths, &pw("a")).unwrap();
    let code = code.expose().to_string();
    let r = request(true, 60);
    let _ = approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, Some(&pw("x"))));
    let canon = password::normalize_for_test(&code).unwrap();
    for entry in walk(&h.paths.state_dir) {
        let text = String::from_utf8_lossy(&std::fs::read(&entry).unwrap()).to_string();
        for needle in [pw("a"), pw("x"), code.clone(), canon.clone()] {
            assert!(
                !text.contains(&needle),
                "{} leaks a secret",
                entry.display()
            );
        }
    }
    let state = std::fs::read_to_string(h.paths.state_dir.join("password.json")).unwrap();
    assert!(state.contains("\"argon2id\"") && state.contains("\"m_kib\""));
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn damaged_state_fails_closed() {
    let h = home();
    std::fs::create_dir_all(&h.paths.state_dir).unwrap();
    std::fs::write(h.paths.state_dir.join("password.json"), b"{not json").unwrap();
    assert_eq!(
        password_required(&h.paths).unwrap_err().code,
        ResultCode::InvalidInput
    );
    let r = request(true, 60);
    assert!(approve_with(&h.ctx(), &r, &says(Decision::ApproveOnce, Some(&pw("a")))).is_err());
}

#[test]
fn password_required_without_password_set_is_rejected() {
    let h = home();
    let r = request(true, 60);
    assert!(msg(approve_with(
        &h.ctx(),
        &r,
        &says(Decision::ApproveOnce, Some(&pw("a")))
    ))
    .contains("none is set"));
}

#[test]
fn terminal_rendering_neutralizes_escapes() {
    let mut r = request(false, 60);
    r.summary = format!("push {}[2J{}evil", '\u{1b}', '\u{202e}');
    r.details = vec!["https://user:tok@example.test/r.git".into()];
    let text = channels::render(&r);
    assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));
    assert!(text.contains("\\u{1b}") && !text.contains("tok@"));
    assert!(text.contains("\"approve\""));
}

#[test]
fn terminal_rendering_shows_the_finding_location_sanitized() {
    use crate::protocol::{Finding, FindingAction, FindingKind};
    let mut r = request(false, 60);
    r.findings = vec![Finding::new(
        FindingKind::SuspiciousCode,
        FindingAction::Approve,
        "npm.code",
        "runs hidden code",
    )
    .target("npm:p@1.0.0")
    .location(format!("lib/{}[31mx.js:7", '\u{1b}'))];
    let text = channels::render(&r);
    assert!(text.contains("[npm:p@1.0.0] at lib/"), "{text}");
    assert!(text.contains("x.js:7: runs hidden code"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
}
