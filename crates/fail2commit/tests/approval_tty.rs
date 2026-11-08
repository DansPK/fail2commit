//! TC-002 through a real pseudo-terminal (Unix): the terminal approver
//! (auto falls back to it when no tray runs) and the hidden-input password
//! CLI. util-linux `script` gives the child a controlling pty; stdin of the
//! child is that pty, so this also proves secrets come from the terminal.
#![cfg(unix)]

mod approval_support;

use approval_support::*;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Pty {
    child: Child,
    stdin: ChildStdin,
    out: Arc<Mutex<String>>,
    seen: usize,
    _log: tempfile::TempDir,
}

fn have_script() -> bool {
    Command::new("script")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

impl Pty {
    fn spawn(h: &Home, args: &[&str]) -> Pty {
        let quote = |s: &str| format!("'{}'", s.replace('\'', r"'\''"));
        let mut line = quote(env!("CARGO_BIN_EXE_fail2commit"));
        for a in args {
            line.push(' ');
            line.push_str(&quote(a));
        }
        let log_dir = tempfile::tempdir().unwrap();
        let log = log_dir.path().join("pty.log");
        let mut c = Command::new("script");
        c.args(["-q", "-e", "-f", "-c", &line])
            .arg(&log)
            .env("FAIL2COMMIT_HOME", h.dir.path())
            .env("TERM", "dumb")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("FAIL2COMMIT_") && k != "FAIL2COMMIT_HOME" {
                c.env_remove(k);
            }
        }
        let mut child = c.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let out = Arc::new(Mutex::new(String::new()));
        let sink = out.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        Pty {
            child,
            stdin,
            out,
            seen: 0,
            _log: log_dir,
        }
    }

    /// Wait until `needle` appears after the last match.
    fn expect(&mut self, needle: &str) -> String {
        let start = Instant::now();
        loop {
            {
                let out = self.out.lock().unwrap();
                if let Some(i) = out[self.seen..].find(needle) {
                    let chunk = out[self.seen..self.seen + i + needle.len()].to_string();
                    self.seen += i + needle.len();
                    return chunk;
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "timed out waiting for {needle:?}; transcript:\n{}",
                self.out.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Type a line once the prompt is up (and echo is already off for
    /// hidden prompts).
    fn type_line(&mut self, s: &str) {
        std::thread::sleep(Duration::from_millis(300));
        self.stdin.write_all(s.as_bytes()).unwrap();
        self.stdin.write_all(b"\r").unwrap();
        self.stdin.flush().unwrap();
    }

    fn finish(mut self) -> (i32, String) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < deadline, "pty child did not exit");
            std::thread::sleep(Duration::from_millis(50));
        };
        std::thread::sleep(Duration::from_millis(200));
        let out = self.out.lock().unwrap().clone();
        (status.code().unwrap_or(-1), out)
    }
}

fn recovery_code(text: &str) -> String {
    let re = regex_lite(text);
    re.unwrap_or_else(|| panic!("no recovery code in transcript:\n{text}"))
}

// Eight dash-separated groups of four Crockford base32 characters.
fn regex_lite(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|w| {
            let g: Vec<&str> = w.split('-').collect();
            g.len() == 8
                && g.iter().all(|p| {
                    p.len() == 4
                        && p.bytes()
                            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
                })
        })
        .map(String::from)
}

fn set_via_cli(h: &Home, p: &str) -> String {
    let mut t = Pty::spawn(h, &["password", "set"]);
    t.expect("New force-push password");
    t.type_line(p);
    t.expect("Repeat new password");
    t.type_line(p);
    let (code, out) = t.finish();
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains(p), "password echoed:\n{out}");
    recovery_code(&out)
}

#[test]
fn terminal_password_lifecycle_and_approval() {
    if !have_script() {
        eprintln!("PENDING: util-linux `script` not installed; pty test not run");
        return;
    }
    let h = home();
    let p1 = pw("tty-1");
    let code1 = set_via_cli(&h, &p1);
    assert!(fail2commit_core::approval::password::enabled(&h.paths).unwrap());

    // Auto with no tray falls back to the terminal; correct password.
    let mut t = Pty::spawn(&h, &["--approver", "auto", "password", "verify"]);
    let prompt = t.expect("\"approve\"");
    assert!(prompt.contains("approval required"), "{prompt}");
    t.type_line("approve");
    t.expect("Force-push password:");
    t.type_line(&p1);
    let (exit, out) = t.finish();
    assert_eq!(exit, 0, "{out}");
    assert!(out.contains("password verified"));
    assert!(!out.contains(&p1));

    // Wrong password denies.
    let mut t = Pty::spawn(&h, &["--approver", "terminal", "password", "verify"]);
    t.expect("\"approve\"");
    t.type_line("approve");
    t.expect("Force-push password:");
    t.type_line(&pw("wrong"));
    let (exit, out) = t.finish();
    assert_eq!(exit, 10, "{out}");
    assert!(out.contains("wrong password"));
    assert!(!out.contains(&pw("wrong")));

    // Anything but the keyword, including an empty line, cancels.
    for typed in ["", "y", "yes please"] {
        let mut t = Pty::spawn(&h, &["--approver", "terminal", "password", "verify"]);
        t.expect("\"approve\"");
        t.type_line(typed);
        let (exit, out) = t.finish();
        assert_eq!(exit, 10, "{typed:?}: {out}");
        assert!(out.contains("canceled"));
    }

    // Reset with the recovery code rotates it.
    let p2 = pw("tty-2");
    let mut t = Pty::spawn(&h, &["password", "reset"]);
    t.expect("Recovery code:");
    t.type_line(&code1.to_lowercase());
    t.expect("New force-push password");
    t.type_line(&p2);
    t.expect("Repeat new password");
    t.type_line(&p2);
    let (exit, out) = t.finish();
    assert_eq!(exit, 0, "{out}");
    let code2 = recovery_code(&out);
    assert_ne!(code1, code2);
    assert!(!out.contains(&p2) && !out.contains(&code1));

    // The old recovery code is rejected.
    let mut t = Pty::spawn(&h, &["password", "reset"]);
    t.expect("Recovery code:");
    t.type_line(&code1);
    t.expect("New force-push password");
    t.type_line(&pw("tty-3"));
    t.expect("Repeat new password");
    t.type_line(&pw("tty-3"));
    let (exit, out) = t.finish();
    assert_eq!(exit, 10, "{out}");
    assert!(out.contains("wrong recovery code"));

    // Change and disable need the current password.
    let mut t = Pty::spawn(&h, &["password", "disable"]);
    t.expect("Current force-push password:");
    t.type_line(&p1);
    assert_eq!(t.finish().0, 10);
    let mut t = Pty::spawn(&h, &["password", "disable"]);
    t.expect("Current force-push password:");
    t.type_line(&p2);
    let (exit, out) = t.finish();
    assert_eq!(exit, 0, "{out}");
    assert!(!fail2commit_core::approval::password::enabled(&h.paths).unwrap());

    let state = h.all_state_text();
    for s in [&p1, &p2, &code1, &code2] {
        assert!(!state.contains(s.as_str()));
    }
}
