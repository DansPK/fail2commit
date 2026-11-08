//! `server pre-receive`: Git hook that protects configured refs.

use super::approvals::{consume, updates_digest, valid_actor, TOKEN_PREFIX};
use super::config::ServerHome;
use crate::git::RefUpdate;
use crate::protocol::{Finding, FindingAction as A, FindingKind as K};
use crate::settings::Limits;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_UPDATES: usize = 4096;
const MAX_PUSH_OPTIONS: usize = 32;
const MAX_OPTION_BYTES: usize = 1024;
const OPTION_KEY: &str = "f2c-approval=";
const SRC: &str = "server.pre-receive";

pub struct ReceiveInput {
    pub updates: Vec<RefUpdate>,
    /// Authenticated actor from the transport (`FAIL2COMMIT_ACTOR`).
    pub actor: Option<String>,
    pub push_options: Vec<String>,
    pub git_dir: PathBuf,
}

impl ReceiveInput {
    /// Read the hook's stdin and environment. Git runs hooks with the
    /// quarantine variables set; they are inherited by every git child.
    pub fn from_hook_env(stdin: impl Read) -> crate::Result<Self> {
        let updates = parse_updates(stdin)?;
        let git_dir = PathBuf::from(std::env::var_os("GIT_DIR").unwrap_or(".".into()));
        let count: usize = match std::env::var("GIT_PUSH_OPTION_COUNT") {
            Ok(c) => c
                .parse()
                .map_err(|_| crate::Error::invalid("bad GIT_PUSH_OPTION_COUNT"))?,
            Err(_) => 0,
        };
        if count > MAX_PUSH_OPTIONS {
            return Err(crate::Error::rejected("too many push options"));
        }
        let mut push_options = Vec::new();
        for i in 0..count {
            let v = std::env::var(format!("GIT_PUSH_OPTION_{i}"))
                .map_err(|_| crate::Error::invalid("unreadable push option"))?;
            if v.len() > MAX_OPTION_BYTES {
                return Err(crate::Error::rejected("push option too long"));
            }
            push_options.push(v);
        }
        let actor = std::env::var("FAIL2COMMIT_ACTOR").ok();
        Ok(ReceiveInput {
            updates,
            actor,
            push_options,
            git_dir,
        })
    }
}

fn valid_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse `<old> <new> <ref>` lines, bounded; anything odd is an error.
pub fn parse_updates(r: impl Read) -> crate::Result<Vec<RefUpdate>> {
    let mut buf = String::new();
    r.take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut buf)
        .map_err(|e| crate::Error::invalid(format!("cannot read ref updates: {e}")))?;
    if buf.len() as u64 > MAX_INPUT_BYTES {
        return Err(crate::Error::rejected("ref update list too large"));
    }
    let mut out: Vec<RefUpdate> = Vec::new();
    for line in buf.lines().filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split(' ').collect();
        let [old, new, refname] = parts[..] else {
            return Err(crate::Error::invalid("malformed ref update line"));
        };
        if !valid_oid(old)
            || !valid_oid(new)
            || !refname.starts_with("refs/")
            || refname.chars().any(char::is_control)
        {
            return Err(crate::Error::invalid("malformed ref update line"));
        }
        if out.iter().any(|u| u.refname == refname) {
            return Err(crate::Error::invalid("duplicate ref in update list"));
        }
        out.push(RefUpdate {
            refname: refname.into(),
            old: old.into(),
            new: new.into(),
        });
        if out.len() > MAX_UPDATES {
            return Err(crate::Error::rejected("too many ref updates"));
        }
    }
    if out.is_empty() {
        return Err(crate::Error::invalid("no ref updates received"));
    }
    Ok(out)
}

/// Stable repository identity: digest of the canonical git directory path.
pub fn repo_id(git_dir: &Path) -> crate::Result<String> {
    let p = git_dir
        .canonicalize()
        .map_err(|e| crate::Error::invalid(format!("repository unusable: {e}")))?;
    let d = crate::digest::Digest::of("server.repo", &p.to_string_lossy())?;
    Ok(d.as_hex()[..32].to_string())
}

/// `Ok(true)` fast-forward, `Ok(false)` rewrite, `Err` unknown (missing
/// objects, not a commit): the caller denies.
fn is_ancestor(git: &Path, repo: &Path, old: &str, new: &str) -> Result<bool, String> {
    // Hardened env (no replace refs etc.), shared with the scanner.
    let out = crate::git::gitcmd::command(git, repo)
        .args(["merge-base", "--is-ancestor", old, new])
        .output()
        .map_err(|e| format!("git failed to start: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err("ancestry could not be determined (missing or invalid objects)".into()),
    }
}

fn finding(kind: K, action: A, update: &RefUpdate, why: &str) -> Finding {
    Finding::new(kind, action, SRC, why).target(update.refname.clone())
}

/// Decide a push. `Ok(())` lets Git apply it; every error denies.
pub fn pre_receive(
    home: &ServerHome,
    git: &Path,
    limits: &Limits,
    input: &ReceiveInput,
) -> crate::Result<()> {
    if let Ok(g) = input.git_dir.canonicalize() {
        if home.dir().starts_with(&g) {
            return Err(crate::Error::invalid(
                "server state is inside the repository; refusing",
            ));
        }
    }
    let cfg = home.load_config()?;
    let protected: Vec<&RefUpdate> = input
        .updates
        .iter()
        .filter(|u| cfg.is_protected(&u.refname))
        .collect();
    if protected.is_empty() {
        return Ok(());
    }

    let mut hard = Vec::new();
    let mut needs_approval = Vec::new();
    for u in &protected {
        if RefUpdate::is_zero(&u.new) {
            needs_approval.push(finding(
                K::RefDeletion,
                A::Approve,
                u,
                "deletion of a protected ref",
            ));
        } else if RefUpdate::is_zero(&u.old) {
            // creation is not a rewrite
        } else if u.refname.starts_with("refs/tags/") {
            if u.old != u.new {
                needs_approval.push(finding(
                    K::TagReplacement,
                    A::Approve,
                    u,
                    "protected tag moved",
                ));
            }
        } else {
            match is_ancestor(git, &input.git_dir, &u.old, &u.new) {
                Ok(true) => {}
                Ok(false) => needs_approval.push(finding(
                    K::RefRewrite,
                    A::Approve,
                    u,
                    "non-fast-forward update of a protected ref",
                )),
                Err(why) => hard.push(finding(K::IncompleteScan, A::Deny, u, &why)),
            }
        }
    }

    if cfg.secret_policy {
        let outgoing: Vec<RefUpdate> = protected
            .iter()
            .filter(|u| !RefUpdate::is_zero(&u.new))
            .map(|u| (*u).clone())
            .collect();
        if !outgoing.is_empty() {
            match crate::git::scan_outgoing(git, &input.git_dir, &outgoing, None, limits) {
                Ok(f) => hard.extend(f.into_iter().map(|mut f| {
                    f.action = A::Deny;
                    f
                })),
                // A configured policy that cannot run denies; it never skips.
                Err(e) => hard.push(Finding::new(
                    K::IncompleteScan,
                    A::Deny,
                    SRC,
                    format!(
                        "secret policy is configured but the scan failed: {}",
                        e.message
                    ),
                )),
            }
        }
    }
    if !hard.is_empty() {
        return Err(crate::Error::rejected("push denied by server policy").with_findings(hard));
    }
    if needs_approval.is_empty() {
        return Ok(());
    }

    let deny = |why: &str| {
        crate::Error::rejected(format!("protected ref update needs approval: {why}"))
            .with_findings(needs_approval.clone())
    };
    let actor = input
        .actor
        .as_deref()
        .filter(|a| valid_actor(a))
        .ok_or_else(|| deny("no authenticated actor (FAIL2COMMIT_ACTOR)"))?;
    let mut tokens = input
        .push_options
        .iter()
        .filter_map(|o| o.strip_prefix(OPTION_KEY));
    let token = tokens
        .next()
        .ok_or_else(|| deny("no f2c-approval push option (is push-option support enabled?)"))?;
    if tokens.next().is_some() || !token.starts_with(TOKEN_PREFIX) {
        return Err(deny("malformed approval push option"));
    }
    let id = repo_id(&input.git_dir)?;
    let digest = updates_digest(&input.updates)?;
    consume(home, token, &id, actor, &digest)
        .map_err(|e| crate::Error::rejected(e.message).with_findings(needs_approval.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects_bad_input() {
        let z = "0".repeat(40);
        let a = "a".repeat(40);
        let ok = format!("{z} {a} refs/heads/main\n");
        assert_eq!(parse_updates(ok.as_bytes()).unwrap().len(), 1);
        for bad in [
            String::new(),
            format!("{z} {a}\n"),
            format!("{z} xyz refs/heads/main\n"),
            format!("{z} {a} heads/main\n"),
            format!("{z} {a} refs/heads/m\n{z} {a} refs/heads/m\n"),
        ] {
            assert!(parse_updates(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let big = "x".repeat(MAX_INPUT_BYTES as usize + 1);
        assert!(parse_updates(big.as_bytes()).is_err());
    }
}
