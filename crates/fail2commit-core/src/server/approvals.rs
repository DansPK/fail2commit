//! Approval tokens: minted by the maintainer, stored only as SHA-256
//! verifiers, consumed atomically (lock + atomic rewrite).

use super::config::ServerHome;
use crate::digest::Digest;
use crate::git::RefUpdate;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_STORE_BYTES: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 1024;
pub(crate) const TOKEN_PREFIX: &str = "f2ca-";

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Store {
    approvals: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    verifier: String,
    repo_id: String,
    actor: String,
    digest: String,
    expires_at: u64,
}

pub struct Issued {
    /// Shown once; never stored.
    pub token: String,
    pub expires_at: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn verifier(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Canonical digest over the sorted `(ref, old, new)` set.
pub fn updates_digest(updates: &[RefUpdate]) -> crate::Result<Digest> {
    let mut sorted = updates.to_vec();
    sorted.sort_by(|a, b| (&a.refname, &a.old, &a.new).cmp(&(&b.refname, &b.old, &b.new)));
    Digest::of("server.ref-updates", &sorted)
}

fn load(home: &ServerHome) -> crate::Result<Store> {
    let file = home.approvals_file();
    if !file.exists() {
        return Ok(Store::default());
    }
    let bytes = crate::fsutil::read_bounded(&file, MAX_STORE_BYTES)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| crate::Error::integrity(format!("approvals.json is invalid: {e}")))
}

fn save(home: &ServerHome, store: &Store) -> crate::Result<()> {
    let bytes = serde_json::to_vec(store).map_err(|e| crate::Error::internal(e.to_string()))?;
    crate::fsutil::atomic_write(&home.approvals_file(), &bytes)
}

pub(crate) fn valid_actor(actor: &str) -> bool {
    !actor.is_empty()
        && actor.len() <= 128
        && actor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@+-".contains(&b))
}

pub fn issue(
    home: &ServerHome,
    repo_id: &str,
    actor: &str,
    updates: &[RefUpdate],
    ttl_secs: u64,
) -> crate::Result<Issued> {
    let cfg = home.load_config()?;
    if !valid_actor(actor) {
        return Err(crate::Error::invalid("invalid actor name"));
    }
    if updates.is_empty() {
        return Err(crate::Error::invalid("at least one ref update is required"));
    }
    if ttl_secs == 0 || ttl_secs > cfg.max_token_ttl_secs {
        return Err(crate::Error::invalid(format!(
            "ttl must be 1..={} seconds",
            cfg.max_token_ttl_secs
        )));
    }
    let digest = updates_digest(updates)?;
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| crate::Error::internal(format!("random: {e}")))?;
    let token = format!("{TOKEN_PREFIX}{}", hex::encode(raw));
    let expires_at = now() + ttl_secs;
    crate::fsutil::with_lock(&home.approvals_file(), || {
        let mut store = load(home)?;
        let t = now();
        store.approvals.retain(|e| e.expires_at > t);
        if store.approvals.len() >= MAX_ENTRIES {
            return Err(crate::Error::invalid("too many pending approvals"));
        }
        store.approvals.push(Entry {
            verifier: verifier(&token),
            repo_id: repo_id.to_string(),
            actor: actor.to_string(),
            digest: digest.to_string(),
            expires_at,
        });
        save(home, &store)
    })?;
    Ok(Issued { token, expires_at })
}

/// Burns the token if its verifier is known, whether or not the binding
/// matches, so a failed attempt always needs fresh approval.
pub(crate) fn consume(
    home: &ServerHome,
    token: &str,
    repo_id: &str,
    actor: &str,
    digest: &Digest,
) -> crate::Result<()> {
    let v = verifier(token);
    let entry = crate::fsutil::with_lock(&home.approvals_file(), || {
        let mut store = load(home)?;
        let t = now();
        store.approvals.retain(|e| e.expires_at > t);
        let Some(i) = store.approvals.iter().position(|e| e.verifier == v) else {
            return Ok(None);
        };
        let e = store.approvals.remove(i);
        save(home, &store)?;
        Ok(Some(e))
    })?;
    let e = entry
        .ok_or_else(|| crate::Error::rejected("approval token is invalid, used or expired"))?;
    if e.repo_id != repo_id || e.actor != actor || !digest.matches(&e.digest) {
        return Err(crate::Error::rejected(
            "approval token does not match this repository, actor and update set",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upd(n: &str) -> RefUpdate {
        RefUpdate {
            refname: "refs/heads/main".into(),
            old: "1".repeat(40),
            new: n.repeat(40),
        }
    }

    fn home() -> (tempfile::TempDir, ServerHome) {
        let d = tempfile::tempdir().unwrap();
        let h = ServerHome::resolve(Some(d.path())).unwrap();
        h.store_config(&Default::default()).unwrap();
        (d, h)
    }

    #[test]
    fn digest_is_order_independent() {
        let a = [upd("2"), upd("3")];
        let b = [upd("3"), upd("2")];
        assert_eq!(updates_digest(&a).unwrap(), updates_digest(&b).unwrap());
        assert_ne!(
            updates_digest(&a).unwrap(),
            updates_digest(&[upd("2")]).unwrap()
        );
    }

    #[test]
    fn token_is_single_use_and_bound() {
        let (_d, h) = home();
        let u = [upd("2")];
        let dg = updates_digest(&u).unwrap();
        let t = issue(&h, "repo", "alice", &u, 60).unwrap().token;
        let stored = std::fs::read_to_string(h.approvals_file()).unwrap();
        assert!(!stored.contains(&t), "token must not be stored");
        consume(&h, &t, "repo", "alice", &dg).unwrap();
        assert!(consume(&h, &t, "repo", "alice", &dg).is_err());

        // A mismatched presentation burns the token.
        let t = issue(&h, "repo", "alice", &u, 60).unwrap().token;
        assert!(consume(&h, &t, "repo", "bob", &dg).is_err());
        assert!(consume(&h, &t, "repo", "alice", &dg).is_err());
        assert!(issue(&h, "repo", "alice", &u, 100_000).is_err());
    }
}
