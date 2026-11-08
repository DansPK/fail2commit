//! Consumed approval nonces (FR-002). A reply is accepted at most once,
//! across processes: the nonce is recorded under a lock in
//! `state_dir/approvals/consumed.json` until the request expires.

use crate::paths::TrustedPaths;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

const MAX_BYTES: u64 = 1024 * 1024;
/// Unexpired entries allowed; beyond this new approvals fail closed.
const MAX_ENTRIES: usize = 4096;

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Store {
    version: u32,
    /// nonce hex -> expires_at
    consumed: BTreeMap<String, u64>,
}

fn file(paths: &TrustedPaths) -> PathBuf {
    paths.state_dir.join("approvals").join("consumed.json")
}

fn load(paths: &TrustedPaths) -> crate::Result<Store> {
    let f = file(paths);
    match crate::fsutil::read_bounded(&f, MAX_BYTES) {
        Ok(b) => serde_json::from_slice(&b)
            .map_err(|_| crate::Error::invalid("approval replay state is damaged; refusing")),
        Err(_) if !f.exists() => Ok(Store {
            version: 1,
            ..Store::default()
        }),
        Err(e) => Err(e),
    }
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Error if `nonce` was already consumed (checked before prompting).
pub(crate) fn ensure_unused(paths: &TrustedPaths, nonce: &str) -> crate::Result<()> {
    if !valid_nonce(nonce) {
        return Err(crate::Error::rejected(
            "approval request has a malformed nonce",
        ));
    }
    if load(paths)?.consumed.contains_key(nonce) {
        return Err(crate::Error::rejected(
            "approval request was already answered",
        ));
    }
    Ok(())
}

/// Record `nonce` as used; exactly one caller wins for a given nonce.
pub(crate) fn consume(paths: &TrustedPaths, nonce: &str, expires_at: u64) -> crate::Result<()> {
    if !valid_nonce(nonce) {
        return Err(crate::Error::rejected(
            "approval request has a malformed nonce",
        ));
    }
    let f = file(paths);
    crate::fsutil::with_lock(&f, || {
        let mut s = load(paths)?;
        let now = crate::approver::now_secs();
        s.consumed.retain(|_, exp| *exp >= now);
        if s.consumed.contains_key(nonce) {
            return Err(crate::Error::rejected(
                "approval reply replayed: request was already answered",
            ));
        }
        if s.consumed.len() >= MAX_ENTRIES {
            return Err(crate::Error::rejected(
                "too many outstanding approvals; refusing",
            ));
        }
        s.consumed.insert(nonce.to_string(), expires_at);
        s.version = 1;
        let bytes = serde_json::to_vec(&s)
            .map_err(|e| crate::Error::internal(format!("serialize replay state: {e}")))?;
        crate::fsutil::atomic_write(&f, &bytes)
    })
}
