//! Bounded, atomic disk cache for OSV advisory data (T-006, SPEC-006).
//!
//! Layout: `<cache_dir>/osv/<sha256(key)>.json`, one file per entry, each a
//! `{"stored_at":<unix secs>,"data":...}` envelope behind a one-line
//! `f2c-hmac1:<hex tag>` header (CR-019). The tag is HMAC-SHA256 over the file
//! name and the exact envelope bytes, keyed by a random per-user secret in the
//! private state directory, so an entry that was edited, copied over another
//! entry's file, or written by an older build reads as a miss. Writes go through
//! [`crate::fsutil::atomic_write`], entries expire by TTL, and the directory is
//! kept under `cache_max_bytes` by evicting the oldest modification times
//! first. Cache content is untrusted input: a malformed, oversized or
//! unverified entry is a cache miss, never an error the caller must handle.

use crate::fsutil;
use crate::paths::TrustedPaths;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache key schema. Bump to invalidate every stored entry after a shape
/// change instead of reusing data written by an older build.
pub const KEY_VERSION: &str = "v1";

/// Largest entry this module will read or write. A bigger payload is simply
/// not cached; the caller still reports the finding.
pub const MAX_ENTRY_BYTES: u64 = 1024 * 1024;

/// File name of the cache tag key under `TrustedPaths::state_dir`.
pub const KEY_FILE: &str = "osv-cache.key";
const KEY_LEN: usize = 32;
const TAG_PREFIX: &[u8] = b"f2c-hmac1:";
/// Prefix, 64 hex characters, newline.
const HEADER_LEN: usize = TAG_PREFIX.len() + 64 + 1;

/// Tag key per cache root, loaded by [`ensure`]. `read` and `write` only see
/// an entry path, so the key is looked up by the root it was loaded for. A
/// root without a key reads nothing and writes nothing.
static KEYS: Mutex<BTreeMap<PathBuf, [u8; KEY_LEN]>> = Mutex::new(BTreeMap::new());

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry<T> {
    pub stored_at: u64,
    pub data: T,
}

/// Directory holding OSV entries for these trusted paths.
pub fn root(paths: &TrustedPaths) -> PathBuf {
    paths.cache_dir.join("osv")
}

/// Location of the cache tag key.
pub fn key_path(paths: &TrustedPaths) -> PathBuf {
    paths.state_dir.join(KEY_FILE)
}

/// Create the cache directory (private permissions), load or create the tag
/// key, and return the directory.
pub fn ensure(paths: &TrustedPaths) -> PathBuf {
    let root = root(paths);
    // A cache directory or key that cannot be created is not fatal: lookups
    // still run and simply never use the disk.
    let _ = fsutil::ensure_private_dir(&root);
    let key = load_or_create_key(&key_path(paths));
    let mut keys = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    match key {
        Some(key) => keys.insert(root.clone(), key),
        None => keys.remove(&root),
    };
    root
}

fn load_or_create_key(path: &Path) -> Option<[u8; KEY_LEN]> {
    let read = |path: &Path| -> Option<[u8; KEY_LEN]> {
        fsutil::read_bounded(path, KEY_LEN as u64)
            .ok()?
            .try_into()
            .ok()
    };
    if let Some(key) = read(path) {
        return Some(key);
    }
    // Missing or damaged: a new key only makes existing entries refetch.
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).ok()?;
    // atomic_write creates the private parent dir and an owner-only file.
    fsutil::atomic_write(path, &key).ok()?;
    // Re-read so racing creators settle on the file that won the rename.
    read(path)
}

fn key_for(path: &Path) -> Option<[u8; KEY_LEN]> {
    let keys = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    keys.get(path.parent()?).copied()
}

/// HMAC-SHA256 (RFC 2104) over the concatenated `parts`, for keys of at most
/// one block. Built on `sha2` rather than adding the `hmac` crate.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    assert!(key.len() <= 64, "HMAC key longer than one SHA-256 block");
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, byte) in key.iter().enumerate() {
        ipad[i] ^= byte;
        opad[i] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Tag for an entry body stored at `path`. The file name is covered so a
/// valid entry copied over another package's file does not verify.
fn tag(key: &[u8; KEY_LEN], path: &Path, body: &[u8]) -> Option<[u8; 32]> {
    let name = path.file_name()?.as_encoded_bytes();
    Some(hmac_sha256(key, &[name, b"\0", body]))
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// File name for `key`: the key never reaches the filesystem verbatim, so an
/// untrusted package name cannot escape the cache directory.
pub fn path_for(root: &Path, key: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    root.join(format!("{}.json", hex::encode(hasher.finalize())))
}

/// Read one entry. `None` for a missing, oversized, unparsable or
/// wrong-shaped file, and for one whose tag is missing or does not verify:
/// the caller then refetches it, or reports the lookup incomplete offline.
pub fn read<T>(path: &Path) -> Option<Entry<T>>
where
    T: serde::de::DeserializeOwned,
{
    let key = key_for(path)?;
    let bytes = fsutil::read_bounded(path, MAX_ENTRY_BYTES + HEADER_LEN as u64).ok()?;
    let (header, body) = bytes.split_at_checked(HEADER_LEN)?;
    let hex_tag = header.strip_prefix(TAG_PREFIX)?.strip_suffix(b"\n")?;
    let stored = hex::decode(hex_tag).ok()?;
    if !crate::digest::ct_eq(&stored, &tag(&key, path, body)?) {
        return None;
    }
    serde_json::from_slice(body).ok()
}

/// Store one entry atomically. Returns `false` when the payload does not fit
/// the configured cache budget and was therefore not written.
pub fn write<T: Serialize>(path: &Path, data: &T, stored_at: u64, max_bytes: u64) -> bool {
    let Some(key) = key_for(path) else {
        return false;
    };
    let entry = Entry { stored_at, data };
    let Ok(body) = serde_json::to_vec(&entry) else {
        return false;
    };
    if body.len() as u64 > MAX_ENTRY_BYTES || (body.len() + HEADER_LEN) as u64 > max_bytes {
        return false;
    }
    let Some(tag) = tag(&key, path, &body) else {
        return false;
    };
    let mut bytes = Vec::with_capacity(HEADER_LEN + body.len());
    bytes.extend_from_slice(TAG_PREFIX);
    bytes.extend_from_slice(hex::encode(tag).as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&body);
    fsutil::atomic_write(path, &bytes).is_ok()
}

/// True once `ttl_secs` have elapsed since `stored_at`.
pub fn is_stale(stored_at: u64, ttl_secs: u64) -> bool {
    now_secs().saturating_sub(stored_at) > ttl_secs
}

/// Drop the oldest entries until the directory holds at most `max_bytes`.
/// Returns the remaining byte total.
pub fn evict(dir: &Path, max_bytes: u64) -> u64 {
    let mut files: Vec<(PathBuf, u64, u64)> = Vec::new();
    let Ok(iter) = fs::read_dir(dir) else {
        return 0;
    };
    for entry in iter.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        files.push((path, meta.len(), mtime));
    }
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    if total <= max_bytes {
        return total;
    }
    files.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
    for (path, len, _) in files {
        if total <= max_bytes {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(len);
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths() -> (tempfile::TempDir, TrustedPaths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = TrustedPaths::under(dir.path());
        (dir, paths)
    }

    #[test]
    fn round_trip_and_staleness() {
        let (_dir, paths) = temp_paths();
        let root = ensure(&paths);
        let file = path_for(&root, "v1:batch:npm:demo@1.0.0");
        assert!(
            read::<Vec<String>>(&file).is_none(),
            "missing file is a miss"
        );
        assert!(write(&file, &vec!["GHSA-A".to_string()], now_secs(), 4096));
        let entry = read::<Vec<String>>(&file).unwrap();
        assert_eq!(entry.data, vec!["GHSA-A".to_string()]);
        assert!(!is_stale(entry.stored_at, 3600));
        assert!(is_stale(entry.stored_at.saturating_sub(10), 1));
    }

    #[test]
    fn refuses_payload_over_budget() {
        let (_dir, paths) = temp_paths();
        let root = ensure(&paths);
        let file = path_for(&root, "k");
        assert!(!write(&file, &vec!["x".to_string(); 64], now_secs(), 32));
        assert!(read::<Vec<String>>(&file).is_none());
    }

    #[test]
    fn evicts_oldest_first() {
        let (_dir, paths) = temp_paths();
        let root = ensure(&paths);
        let mut written = Vec::new();
        for i in 0..4u32 {
            let file = path_for(&root, &format!("k{i}"));
            assert!(write(
                &file,
                &vec!["y".to_string(); 32],
                now_secs(),
                MAX_ENTRY_BYTES
            ));
            written.push(file);
        }
        let one = fs::metadata(&written[0]).unwrap().len();
        let after = evict(&root, one);
        assert!(after <= one, "remaining {after} bytes over budget {one}");
        assert!(
            written.iter().any(|p| p.exists()),
            "one entry fits the budget"
        );
    }

    #[test]
    fn zero_budget_removes_everything() {
        let (_dir, paths) = temp_paths();
        let root = ensure(&paths);
        assert!(write(
            &path_for(&root, "k"),
            &vec![1u8],
            now_secs(),
            MAX_ENTRY_BYTES
        ));
        assert_eq!(evict(&root, 0), 0);
    }

    #[test]
    fn malformed_entry_is_a_miss() {
        let (_dir, paths) = temp_paths();
        let root = ensure(&paths);
        let file = path_for(&root, "broken");
        std::fs::write(&file, b"{not json").unwrap();
        assert!(read::<Vec<String>>(&file).is_none());
    }

    #[test]
    fn hmac_matches_rfc4231_case_1() {
        let tag = hmac_sha256(&[0x0b; 20], &[b"Hi ", b"There"]);
        assert_eq!(
            hex::encode(tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn tampered_swapped_and_untagged_entries_are_misses() {
        let (_dir, paths) = temp_paths();
        let root = ensure(&paths);
        let evil = path_for(&root, "evil");
        let clean = path_for(&root, "clean");
        assert!(write(&evil, &vec!["MAL-1".to_string()], now_secs(), 4096));
        assert!(write(&clean, &Vec::<String>::new(), now_secs(), 4096));
        let claim_clean = format!(r#"{{"stored_at":{},"data":[]}}"#, now_secs());

        // Body edited under the original tag.
        let mut edited = fs::read(&evil).unwrap()[..HEADER_LEN].to_vec();
        edited.extend_from_slice(claim_clean.as_bytes());
        fs::write(&evil, &edited).unwrap();
        assert!(read::<Vec<String>>(&evil).is_none());

        // A valid entry copied over another entry's file.
        fs::copy(&clean, &evil).unwrap();
        assert!(read::<Vec<String>>(&evil).is_none());
        assert!(read::<Vec<String>>(&clean).is_some());

        // An entry from an older build: the bare envelope, no tag.
        fs::write(&evil, &claim_clean).unwrap();
        assert!(read::<Vec<String>>(&evil).is_none());
    }

    #[test]
    fn key_is_created_once_and_a_new_key_invalidates_entries() {
        let (_dir, paths) = temp_paths();
        let root = ensure(&paths);
        let key = fs::read(key_path(&paths)).unwrap();
        assert_eq!(key.len(), KEY_LEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(key_path(&paths)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let file = path_for(&root, "k");
        assert!(write(&file, &vec!["A".to_string()], now_secs(), 4096));
        ensure(&paths);
        assert_eq!(fs::read(key_path(&paths)).unwrap(), key, "key is reused");
        assert!(read::<Vec<String>>(&file).is_some());

        fs::remove_file(key_path(&paths)).unwrap();
        ensure(&paths);
        assert_ne!(fs::read(key_path(&paths)).unwrap(), key);
        assert!(read::<Vec<String>>(&file).is_none(), "old key's entry");
    }

    #[test]
    fn root_without_a_key_neither_reads_nor_writes() {
        let dir = tempfile::tempdir().unwrap();
        let file = path_for(&dir.path().join("never-ensured"), "k");
        assert!(!write(&file, &vec![1u8], now_secs(), MAX_ENTRY_BYTES));
        assert!(read::<Vec<u8>>(&file).is_none());
    }
}
