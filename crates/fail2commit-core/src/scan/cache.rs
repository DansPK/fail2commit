//! Bounded, atomic disk cache for OSV advisory data (T-006, SPEC-006).
//!
//! Layout: `<cache_dir>/osv/<sha256(key)>.json`, one file per entry, each a
//! `{"stored_at":<unix secs>,"data":...}` envelope. Writes go through
//! [`crate::fsutil::atomic_write`], entries expire by TTL, and the directory is
//! kept under `cache_max_bytes` by evicting the oldest modification times
//! first. Cache content is untrusted input: a malformed or oversized entry is
//! a cache miss, never an error the caller must handle.

use crate::fsutil;
use crate::paths::TrustedPaths;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache key schema. Bump to invalidate every stored entry after a shape
/// change instead of reusing data written by an older build.
pub const KEY_VERSION: &str = "v1";

/// Largest entry this module will read or write. A bigger payload is simply
/// not cached; the caller still reports the finding.
pub const MAX_ENTRY_BYTES: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry<T> {
    pub stored_at: u64,
    pub data: T,
}

/// Directory holding OSV entries for these trusted paths.
pub fn root(paths: &TrustedPaths) -> PathBuf {
    paths.cache_dir.join("osv")
}

/// Create the cache directory (private permissions) and return it.
pub fn ensure(paths: &TrustedPaths) -> PathBuf {
    let root = root(paths);
    // A cache directory that cannot be created is not fatal: lookups still run
    // and simply never hit the disk.
    let _ = fsutil::ensure_private_dir(&root);
    root
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
/// wrong-shaped file.
pub fn read<T>(path: &Path) -> Option<Entry<T>>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fsutil::read_bounded(path, MAX_ENTRY_BYTES).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Store one entry atomically. Returns `false` when the payload does not fit
/// the configured cache budget and was therefore not written.
pub fn write<T: Serialize>(path: &Path, data: &T, stored_at: u64, max_bytes: u64) -> bool {
    let entry = Entry { stored_at, data };
    let Ok(bytes) = serde_json::to_vec(&entry) else {
        return false;
    };
    let len = bytes.len() as u64;
    if len > MAX_ENTRY_BYTES || len > max_bytes {
        return false;
    }
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
}
