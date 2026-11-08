//! Canonical operation digests (CHORE-001, frozen).
//!
//! Every approval binds to `Digest::of(domain, value)`. Canonical form: JSON
//! with object keys sorted bytewise, no whitespace, serde_json escaping. The
//! hash input is `"fail2commit/v1/" + domain + "\0" + canonical`, SHA-256.
//! Callers must put every security-relevant input in `value` (refs + old/new
//! OIDs, resolved package set + integrity, effective config, target), in a
//! deterministic order for sequences.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Digest(String);

impl Digest {
    pub fn of<T: Serialize + ?Sized>(domain: &str, value: &T) -> crate::Result<Digest> {
        let canonical = canonical_json(value)?;
        let mut h = Sha256::new();
        h.update(b"fail2commit/v1/");
        h.update(domain.as_bytes());
        h.update([0u8]);
        h.update(canonical.as_bytes());
        Ok(Digest(hex::encode(h.finalize())))
    }

    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Constant-time comparison against a hex string from an untrusted peer.
    pub fn matches(&self, other_hex: &str) -> bool {
        ct_eq(self.0.as_bytes(), other_hex.as_bytes())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonical JSON string for `value` (sorted keys, compact).
pub fn canonical_json<T: Serialize + ?Sized>(value: &T) -> crate::Result<String> {
    let v = serde_json::to_value(value)
        .map_err(|e| crate::Error::internal(format!("canonicalize: {e}")))?;
    let mut out = String::new();
    write_canonical(&v, &mut out);
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("string serializes"));
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Constant-time byte comparison (length leak only).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 32 random bytes as hex, from the OS CSPRNG.
pub fn random_hex32() -> crate::Result<String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)
        .map_err(|e| crate::Error::internal(format!("OS random source failed: {e}")))?;
    Ok(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_digest() {
        let a = json!({"b": 1, "a": {"y": [1, 2], "x": "s"}});
        let b = json!({"a": {"x": "s", "y": [1, 2]}, "b": 1});
        assert_eq!(Digest::of("t", &a).unwrap(), Digest::of("t", &b).unwrap());
        assert_eq!(
            canonical_json(&a).unwrap(),
            r#"{"a":{"x":"s","y":[1,2]},"b":1}"#
        );
    }

    #[test]
    fn domain_and_values_separate_digests() {
        let v = json!(["refs/heads/main", "0000", "1111"]);
        let w = json!(["refs/heads/main", "0000", "2222"]);
        assert_ne!(
            Digest::of("git", &v).unwrap(),
            Digest::of("npm", &v).unwrap()
        );
        assert_ne!(
            Digest::of("git", &v).unwrap(),
            Digest::of("git", &w).unwrap()
        );
    }

    #[test]
    fn matches_and_random() {
        let d = Digest::of("t", &1).unwrap();
        assert!(d.matches(d.as_hex()));
        assert!(!d.matches("00"));
        let r = random_hex32().unwrap();
        assert_eq!(r.len(), 64);
        assert_ne!(r, random_hex32().unwrap());
    }
}
