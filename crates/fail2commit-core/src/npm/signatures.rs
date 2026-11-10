//! CR-018 (P-108): npm registry signatures and a provenance-downgrade warning.
//!
//! Before anything from the plan is downloaded, every unique artifact's
//! `dist.signatures` is verified against the registry's ECDSA P-256 keys
//! (`<registry>/-/npm/v1/keys`) over `"<name>@<version>:<integrity>"`, the
//! message npm signs. Registry responses and the key cache are untrusted
//! input: sizes and counts are bounded, redirects are refused, and a check
//! that cannot run is a deny, never "clean". Sigstore bundles (Fulcio chain,
//! Rekor inclusion) are not verified; only the presence of provenance is read.

use super::config::Registry;
use super::lockfile::{Plan, PlanPkg};
use super::review::package_id;
use super::Deps;
use crate::fsutil;
use crate::paths::TrustedPaths;
use crate::protocol::{Finding, FindingAction, FindingKind};
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const SOURCE: &str = "npm.signatures";
const KEYS_MAX_BYTES: u64 = 64 * 1024;
const MAX_KEYS: usize = 32;
const MAX_SIGS: usize = 16;
/// Full packuments of popular packages run to tens of MB.
const META_MAX_BYTES: u64 = 64 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(60);
const CORGI: &str = "application/vnd.npm.install-v1+json";
const FULL: &str = "application/json";
/// Also lets the test registry tell these lookups apart from npm's own.
pub const USER_AGENT: &str = concat!("fail2commit-signatures/", env!("CARGO_PKG_VERSION"));
pub const PROVENANCE_MSG: &str =
    "earlier versions were published with build provenance; this one was not (possible hijacked account)";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

struct Key {
    keyid: String,
    vk: VerifyingKey,
    /// Unix seconds; a signature made at or after this time does not count.
    expires: Option<i64>,
}

/// Signature and provenance findings for `plan`; empty when the check is off.
pub fn check(deps: &Deps<'_>, registry: &Registry, plan: &Plan) -> Vec<Finding> {
    let cfg = &deps.settings.signatures;
    if !cfg.verify {
        return vec![];
    }
    let url = &registry.url;
    let keys = match load_keys(deps.paths, registry, cfg.keys_ttl_secs) {
        Ok(Some(k)) => k,
        Ok(None) => {
            let why = format!("registry {url} publishes no signing keys; signatures not verified");
            let kind = FindingKind::IncompleteScan;
            return vec![Finding::new(kind, FindingAction::Approve, SOURCE, why)];
        }
        Err(e) => {
            let why = format!(
                "could not load the signing keys of registry {url}: {e}; signatures are unverifiable"
            );
            let kind = FindingKind::SignatureInvalid;
            return vec![Finding::new(kind, FindingAction::Deny, SOURCE, why)];
        }
    };
    let mut uniq: Vec<&PlanPkg> = Vec::new();
    for p in plan.pkgs.iter().filter(|p| !p.skip_platform) {
        if !uniq
            .iter()
            .any(|u| u.name == p.name && u.version == p.version && u.integrity == p.integrity)
        {
            uniq.push(p);
        }
    }
    let next = AtomicUsize::new(0);
    let out = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..uniq.len().clamp(1, 8) {
            s.spawn(|| {
                while let Some(p) = uniq.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let target = package_id(p).display();
                    let f = match verify_pkg(registry, &keys, p) {
                        Ok(false) => continue,
                        Ok(true) => Finding::new(
                            FindingKind::ProvenanceMissing,
                            FindingAction::Approve,
                            SOURCE,
                            PROVENANCE_MSG,
                        ),
                        Err(why) => Finding::new(
                            FindingKind::SignatureInvalid,
                            FindingAction::Deny,
                            SOURCE,
                            why,
                        ),
                    };
                    out.lock().expect("findings").push(f.target(target));
                }
            });
        }
    });
    let mut out = out.into_inner().expect("findings");
    out.sort_by(|a, b| a.target.cmp(&b.target));
    out
}

enum Got {
    Body(Vec<u8>),
    NotFound,
}

/// GET without redirects, bounded by `max` bytes. Only 200 is a body.
fn get(url: &str, accept: &str, max: u64) -> Result<Got, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    match agent
        .get(url)
        .header("Accept", accept)
        .header("Accept-Encoding", "identity")
        .header("User-Agent", USER_AGENT)
        .call()
    {
        Ok(mut r) if r.status() == 200 => r
            .body_mut()
            .with_config()
            .limit(max)
            .read_to_vec()
            .map(Got::Body)
            .map_err(|e| e.to_string()),
        Ok(r) => Err(format!("unexpected HTTP status {}", r.status())),
        Err(ureq::Error::StatusCode(404)) => Ok(Got::NotFound),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Serialize, Deserialize)]
struct CachedKeys {
    stored_at: u64,
    body: String,
}

/// `Ok(None)`: the registry does not sign (404 on the keys endpoint).
fn load_keys(paths: &TrustedPaths, reg: &Registry, ttl: u64) -> Result<Option<Vec<Key>>, String> {
    let file = paths.cache_dir.join("npm-signatures").join(format!(
        "{}.json",
        hex::encode(Sha256::digest(reg.url.as_bytes()))
    ));
    let now = crate::approver::now_secs();
    let cached = fsutil::read_bounded(&file, 2 * KEYS_MAX_BYTES)
        .ok()
        .and_then(|b| serde_json::from_slice::<CachedKeys>(&b).ok())
        .filter(|c| c.stored_at <= now && now - c.stored_at < ttl)
        .and_then(|c| parse_keys(c.body.as_bytes()).ok());
    if let Some(k) = cached {
        return Ok(Some(k));
    }
    let body = match get(&format!("{}-/npm/v1/keys", reg.url), FULL, KEYS_MAX_BYTES)? {
        Got::NotFound => return Ok(None),
        Got::Body(b) => b,
    };
    let keys = parse_keys(&body)?;
    // A cache that cannot be written only costs a refetch next time.
    if let Ok(body) = String::from_utf8(body) {
        if let Ok(bytes) = serde_json::to_vec(&CachedKeys {
            stored_at: now,
            body,
        }) {
            let _ = fsutil::atomic_write(&file, &bytes);
        }
    }
    Ok(Some(keys))
}

fn parse_keys(body: &[u8]) -> Result<Vec<Key>, String> {
    #[derive(Deserialize)]
    struct Doc {
        keys: Vec<Raw>,
    }
    #[derive(Deserialize)]
    struct Raw {
        keyid: String,
        keytype: String,
        scheme: String,
        key: String,
        expires: Option<String>,
    }
    let doc: Doc =
        serde_json::from_slice(body).map_err(|e| format!("malformed keys document: {e}"))?;
    if doc.keys.is_empty() || doc.keys.len() > MAX_KEYS {
        return Err(format!("keys document lists {} keys", doc.keys.len()));
    }
    let mut out = Vec::new();
    for k in doc.keys {
        // A key of another type can never verify; it is simply not usable.
        if k.keytype != "ecdsa-sha2-nistp256" || k.scheme != "ecdsa-sha2-nistp256" {
            continue;
        }
        let vk = B64
            .decode(&k.key)
            .ok()
            .and_then(|der| VerifyingKey::from_public_key_der(&der).ok())
            .ok_or_else(|| format!("key {} is not a P-256 public key", k.keyid))?;
        let expires = match &k.expires {
            None => None,
            Some(t) => Some(rfc3339(t).ok_or_else(|| format!("key {} has a bad expiry", k.keyid))?),
        };
        out.push(Key {
            keyid: k.keyid,
            vk,
            expires,
        });
    }
    Ok(out)
}

/// What one packument says about one version.
struct Meta {
    integrity: Option<String>,
    sigs: Option<Vec<(String, String)>>,
    published: Option<i64>,
    /// Whether this version has provenance and whether an earlier one had.
    provenance: bool,
    earlier_provenance: bool,
}

fn meta(body: &[u8], p: &PlanPkg) -> Result<Meta, String> {
    let doc: Value = serde_json::from_slice(body)
        .map_err(|e| format!("registry metadata for {} is not valid JSON: {e}", p.name))?;
    let versions = doc
        .get("versions")
        .and_then(Value::as_object)
        .ok_or("registry metadata has no versions")?;
    let dist = versions
        .get(&p.version)
        .and_then(|v| v.get("dist"))
        .ok_or_else(|| format!("registry metadata has no version {}", p.version))?;
    let has_prov = |v: &Value| {
        v.pointer("/dist/attestations/provenance")
            .is_some_and(|x| !x.is_null())
    };
    let sigs = match dist.get("signatures") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) if a.len() <= MAX_SIGS => Some(
            a.iter()
                .map(|s| {
                    let f = |k| s.get(k).and_then(Value::as_str).map(str::to_string);
                    f("keyid")
                        .zip(f("sig"))
                        .ok_or("malformed dist.signatures entry")
                })
                .collect::<Result<_, _>>()?,
        ),
        Some(_) => return Err("malformed dist.signatures".into()),
    };
    Ok(Meta {
        integrity: dist
            .get("integrity")
            .and_then(Value::as_str)
            .map(str::to_string),
        sigs,
        published: doc
            .pointer("/time")
            .and_then(|t| t.get(&p.version))
            .and_then(Value::as_str)
            .and_then(rfc3339),
        provenance: has_prov(&versions[&p.version]),
        earlier_provenance: versions
            .iter()
            .any(|(v, m)| semver_lt(v, &p.version) && has_prov(m)),
    })
}

/// `Ok(true)` when the signature is valid but provenance was dropped.
fn verify_pkg(reg: &Registry, keys: &[Key], p: &PlanPkg) -> Result<bool, String> {
    let ok_name = !p.name.is_empty()
        && p.name.len() <= 214
        && p.name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@/._~-".contains(&b));
    if !ok_name {
        return Err("package name cannot be looked up on the registry".into());
    }
    let url = format!("{}{}", reg.url, p.name.replacen('/', "%2f", 1));
    let fetch = |accept| match get(&url, accept, META_MAX_BYTES) {
        Ok(Got::Body(b)) => meta(&b, p),
        Ok(Got::NotFound) => Err("the registry has no metadata for this package".into()),
        Err(e) => Err(format!("could not fetch registry metadata: {e}")),
    };
    let mut m = fetch(CORGI)?;
    // The abbreviated document has no `time` map, which key expiry needs.
    let expiring = m
        .sigs
        .iter()
        .flatten()
        .any(|(id, _)| keys.iter().any(|k| &k.keyid == id && k.expires.is_some()));
    if m.sigs.is_none() || (expiring && m.published.is_none()) {
        m = fetch(FULL)?;
    }
    let integrity = m
        .integrity
        .ok_or("registry metadata has no dist.integrity")?;
    if integrity != p.integrity {
        return Err("registry metadata integrity differs from the lockfile integrity".into());
    }
    let sigs = m
        .sigs
        .filter(|s| !s.is_empty())
        .ok_or("no registry signature for this version")?;
    let msg = format!("{}@{}:{integrity}", p.name, p.version);
    let mut why = "no signature matches a registry key (unknown keyid)".to_string();
    for (keyid, sig) in &sigs {
        let Some(key) = keys.iter().find(|k| &k.keyid == keyid) else {
            continue;
        };
        if let Some(exp) = key.expires {
            match m.published {
                None => {
                    why = format!("publish time unknown; expiry of key {keyid} cannot be checked");
                    continue;
                }
                Some(t) if t >= exp => {
                    why = format!("signed with key {keyid} after the key expired");
                    continue;
                }
                Some(_) => {}
            }
        }
        let valid = B64
            .decode(sig)
            .ok()
            .and_then(|d| Signature::from_der(&d).ok())
            .is_some_and(|s| key.vk.verify(msg.as_bytes(), &s).is_ok());
        if valid {
            return Ok(!m.provenance && m.earlier_provenance);
        }
        why = format!("registry signature by key {keyid} is invalid");
    }
    Err(why)
}

/// `a < b` by semver precedence; unparsable versions are never earlier.
/// shortcut: prerelease tags compare as whole strings, not per identifier;
/// upgrade if a provenance warning ever hinges on prerelease ordering.
fn semver_lt(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> Option<([u64; 3], Option<&str>)> {
        let v = v.split('+').next()?;
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        let mut n = core.split('.').map(|x| x.parse::<u64>().ok());
        let t = [n.next()??, n.next()??, n.next()??];
        n.next().is_none().then_some((t, pre))
    }
    let (Some((ta, pa)), Some((tb, pb))) = (parse(a), parse(b)) else {
        return false;
    };
    match ta.cmp(&tb) {
        std::cmp::Ordering::Equal => match (pa, pb) {
            (Some(x), Some(y)) => x < y,
            (Some(_), None) => true,
            _ => false,
        },
        o => o.is_lt(),
    }
}

/// RFC 3339 timestamp to Unix seconds.
fn rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let d = b.get(r)?;
        d.iter()
            .all(u8::is_ascii_digit)
            .then(|| d.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0')))
    };
    let seps = [(4, b'-'), (7, b'-'), (13, b':'), (16, b':')];
    if b.len() < 20 || seps.iter().any(|&(i, c)| b[i] != c) || !b"Tt ".contains(&b[10]) {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let offset = match b.get(i..)? {
        b"Z" | b"z" => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let o = num(i + 1..i + 3)? * 3600 + num(i + 4..i + 6)? * 60;
            if *sign == b'+' {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    // Days from civil (H. Hinnant), proleptic Gregorian.
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + sec - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public data from registry.npmjs.org (read once, 2026-11-10): the
    // registry key that signed left-pad@1.3.0 and that signature.
    const NPM_KEYS: &str = r#"{"keys":[{"expires":"2025-01-29T00:00:00.000Z","keyid":"SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA","keytype":"ecdsa-sha2-nistp256","scheme":"ecdsa-sha2-nistp256","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="}]}"#;
    const LP_MSG: &str = "left-pad@1.3.0:sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==";
    const LP_SIG: &str = "MEYCIQD6P3wA64go2fjiRW+yNvdi0x7Jtge3eAxAlwNaK2wyfQIhAKMCJXCFKygnFmsVuppuZIuNzTCYx2WlrJSg8B6wMqZk";

    #[test]
    fn verifies_a_real_npm_registry_signature() {
        let keys = parse_keys(NPM_KEYS.as_bytes()).unwrap();
        assert_eq!(keys[0].expires, Some(1_738_108_800));
        let sig = Signature::from_der(&B64.decode(LP_SIG).unwrap()).unwrap();
        assert!(keys[0].vk.verify(LP_MSG.as_bytes(), &sig).is_ok());
        let tampered = LP_MSG.replace("1.3.0", "1.3.1");
        assert!(keys[0].vk.verify(tampered.as_bytes(), &sig).is_err());
    }

    #[test]
    fn keys_documents_are_bounded_and_strict() {
        for bad in [
            "",
            "{}",
            r#"{"keys":[]}"#,
            r#"{"keys":[{"keyid":"k","keytype":"ecdsa-sha2-nistp256","scheme":"ecdsa-sha2-nistp256","key":"AAAA","expires":null}]}"#,
            &NPM_KEYS.replace("2025-01-29T00:00:00.000Z", "soon"),
        ] {
            assert!(parse_keys(bad.as_bytes()).is_err(), "{bad}");
        }
        let many = format!(
            r#"{{"keys":[{}]}}"#,
            vec![&NPM_KEYS[9..NPM_KEYS.len() - 2]; MAX_KEYS + 1].join(",")
        );
        assert!(parse_keys(many.as_bytes()).is_err());
        let other = NPM_KEYS.replace(
            r#""keytype":"ecdsa-sha2-nistp256""#,
            r#""keytype":"ed25519""#,
        );
        assert!(parse_keys(other.as_bytes()).unwrap().is_empty());
    }

    #[test]
    fn timestamps_and_versions() {
        assert_eq!(rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339("2014-03-14T09:09:20.762Z"), Some(1_394_788_160));
        assert_eq!(rfc3339("2000-03-01T01:00:00+01:00"), Some(951_868_800));
        for bad in [
            "2025-13-01T00:00:00Z",
            "2025-01-01T00:00:00",
            "2025-01-01",
            "x",
        ] {
            assert_eq!(rfc3339(bad), None, "{bad}");
        }
        assert!(semver_lt("1.2.3", "1.10.0"));
        assert!(semver_lt("2.0.0-rc.1", "2.0.0"));
        assert!(!semver_lt("2.0.0", "2.0.0-rc.1"));
        assert!(!semver_lt("1.0.0", "1.0.0"));
        assert!(!semver_lt("banana", "1.0.0"));
    }

    /// Rough cost of one check against the real registry. Read-only.
    #[test]
    #[ignore = "needs the live npm registry"]
    fn live_left_pad_verifies() {
        let reg = Registry::parse(super::super::config::DEFAULT_REGISTRY).unwrap();
        let t0 = std::time::Instant::now();
        let Got::Body(b) = get(&format!("{}-/npm/v1/keys", reg.url), FULL, KEYS_MAX_BYTES).unwrap()
        else {
            panic!("no keys")
        };
        let keys = parse_keys(&b).unwrap();
        let t1 = std::time::Instant::now();
        let p = PlanPkg {
            path: "node_modules/left-pad".into(),
            name: "left-pad".into(),
            version: "1.3.0".into(),
            resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into(),
            integrity: LP_MSG.split_once(':').unwrap().1.into(),
            optional: false,
            skip_platform: false,
        };
        assert_eq!(verify_pkg(&reg, &keys, &p), Ok(false));
        eprintln!("keys {:?}, left-pad {:?}", t1 - t0, t1.elapsed());
    }
}
