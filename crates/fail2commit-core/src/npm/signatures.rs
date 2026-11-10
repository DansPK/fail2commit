//! CR-018 (P-108): npm registry signatures and a provenance-downgrade warning.
//!
//! Before anything from the plan is downloaded, every unique artifact's
//! `dist.signatures` is verified with ECDSA P-256 over
//! `"<name>@<version>:<integrity>"`, the message npm signs. Which keys count:
//!
//! - `registry.npmjs.org`: only the keys built into this binary
//!   ([`builtin_keys`]). The registry's keys endpoint can only select among
//!   them; a key it adds is never trusted.
//! - any other registry: trust on first use. The first key set seen (or "no
//!   keys") is recorded in the private state directory under a keyed
//!   HMAC-SHA256 tag; a later different set is a deny until the user runs
//!   `fail2commit signatures forget <registry-url>`.
//!
//! Registry responses and the record are untrusted input: sizes and counts
//! are bounded, redirects are refused, metadata is streamed into typed
//! structs, and a check that cannot run is a deny, never "clean". Sigstore
//! bundles (Fulcio chain, Rekor inclusion) are not verified; only the
//! presence of provenance is read.

use super::config::{Registry, DEFAULT_REGISTRY};
use super::lockfile::{Plan, PlanPkg};
use super::review::package_id;
use super::Deps;
use crate::fsutil;
use crate::paths::TrustedPaths;
use crate::protocol::{Finding, FindingAction, FindingKind};
use base64::Engine as _;
use hmac::{KeyInit as _, Mac as _};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const SOURCE: &str = "npm.signatures";
const KEYS_MAX_BYTES: u64 = 64 * 1024;
const MAX_KEYS: usize = 32;
const MAX_SIGS: usize = 16;
/// Upper bound for one metadata document (also capped by
/// `limits.artifact_max_bytes`). Documents are streamed, never buffered.
const META_MAX_BYTES: u64 = 64 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(60);
const CORGI: &str = "application/vnd.npm.install-v1+json";
const FULL: &str = "application/json";
const RECORD_DIR: &str = "npm-signatures";
const SECRET_FILE: &str = "npm-signatures.key";
const TAG_PREFIX: &[u8] = b"f2c-hmac1:";
/// Also lets the test registry tell these lookups apart from npm's own.
pub const USER_AGENT: &str = concat!("fail2commit-signatures/", env!("CARGO_PKG_VERSION"));
pub const PROVENANCE_MSG: &str =
    "earlier versions were published with build provenance; this one was not (possible hijacked account)";
const UNKNOWN_KEY_MSG: &str =
    "signed with a key this fail2commit version does not know; update fail2commit";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// npm's public registry signing keys, from one read-only fetch of
/// <https://registry.npmjs.org/-/npm/v1/keys> on 2026-11-10T11:24:41Z.
/// `(keyid, SPKI DER base64, expires)`; both are `ecdsa-sha2-nistp256`.
const NPM_KEYS: [(&str, &str, Option<&str>); 2] = [
    (
        "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==",
        Some("2025-01-29T00:00:00.000Z"),
    ),
    (
        "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g==",
        None,
    ),
];

/// Signing keys shipped for one registry; only these verify its artifacts.
#[derive(Clone, Debug)]
pub struct PinnedKeys {
    /// Registry URL as pinned (`https://host/path/`).
    pub registry: String,
    pub keys: Vec<PinnedKey>,
}

#[derive(Clone, Debug)]
pub struct PinnedKey {
    pub keyid: String,
    /// Base64 SPKI DER of a P-256 public key.
    pub key: String,
    /// RFC 3339.
    pub expires: Option<String>,
}

/// The keys this binary ships: npm's public registry.
pub fn builtin_keys() -> Vec<PinnedKeys> {
    vec![PinnedKeys {
        registry: DEFAULT_REGISTRY.into(),
        keys: NPM_KEYS
            .iter()
            .map(|(keyid, key, expires)| PinnedKey {
                keyid: (*keyid).into(),
                key: (*key).into(),
                expires: expires.map(Into::into),
            })
            .collect(),
    }]
}

struct Key {
    keyid: String,
    vk: VerifyingKey,
    /// Unix seconds; a version published at or after this time does not count.
    expires: Option<i64>,
}

/// One entry of a keys document, kept verbatim in the TOFU record.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct RawKey {
    keyid: String,
    keytype: String,
    scheme: String,
    key: String,
    expires: Option<String>,
}

fn to_key(keyid: &str, key: &str, expires: Option<&str>) -> Result<Key, String> {
    let vk = B64
        .decode(key)
        .ok()
        .and_then(|der| VerifyingKey::from_public_key_der(&der).ok())
        .ok_or_else(|| format!("key {keyid} is not a P-256 public key"))?;
    let expires = match expires {
        None => None,
        Some(t) => Some(rfc3339(t).ok_or_else(|| format!("key {keyid} has a bad expiry"))?),
    };
    Ok(Key {
        keyid: keyid.into(),
        vk,
        expires,
    })
}

fn is_p256(k: &RawKey) -> bool {
    k.keytype == "ecdsa-sha2-nistp256" && k.scheme == "ecdsa-sha2-nistp256"
}

/// Usable keys of a set; keys of another type can never verify and are left out.
fn set_keys(set: &[RawKey]) -> Result<Vec<Key>, String> {
    set.iter()
        .filter(|k| is_p256(k))
        .map(|k| to_key(&k.keyid, &k.key, k.expires.as_deref()))
        .collect()
}

/// A keys document: 1..=32 entries, every P-256 key well formed.
fn parse_set(body: &[u8]) -> Result<Vec<RawKey>, String> {
    #[derive(Deserialize)]
    struct Doc {
        keys: Vec<RawKey>,
    }
    let doc: Doc =
        serde_json::from_slice(body).map_err(|e| format!("malformed keys document: {e}"))?;
    if doc.keys.is_empty() || doc.keys.len() > MAX_KEYS {
        return Err(format!("keys document lists {} keys", doc.keys.len()));
    }
    set_keys(&doc.keys)?;
    Ok(doc.keys)
}

fn same_set(a: &[RawKey], b: &[RawKey]) -> bool {
    let sorted = |s: &[RawKey]| {
        let mut v = s.to_vec();
        v.sort_by(|x, y| x.keyid.cmp(&y.keyid));
        v
    };
    sorted(a) == sorted(b)
}

// ------------------------------------------------------------ TOFU record

#[derive(Serialize, Deserialize, Debug)]
struct Record {
    registry: String,
    /// `None`: the registry published no keys when it was first seen.
    keys: Option<Vec<RawKey>>,
    /// Last time the keys endpoint confirmed this record (Unix seconds).
    checked_at: u64,
}

enum Stored {
    Missing,
    Valid(Record),
    Tampered,
}

fn record_path(paths: &TrustedPaths, url: &str) -> PathBuf {
    paths.state_dir.join(RECORD_DIR).join(format!(
        "{}.json",
        hex::encode(Sha256::digest(url.as_bytes()))
    ))
}

/// Per-user tag secret; created on first write only.
fn secret(paths: &TrustedPaths, create: bool) -> Option<[u8; 32]> {
    let path = paths.state_dir.join(SECRET_FILE);
    let read = || -> Option<[u8; 32]> { fsutil::read_bounded(&path, 32).ok()?.try_into().ok() };
    if let Some(k) = read() {
        return Some(k);
    }
    if !create {
        return None;
    }
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).ok()?;
    fsutil::atomic_write(&path, &k).ok()?;
    read() // racing creators settle on the file that won the rename
}

/// Covers the file name, so a valid record copied over another registry's
/// file does not verify.
fn tag(secret: &[u8; 32], path: &Path, body: &[u8]) -> Option<hmac::Hmac<Sha256>> {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret).ok()?;
    mac.update(path.file_name()?.as_encoded_bytes());
    mac.update(b"\0");
    mac.update(body);
    Some(mac)
}

fn read_record(paths: &TrustedPaths, url: &str) -> Stored {
    let path = record_path(paths, url);
    if !path.exists() {
        return Stored::Missing;
    }
    let verified = || -> Option<Record> {
        let bytes = fsutil::read_bounded(&path, 2 * KEYS_MAX_BYTES).ok()?;
        let nl = bytes.iter().position(|b| *b == b'\n')?;
        let (header, body) = (&bytes[..nl], &bytes[nl + 1..]);
        let stored = hex::decode(header.strip_prefix(TAG_PREFIX)?).ok()?;
        tag(&secret(paths, false)?, &path, body)?
            .verify_slice(&stored)
            .ok()?;
        let rec: Record = serde_json::from_slice(body).ok()?;
        (rec.registry == url).then_some(rec)
    };
    verified().map_or(Stored::Tampered, Stored::Valid)
}

fn write_record(paths: &TrustedPaths, rec: &Record) -> Result<(), String> {
    let path = record_path(paths, &rec.registry);
    let body = serde_json::to_vec(rec).map_err(|e| e.to_string())?;
    let secret = secret(paths, true).ok_or("cannot create the record tag key")?;
    let mac = tag(&secret, &path, &body).ok_or("cannot tag the record")?;
    let mut bytes = TAG_PREFIX.to_vec();
    bytes.extend_from_slice(hex::encode(mac.finalize().into_bytes()).as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&body);
    fsutil::atomic_write(&path, &bytes).map_err(|e| e.message)
}

/// `fail2commit signatures forget <registry-url>`: drop the trust-on-first-use
/// record so the next install records the registry's keys afresh. Returns a
/// description of what was removed.
pub fn forget(paths: &TrustedPaths, raw: &str) -> crate::Result<String> {
    let url = Registry::parse(raw)?.url;
    let path = record_path(paths, &url);
    let what = match read_record(paths, &url) {
        Stored::Missing => return Ok(format!("no signing keys were recorded for {url}")),
        Stored::Tampered => "a record that failed its integrity check".to_string(),
        Stored::Valid(Record { keys: None, .. }) => "the record that it signs nothing".into(),
        Stored::Valid(Record { keys: Some(k), .. }) => format!(
            "{} recorded signing key(s): {}",
            k.len(),
            k.iter()
                .map(|k| k.keyid.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    std::fs::remove_file(&path)?;
    Ok(format!("removed {what} for {url}"))
}

// ---------------------------------------------------------------- trust

enum Trust {
    /// `known`: keyids this binary ships for the registry (pinned only).
    Keys {
        keys: Vec<Key>,
        known: Option<Vec<String>>,
    },
    /// A registry that publishes no keys; `first` when just recorded.
    Unsigned { first: bool },
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into()
}

/// `Ok(None)`: the keys endpoint answered 404.
fn fetch_keys(url: &str) -> Result<Option<Vec<RawKey>>, String> {
    let resp = agent()
        .get(&format!("{url}-/npm/v1/keys"))
        .header("Accept", FULL)
        .header("Accept-Encoding", "identity")
        .header("User-Agent", USER_AGENT)
        .call();
    match resp {
        Ok(mut r) if r.status() == 200 => {
            let body = r
                .body_mut()
                .with_config()
                .limit(KEYS_MAX_BYTES)
                .read_to_vec()
                .map_err(|e| e.to_string())?;
            parse_set(&body).map(Some)
        }
        Ok(r) => Err(format!("unexpected HTTP status {}", r.status())),
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Which keys verify `reg`'s artifacts. `Err` is a deny reason.
fn trust(
    paths: &TrustedPaths,
    pinned: Option<&PinnedKeys>,
    reg: &Registry,
    ttl: u64,
) -> Result<Trust, String> {
    let url = &reg.url;
    let forget = format!("`fail2commit signatures forget {url}`");
    let rec = match read_record(paths, url) {
        Stored::Tampered => {
            return Err(format!(
                "the recorded signing keys of registry {url} failed their integrity check; \
                 if you trust the registry, run {forget}"
            ))
        }
        Stored::Missing => None,
        Stored::Valid(r) => Some(r),
    };
    let now = crate::approver::now_secs();
    let fresh = rec
        .as_ref()
        .filter(|r| r.checked_at <= now && now - r.checked_at < ttl);
    let observed = match fresh {
        Some(r) => r.keys.clone(),
        None => fetch_keys(url).map_err(|e| {
            format!("could not load the signing keys of registry {url}: {e}; signatures are unverifiable")
        })?,
    };
    let refetched = fresh.is_none();
    let save = |keys: Option<Vec<RawKey>>| {
        write_record(
            paths,
            &Record {
                registry: url.clone(),
                keys,
                checked_at: now,
            },
        )
        .map_err(|e| format!("could not record the signing keys of registry {url}: {e}"))
    };

    if let Some(p) = pinned {
        let set = observed.ok_or_else(|| {
            format!(
                "registry {url} publishes no signing keys, but this fail2commit version ships \
                 keys for it; signatures are unverifiable"
            )
        })?;
        if refetched {
            // Only spares a refetch within the TTL; trust comes from the binary.
            let _ = save(Some(set.clone()));
        }
        let keys = p
            .keys
            .iter()
            .filter(|k| set.iter().any(|s| s.keyid == k.keyid))
            .map(|k| to_key(&k.keyid, &k.key, k.expires.as_deref()))
            .collect::<Result<_, _>>()?;
        let known = p.keys.iter().map(|k| k.keyid.clone()).collect();
        return Ok(Trust::Keys {
            keys,
            known: Some(known),
        });
    }

    match (rec.map(|r| r.keys), observed) {
        (Some(Some(_)), None) => Err(format!(
            "registry {url} had signing keys recorded on first use but now publishes none; \
             if this is expected, run {forget}"
        )),
        (Some(Some(old)), Some(new)) if !same_set(&old, &new) => Err(format!(
            "the signing keys of registry {url} changed since first use; \
             if this is expected, run {forget}"
        )),
        (prev, None) => {
            if prev.is_none() {
                save(None)?;
            } else if refetched {
                let _ = save(None);
            }
            Ok(Trust::Unsigned {
                first: prev.is_none(),
            })
        }
        (prev, Some(new)) => {
            let keys = set_keys(&new)?;
            match prev {
                // First keys seen (or an unsigned registry that now signs).
                None | Some(None) => save(Some(new))?,
                Some(Some(_)) if refetched => {
                    let _ = save(Some(new));
                }
                Some(Some(_)) => {}
            }
            Ok(Trust::Keys { keys, known: None })
        }
    }
}

/// Signature and provenance findings for `plan`; empty when the check is off.
pub fn check(deps: &Deps<'_>, registry: &Registry, plan: &Plan) -> Vec<Finding> {
    let cfg = &deps.settings.signatures;
    if !cfg.verify {
        return vec![];
    }
    let url = &registry.url;
    let pinned = deps.pinned_keys.iter().find(|p| &p.registry == url);
    let (keys, known) = match trust(deps.paths, pinned, registry, cfg.keys_ttl_secs) {
        Ok(Trust::Keys { keys, known }) => (keys, known),
        Ok(Trust::Unsigned { first }) => {
            let why = if first {
                format!("registry {url} publishes no signing keys; signatures not verified")
            } else {
                format!(
                    "registry {url} publishes no signing keys (recorded as unsigned on first \
                     use); signatures not verified"
                )
            };
            let kind = FindingKind::IncompleteScan;
            return vec![Finding::new(kind, FindingAction::Approve, SOURCE, why)];
        }
        Err(why) => {
            let kind = FindingKind::SignatureInvalid;
            return vec![Finding::new(kind, FindingAction::Deny, SOURCE, why)];
        }
    };
    let ctx = Ctx {
        reg: registry,
        keys: &keys,
        known: known.as_deref(),
        max: META_MAX_BYTES.min(deps.settings.limits.artifact_max_bytes),
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
                    let f = match verify_pkg(&ctx, p) {
                        Ok(false) => continue,
                        Ok(true) => Finding::new(
                            FindingKind::ProvenanceMissing,
                            FindingAction::Approve,
                            SOURCE,
                            PROVENANCE_MSG,
                        ),
                        Err(Fail::Deny(why)) => Finding::new(
                            FindingKind::SignatureInvalid,
                            FindingAction::Deny,
                            SOURCE,
                            why,
                        ),
                        Err(Fail::Incomplete(why)) => Finding::new(
                            FindingKind::IncompleteScan,
                            FindingAction::Approve,
                            SOURCE,
                            why,
                        ),
                    };
                    out.lock()
                        .expect("findings")
                        .push(f.target(package_id(p).display()));
                }
            });
        }
    });
    let mut out = out.into_inner().expect("findings");
    out.sort_by(|a, b| a.target.cmp(&b.target));
    out
}

// ------------------------------------------------------------- metadata

/// Only the fields the check reads; everything else is skipped while
/// streaming, so a large packument never sits in memory.
#[derive(Deserialize)]
struct Doc {
    #[serde(default)]
    versions: BTreeMap<String, Version>,
    #[serde(default)]
    time: Option<BTreeMap<String, TimeVal>>,
}

#[derive(Deserialize)]
struct Version {
    dist: Option<Dist>,
}

#[derive(Deserialize)]
struct Dist {
    integrity: Option<String>,
    signatures: Option<Vec<Sig>>,
    attestations: Option<Attestations>,
}

#[derive(Deserialize)]
struct Sig {
    keyid: String,
    sig: String,
}

#[derive(Deserialize)]
struct Attestations {
    provenance: Option<IgnoredAny>,
}

/// `time` also holds `created`, `modified` and, for unpublished packages, an
/// object; only strings are publish times.
#[derive(Deserialize)]
#[serde(untagged)]
enum TimeVal {
    At(String),
    Other(IgnoredAny),
}

impl Doc {
    fn dist(&self, v: &str) -> Option<&Dist> {
        self.versions.get(v)?.dist.as_ref()
    }
    fn has_provenance(&self, v: &str) -> bool {
        self.dist(v)
            .and_then(|d| d.attestations.as_ref())
            .is_some_and(|a| a.provenance.is_some())
    }
    fn published(&self, v: &str) -> Option<i64> {
        match self.time.as_ref()?.get(v)? {
            TimeVal::At(t) => rfc3339(t),
            TimeVal::Other(_) => None,
        }
    }
    /// Another version with provenance published before `v`: by the `time`
    /// map when both times are known, by semver otherwise.
    fn earlier_provenance(&self, v: &str) -> bool {
        let this = self.published(v);
        self.versions
            .keys()
            .filter(|o| o.as_str() != v && self.has_provenance(o))
            .any(|o| match (this, self.published(o)) {
                (Some(a), Some(b)) => b < a,
                _ => semver_lt(o, v),
            })
    }
}

enum Fail {
    Deny(String),
    /// The check could not finish but nothing is known to be wrong.
    Incomplete(String),
}

struct Ctx<'a> {
    reg: &'a Registry,
    keys: &'a [Key],
    /// Keyids this binary ships for the registry (pinned registries only).
    known: Option<&'a [String]>,
    max: u64,
}

struct Counted<R> {
    inner: R,
    n: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n += n as u64;
        Ok(n)
    }
}

fn fetch_doc(url: &str, accept: &str, max: u64) -> Result<Doc, Fail> {
    let deny = Fail::Deny;
    let mut r = match agent()
        .get(url)
        .header("Accept", accept)
        .header("Accept-Encoding", "identity")
        .header("User-Agent", USER_AGENT)
        .call()
    {
        Ok(r) if r.status() == 200 => r,
        Ok(r) => return Err(deny(format!("unexpected HTTP status {}", r.status()))),
        Err(ureq::Error::StatusCode(404)) => {
            return Err(deny("the registry has no metadata for this package".into()))
        }
        Err(e) => return Err(deny(format!("could not fetch registry metadata: {e}"))),
    };
    let reader = r.body_mut().with_config().limit(u64::MAX).reader();
    let mut counted = Counted {
        inner: reader.take(max + 1),
        n: 0,
    };
    let parsed = serde_json::from_reader::<_, Doc>(std::io::BufReader::with_capacity(
        64 * 1024,
        &mut counted,
    ));
    if counted.n > max {
        return Err(Fail::Incomplete(format!(
            "registry metadata is larger than {max} bytes; signature not checked"
        )));
    }
    parsed.map_err(|e| deny(format!("registry metadata is not valid: {e}")))
}

/// `Ok(true)` when the signature is valid but provenance was dropped.
fn verify_pkg(cx: &Ctx<'_>, p: &PlanPkg) -> Result<bool, Fail> {
    let deny = |m: &str| Fail::Deny(m.to_string());
    let ok_name = !p.name.is_empty()
        && p.name.len() <= 214
        && p.name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@/._~-".contains(&b));
    if !ok_name {
        return Err(deny("package name cannot be looked up on the registry"));
    }
    let url = format!("{}{}", cx.reg.url, p.name.replacen('/', "%2f", 1));
    let v = p.version.as_str();
    let mut doc = fetch_doc(&url, CORGI, cx.max)?;
    // The abbreviated document has no `time` map, which key expiry and the
    // provenance ordering need; fetch the full one only then.
    let expiring = doc
        .dist(v)
        .and_then(|d| d.signatures.as_ref())
        .into_iter()
        .flatten()
        .any(|s| {
            cx.keys
                .iter()
                .any(|k| k.keyid == s.keyid && k.expires.is_some())
        });
    let needs_time = !doc.has_provenance(v) && doc.versions.keys().any(|o| doc.has_provenance(o));
    let no_sigs = doc.dist(v).is_none_or(|d| d.signatures.is_none());
    if doc.time.is_none() && (no_sigs || expiring || needs_time) {
        doc = fetch_doc(&url, FULL, cx.max)?;
    }
    let dist = doc
        .dist(v)
        .ok_or_else(|| Fail::Deny(format!("registry metadata has no version {v}")))?;
    let integrity = dist
        .integrity
        .as_deref()
        .ok_or_else(|| deny("registry metadata has no dist.integrity"))?;
    if integrity != p.integrity {
        return Err(deny(
            "registry metadata integrity differs from the lockfile integrity",
        ));
    }
    let sigs = dist
        .signatures
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| deny("no registry signature for this version"))?;
    if sigs.len() > MAX_SIGS {
        return Err(deny("too many registry signatures for this version"));
    }
    let msg = format!("{}@{v}:{integrity}", p.name);
    let published = doc.published(v);
    let mut why = String::new();
    for s in sigs {
        let Some(key) = cx.keys.iter().find(|k| k.keyid == s.keyid) else {
            if why.is_empty() {
                why = match cx.known {
                    Some(known) if !known.contains(&s.keyid) => UNKNOWN_KEY_MSG.into(),
                    _ => format!(
                        "signed with key {}, which registry {} does not list",
                        s.keyid, cx.reg.url
                    ),
                };
            }
            continue;
        };
        if let Some(exp) = key.expires {
            match published {
                None => {
                    why = format!(
                        "publish time unknown; expiry of key {} cannot be checked",
                        s.keyid
                    );
                    continue;
                }
                Some(t) if t >= exp => {
                    why = format!("signed with key {} after the key expired", s.keyid);
                    continue;
                }
                Some(_) => {}
            }
        }
        let valid = B64
            .decode(&s.sig)
            .ok()
            .and_then(|d| Signature::from_der(&d).ok())
            .is_some_and(|sig| key.vk.verify(msg.as_bytes(), &sig).is_ok());
        if valid {
            return Ok(!doc.has_provenance(v) && doc.earlier_provenance(v));
        }
        why = format!("registry signature by key {} is invalid", s.keyid);
    }
    Err(Fail::Deny(why))
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

    // Public data from registry.npmjs.org (read 2026-11-10): the signature
    // npm's registry made over left-pad@1.3.0.
    const LP_INTEGRITY: &str = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==";
    const LP_SIG: &str = "MEYCIQD6P3wA64go2fjiRW+yNvdi0x7Jtge3eAxAlwNaK2wyfQIhAKMCJXCFKygnFmsVuppuZIuNzTCYx2WlrJSg8B6wMqZk";

    fn builtin() -> Vec<Key> {
        builtin_keys()[0]
            .keys
            .iter()
            .map(|k| to_key(&k.keyid, &k.key, k.expires.as_deref()).unwrap())
            .collect()
    }

    #[test]
    fn the_builtin_npm_key_verifies_a_real_signature() {
        let keys = builtin();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].expires, Some(1_738_108_800));
        let sig = Signature::from_der(&B64.decode(LP_SIG).unwrap()).unwrap();
        let msg = format!("left-pad@1.3.0:{LP_INTEGRITY}");
        assert!(keys[0].vk.verify(msg.as_bytes(), &sig).is_ok());
        assert!(keys[1].vk.verify(msg.as_bytes(), &sig).is_err());
        let tampered = msg.replace("1.3.0", "1.3.1");
        assert!(keys[0].vk.verify(tampered.as_bytes(), &sig).is_err());
        assert_eq!(builtin_keys()[0].registry, DEFAULT_REGISTRY);
    }

    #[test]
    fn keys_documents_are_bounded_and_strict() {
        let one = r#"{"keyid":"k","keytype":"ecdsa-sha2-nistp256","scheme":"ecdsa-sha2-nistp256","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g==","expires":null}"#;
        assert_eq!(
            parse_set(format!(r#"{{"keys":[{one}]}}"#).as_bytes())
                .unwrap()
                .len(),
            1
        );
        for bad in [
            String::new(),
            "{}".into(),
            r#"{"keys":[]}"#.into(),
            format!(r#"{{"keys":[{}]}}"#, one.replace("MFkw", "AAAA")),
            format!(r#"{{"keys":[{}]}}"#, one.replace("null", "\"soon\"")),
            format!(r#"{{"keys":[{}]}}"#, vec![one; MAX_KEYS + 1].join(",")),
        ] {
            assert!(parse_set(bad.as_bytes()).is_err(), "{bad}");
        }
        let other = one.replace(
            r#""keytype":"ecdsa-sha2-nistp256""#,
            r#""keytype":"ed25519""#,
        );
        let set = parse_set(format!(r#"{{"keys":[{other}]}}"#).as_bytes()).unwrap();
        assert!(set_keys(&set).unwrap().is_empty());
    }

    #[test]
    fn records_are_tagged_and_bound_to_their_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = TrustedPaths::under(tmp.path());
        let url = "http://127.0.0.1:1/";
        assert!(matches!(read_record(&paths, url), Stored::Missing));
        let rec = Record {
            registry: url.into(),
            keys: None,
            checked_at: 7,
        };
        write_record(&paths, &rec).unwrap();
        assert!(matches!(read_record(&paths, url), Stored::Valid(r) if r.checked_at == 7));

        let path = record_path(&paths, url);
        let good = std::fs::read(&path).unwrap();
        // Edited body, record copied to another registry's file, lost secret.
        std::fs::write(&path, String::from_utf8_lossy(&good).replace(":7", ":8")).unwrap();
        assert!(matches!(read_record(&paths, url), Stored::Tampered));
        let other = "http://127.0.0.1:2/";
        std::fs::write(record_path(&paths, other), &good).unwrap();
        assert!(matches!(read_record(&paths, other), Stored::Tampered));
        std::fs::write(&path, &good).unwrap();
        std::fs::remove_file(paths.state_dir.join(SECRET_FILE)).unwrap();
        assert!(matches!(read_record(&paths, url), Stored::Tampered));

        let msg = forget(&paths, url).unwrap();
        assert!(msg.contains("removed") && msg.contains(url), "{msg}");
        assert!(matches!(read_record(&paths, url), Stored::Missing));
        assert!(forget(&paths, url)
            .unwrap()
            .contains("no signing keys were recorded"));
    }

    #[test]
    fn provenance_order_uses_publish_time_then_semver() {
        let doc: Doc = serde_json::from_str(
            r#"{"versions":{
                "1.0.0":{"dist":{}},
                "2.0.0":{"dist":{"attestations":{"provenance":{"predicateType":"x"}}}},
                "1.5.0":{"dist":{}}},
              "time":{"created":"2026-01-01T00:00:00Z","unpublished":{"x":1},
                "1.0.0":"2026-01-01T00:00:00Z","2.0.0":"2026-02-01T00:00:00Z",
                "1.5.0":"2026-03-01T00:00:00Z"}}"#,
        )
        .unwrap();
        assert!(doc.earlier_provenance("1.5.0"), "backport published later");
        assert!(!doc.earlier_provenance("1.0.0"));
        let no_time: Doc = serde_json::from_str(
            r#"{"versions":{"2.0.0":{"dist":{"attestations":{"provenance":{}}}},"1.5.0":{"dist":null}}}"#,
        )
        .unwrap();
        assert!(!no_time.earlier_provenance("1.5.0"), "semver fallback");
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
    fn live_left_pad_verifies_with_builtin_keys() {
        let reg = Registry::parse(DEFAULT_REGISTRY).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let paths = TrustedPaths::under(tmp.path());
        let pinned = builtin_keys();
        let t0 = std::time::Instant::now();
        let Ok(Trust::Keys { keys, known }) = trust(&paths, Some(&pinned[0]), &reg, 0) else {
            panic!("npm keys not trusted")
        };
        let t1 = std::time::Instant::now();
        let p = PlanPkg {
            path: "node_modules/left-pad".into(),
            name: "left-pad".into(),
            version: "1.3.0".into(),
            resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into(),
            integrity: LP_INTEGRITY.into(),
            optional: false,
            skip_platform: false,
        };
        let cx = Ctx {
            reg: &reg,
            keys: &keys,
            known: known.as_deref(),
            max: META_MAX_BYTES,
        };
        assert!(matches!(verify_pkg(&cx, &p), Ok(false)));
        eprintln!("keys {:?}, left-pad {:?}", t1 - t0, t1.elapsed());
    }
}
