//! Force-push password and recovery code state (FR-002, SPEC-002).
//!
//! One private JSON file, `state_dir/password.json`, holds Argon2id
//! verifiers (salt, hash, recorded cost parameters), a generation counter
//! bumped on every set/change/reset/disable, and the persisted failed-attempt
//! counter. Every read-modify-write runs under `fsutil::with_lock`, so
//! concurrent attempts from several processes serialize and cannot lose a
//! failure count.

use crate::digest::ct_eq;
use crate::paths::TrustedPaths;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_SECRET_BYTES: usize = 1024;
/// Failures allowed before backoff starts.
pub const FREE_ATTEMPTS: u32 = 3;
/// First lockout; doubles per further failure up to [`MAX_LOCKOUT_SECS`].
pub const BASE_LOCKOUT_SECS: u64 = 30;
pub const MAX_LOCKOUT_SECS: u64 = 3600;
const STATE_VERSION: u32 = 1;
const STATE_MAX_BYTES: u64 = 64 * 1024;
/// Recovery code entropy: 20 bytes = 160 bits = 32 Crockford base32 chars.
const RECOVERY_BYTES: usize = 20;
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Argon2id cost parameters, recorded with each verifier.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Kdf {
    pub alg: String,
    pub version: u32,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub len: usize,
}

impl Kdf {
    /// OWASP minimum recommendation for Argon2id (19 MiB, 2 passes, 1 lane).
    pub fn recommended() -> Kdf {
        Kdf {
            alg: "argon2id".into(),
            version: 0x13,
            m_kib: 19 * 1024,
            t: 2,
            p: 1,
            len: 32,
        }
    }

    // Unit tests hash dozens of times in a debug build; integration tests and
    // release builds use the recommended cost.
    fn current() -> Kdf {
        if cfg!(test) {
            Kdf {
                m_kib: 64,
                t: 1,
                ..Kdf::recommended()
            }
        } else {
            Kdf::recommended()
        }
    }

    fn hash(&self, secret: &[u8], salt: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
        // Recorded parameters come from trusted state, but bound them so a
        // damaged file fails closed instead of exhausting memory.
        let sane = self.alg == "argon2id"
            && self.version == 0x13
            && (8..=1024 * 1024).contains(&self.m_kib)
            && (1..=16).contains(&self.t)
            && (1..=8).contains(&self.p)
            && (16..=64).contains(&self.len);
        if !sane {
            return Err(crate::Error::invalid(
                "password state has unsupported KDF parameters",
            ));
        }
        let params = argon2::Params::new(self.m_kib, self.t, self.p, Some(self.len))
            .map_err(|e| crate::Error::internal(format!("argon2 params: {e}")))?;
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = Zeroizing::new(vec![0u8; self.len]);
        a.hash_password_into(secret, salt, &mut out)
            .map_err(|e| crate::Error::internal(format!("argon2: {e}")))?;
        Ok(out)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct Verifier {
    kdf: Kdf,
    salt: String,
    hash: String,
}

impl Verifier {
    fn new(secret: &[u8]) -> crate::Result<Verifier> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt)
            .map_err(|e| crate::Error::internal(format!("OS random source failed: {e}")))?;
        let kdf = Kdf::current();
        let hash = kdf.hash(secret, &salt)?;
        Ok(Verifier {
            kdf,
            salt: hex::encode(salt),
            hash: hex::encode(&*hash),
        })
    }

    fn matches(&self, secret: &[u8]) -> crate::Result<bool> {
        let salt = hex::decode(&self.salt)
            .map_err(|_| crate::Error::invalid("password state is damaged"))?;
        let want = Zeroizing::new(
            hex::decode(&self.hash)
                .map_err(|_| crate::Error::invalid("password state is damaged"))?,
        );
        let got = self.kdf.hash(secret, &salt)?;
        Ok(ct_eq(&got, &want))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    version: u32,
    /// Bumped on set/change/reset/disable; binds pending approvals.
    pub(crate) generation: u64,
    password: Option<Verifier>,
    recovery: Option<Verifier>,
    pub(crate) failures: u32,
    pub(crate) locked_until: u64,
    changed_at: u64,
}

impl State {
    pub(crate) fn enabled(&self) -> bool {
        self.password.is_some()
    }
}

/// A recovery code. Shown once; `Debug`/`Display` never reveal it.
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    fn generate() -> crate::Result<RecoveryCode> {
        let mut raw = Zeroizing::new([0u8; RECOVERY_BYTES]);
        getrandom::fill(&mut *raw)
            .map_err(|e| crate::Error::internal(format!("OS random source failed: {e}")))?;
        let mut s = Zeroizing::new(String::with_capacity(40));
        let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
        for b in raw.iter() {
            acc = (acc << 8) | u32::from(*b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                if n > 0 && n % 4 == 0 {
                    s.push('-');
                }
                s.push(CROCKFORD[((acc >> bits) & 31) as usize] as char);
                n += 1;
            }
        }
        Ok(RecoveryCode(s))
    }

    /// The code text, for one-time display on the console.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

/// Canonical form of a typed recovery code (Crockford: case-insensitive,
/// separators ignored, O->0, I/L->1). `None` if it cannot be a code.
fn normalize_recovery(input: &str) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(32));
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' | '\t' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !CROCKFORD.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == RECOVERY_BYTES * 8 / 5).then_some(out)
}

/// Public, secret-free summary for `password status`.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub enabled: bool,
    pub generation: u64,
    pub failed_attempts: u32,
    pub locked_for_secs: u64,
    pub kdf: Option<Kdf>,
}

fn state_file(paths: &TrustedPaths) -> PathBuf {
    paths.state_dir.join("password.json")
}

pub(crate) fn load(paths: &TrustedPaths) -> crate::Result<State> {
    let file = state_file(paths);
    match crate::fsutil::read_bounded(&file, STATE_MAX_BYTES) {
        Ok(bytes) => {
            let s: State = serde_json::from_slice(&bytes)
                .map_err(|_| crate::Error::invalid("password state is damaged; refusing"))?;
            if s.version != STATE_VERSION {
                return Err(crate::Error::invalid("password state has unknown version"));
            }
            Ok(s)
        }
        Err(_) if !file.exists() => Ok(State {
            version: STATE_VERSION,
            ..State::default()
        }),
        Err(e) => Err(e),
    }
}

fn store(paths: &TrustedPaths, s: &State) -> crate::Result<()> {
    let bytes = serde_json::to_vec_pretty(s)
        .map_err(|e| crate::Error::internal(format!("serialize password state: {e}")))?;
    crate::fsutil::atomic_write(&state_file(paths), &bytes)
}

/// Read-modify-write under the state lock.
fn locked<T>(
    paths: &TrustedPaths,
    f: impl FnOnce(&mut State) -> crate::Result<T>,
) -> crate::Result<T> {
    crate::fsutil::ensure_private_dir(&paths.state_dir)?;
    crate::fsutil::with_lock(&state_file(paths), || {
        let mut s = load(paths)?;
        let out = f(&mut s)?;
        store(paths, &s)?;
        Ok(out)
    })
}

fn lockout_secs(failures: u32) -> u64 {
    if failures < FREE_ATTEMPTS {
        return 0;
    }
    let exp = (failures - FREE_ATTEMPTS).min(16);
    BASE_LOCKOUT_SECS
        .saturating_mul(1u64 << exp)
        .min(MAX_LOCKOUT_SECS)
}

/// Rate-limited check. `check` returns whether the secret matched; on a
/// match `apply` mutates the state. Failures are persisted before the error
/// is returned, so a crash or kill cannot reset the counter.
fn attempt<T>(
    paths: &TrustedPaths,
    what: &str,
    check: impl FnOnce(&State) -> crate::Result<bool>,
    apply: impl FnOnce(&mut State) -> crate::Result<T>,
) -> crate::Result<T> {
    let now = crate::approver::now_secs();
    let mut outcome: Option<crate::Result<T>> = None;
    let res = locked(paths, |s| {
        if s.locked_until > now {
            outcome = Some(Err(crate::Error::rejected(format!(
                "too many failed attempts; try again in {} s",
                s.locked_until - now
            ))));
            return Ok(());
        }
        if check(s)? {
            s.failures = 0;
            s.locked_until = 0;
            outcome = Some(apply(s));
        } else {
            s.failures = s.failures.saturating_add(1);
            let wait = lockout_secs(s.failures);
            if wait > 0 {
                s.locked_until = now.saturating_add(wait);
            }
            outcome = Some(Err(crate::Error::rejected(format!("wrong {what}"))));
        }
        Ok(())
    });
    res?;
    outcome.unwrap_or_else(|| Err(crate::Error::internal("password attempt did not run")))
}

fn check_new_password(new: &str) -> crate::Result<()> {
    if new.chars().count() < MIN_PASSWORD_CHARS {
        return Err(crate::Error::invalid(format!(
            "password must have at least {MIN_PASSWORD_CHARS} characters"
        )));
    }
    if new.len() > MAX_SECRET_BYTES || new.chars().any(char::is_control) {
        return Err(crate::Error::invalid(
            "password is too long or contains control characters",
        ));
    }
    Ok(())
}

fn bump(s: &mut State) {
    s.generation = s.generation.saturating_add(1);
    s.changed_at = crate::approver::now_secs();
}

pub fn enabled(paths: &TrustedPaths) -> crate::Result<bool> {
    Ok(load(paths)?.password.is_some())
}

pub fn status(paths: &TrustedPaths) -> crate::Result<Status> {
    let s = load(paths)?;
    let now = crate::approver::now_secs();
    Ok(Status {
        enabled: s.password.is_some(),
        generation: s.generation,
        failed_attempts: s.failures,
        locked_for_secs: s.locked_until.saturating_sub(now),
        kdf: s.password.as_ref().map(|v| v.kdf.clone()),
    })
}

/// Enable the password. Returns the recovery code to show once.
pub fn set(paths: &TrustedPaths, new: &str) -> crate::Result<RecoveryCode> {
    check_new_password(new)?;
    let code = RecoveryCode::generate()?;
    let norm = normalize_recovery(code.expose())
        .ok_or_else(|| crate::Error::internal("generated recovery code is malformed"))?;
    let pw = Verifier::new(new.as_bytes())?;
    let rc = Verifier::new(norm.as_bytes())?;
    locked(paths, |s| {
        if s.password.is_some() {
            return Err(crate::Error::invalid(
                "a password is already set; use `password change` or `password reset`",
            ));
        }
        s.password = Some(pw);
        s.recovery = Some(rc);
        s.failures = 0;
        s.locked_until = 0;
        bump(s);
        Ok(())
    })?;
    Ok(code)
}

fn require_enabled(s: &State) -> crate::Result<&Verifier> {
    s.password
        .as_ref()
        .ok_or_else(|| crate::Error::invalid("no force-push password is set"))
}

/// Replace the password after verifying the current one. The recovery code
/// is kept; pending approvals are invalidated.
pub fn change(paths: &TrustedPaths, current: &str, new: &str) -> crate::Result<()> {
    check_new_password(new)?;
    let pw = Verifier::new(new.as_bytes())?;
    attempt(
        paths,
        "password",
        |s| require_enabled(s)?.matches(current.as_bytes()),
        |s| {
            s.password = Some(pw);
            bump(s);
            Ok(())
        },
    )
}

/// Turn the password off after verifying the current one.
pub fn disable(paths: &TrustedPaths, current: &str) -> crate::Result<()> {
    attempt(
        paths,
        "password",
        |s| require_enabled(s)?.matches(current.as_bytes()),
        |s| {
            s.password = None;
            s.recovery = None;
            bump(s);
            Ok(())
        },
    )
}

/// Set a new password with the recovery code. Rotates the recovery code
/// (the old one stops working) and invalidates pending approvals.
pub fn reset(paths: &TrustedPaths, recovery: &str, new: &str) -> crate::Result<RecoveryCode> {
    check_new_password(new)?;
    let code = RecoveryCode::generate()?;
    let norm = normalize_recovery(code.expose())
        .ok_or_else(|| crate::Error::internal("generated recovery code is malformed"))?;
    let pw = Verifier::new(new.as_bytes())?;
    let rc = Verifier::new(norm.as_bytes())?;
    let typed = normalize_recovery(recovery);
    attempt(
        paths,
        "recovery code",
        |s| {
            let v = s
                .recovery
                .as_ref()
                .ok_or_else(|| crate::Error::invalid("no recovery code is set"))?;
            match &typed {
                Some(t) => v.matches(t.as_bytes()),
                None => Ok(false),
            }
        },
        |s| {
            s.password = Some(pw);
            s.recovery = Some(rc);
            bump(s);
            Ok(())
        },
    )?;
    Ok(code)
}

/// Verify the password for an approval minted under `generation`.
pub(crate) fn verify_for_request(
    paths: &TrustedPaths,
    password: &str,
    generation: u64,
) -> crate::Result<()> {
    attempt(
        paths,
        "password",
        |s| {
            if s.generation != generation {
                return Err(crate::Error::rejected(
                    "password state changed after the request was created; retry the operation",
                ));
            }
            if password.len() > MAX_SECRET_BYTES {
                return Ok(false);
            }
            require_enabled(s)?.matches(password.as_bytes())
        },
        |_| Ok(()),
    )
}

/// Refuse to run if a secret seems to be supplied through the environment.
/// The value is never read or echoed.
pub fn reject_secret_env() -> crate::Result<()> {
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().to_ascii_uppercase();
        if k.starts_with("FAIL2COMMIT_")
            && ["PASSWORD", "RECOVERY", "PASSPHRASE", "SECRET"]
                .iter()
                .any(|w| k.contains(w))
        {
            return Err(crate::Error::invalid(format!(
                "{k} is set: passwords and recovery codes are accepted only from hidden console input; unset it"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn force_lock(paths: &TrustedPaths, locked_until: u64) {
    locked(paths, |s| {
        s.locked_until = locked_until;
        Ok(())
    })
    .unwrap();
}

#[cfg(test)]
pub(crate) fn normalize_for_test(input: &str) -> Option<String> {
    normalize_recovery(input).map(|z| z.to_string())
}
