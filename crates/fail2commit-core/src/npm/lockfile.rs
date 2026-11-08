//! The exact lockfile graph (SPEC-004): every package's name, version,
//! pinned-registry URL and strong integrity, validated before any download.

use super::config::Registry;
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::{Error, Result};
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanPkg {
    /// Lockfile key, e.g. `node_modules/a/node_modules/b`.
    pub path: String,
    pub name: String,
    pub version: String,
    pub resolved: String,
    pub integrity: String,
    pub optional: bool,
    /// `optional` and not installable on this OS/CPU: reviewed but not fetched.
    pub skip_platform: bool,
}

#[derive(Clone, Debug)]
pub struct Plan {
    /// Sorted by `path`.
    pub pkgs: Vec<PlanPkg>,
}

fn deny(msg: impl Into<String>, target: &str) -> Error {
    let msg = msg.into();
    Error::invalid(msg.clone()).with_findings(vec![Finding::new(
        FindingKind::UnsupportedInput,
        FindingAction::Deny,
        "npm.lockfile",
        msg,
    )
    .target(target.to_string())])
}

fn platform_ok(list: Option<&serde_json::Value>, current: &str) -> bool {
    let Some(items) = list.and_then(|v| v.as_array()) else {
        return true;
    };
    let names: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
    if names.is_empty() {
        return true;
    }
    if names.iter().any(|n| *n == format!("!{current}")) {
        return false;
    }
    let allow: Vec<_> = names.iter().filter(|n| !n.starts_with('!')).collect();
    allow.is_empty() || allow.iter().any(|n| **n == current)
}

fn node_os() -> &'static str {
    match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        o => o,
    }
}

fn node_cpu() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        a => a,
    }
}

/// Parse and validate `package-lock.json` bytes against the pinned registry.
pub fn parse(bytes: &[u8], registry: &Registry, max_nodes: u64) -> Result<Plan> {
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| Error::invalid(format!("package-lock.json is not valid JSON: {e}")))?;
    let version = v
        .get("lockfileVersion")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let packages = v.get("packages").and_then(|p| p.as_object());
    let (true, Some(packages)) = ((2..=3).contains(&version), packages) else {
        return Err(deny(
            "only lockfileVersion 2 or 3 with a packages map is supported",
            "package-lock.json",
        ));
    };
    if packages.len() as u64 > max_nodes {
        return Err(Error::incomplete(format!(
            "lockfile has {} packages, over the {max_nodes} limit",
            packages.len()
        )));
    }
    let mut pkgs = Vec::new();
    for (key, e) in packages {
        if key.is_empty() {
            continue;
        }
        let target = key.as_str();
        let segs: Vec<&str> = key.split('/').collect();
        if key.contains('\\')
            || key.starts_with('/')
            || segs
                .iter()
                .any(|s| s.is_empty() || *s == ".." || *s == "." || s.contains(':'))
            || segs[0] != "node_modules"
        {
            return Err(deny(
                "lockfile entry is outside node_modules (workspace or path package)",
                target,
            ));
        }
        let name = key
            .rsplit_once("node_modules/")
            .map(|(_, n)| n)
            .unwrap_or(key);
        if e.get("link").and_then(|l| l.as_bool()) == Some(true) {
            return Err(deny("linked packages are not supported", target));
        }
        if e.get("inBundle").and_then(|l| l.as_bool()) == Some(true) {
            return Err(deny("bundled dependencies are not supported", target));
        }
        if let Some(n) = e.get("name").and_then(|n| n.as_str()) {
            if n != name {
                return Err(deny("package aliases are not supported", target));
            }
        }
        let s = |k: &str| e.get(k).and_then(|x| x.as_str()).unwrap_or("");
        let (version, resolved, integrity) = (s("version"), s("resolved"), s("integrity"));
        if version.is_empty() || resolved.is_empty() {
            return Err(deny(
                "lockfile entry has no registry source (git, file or bundled package)",
                target,
            ));
        }
        if !registry.serves(resolved) {
            return Err(deny(
                format!(
                    "resolved URL is not on the pinned registry {}: {}",
                    registry.url,
                    crate::redact::redact_url_credentials(resolved)
                ),
                target,
            ));
        }
        if !has_sha512(integrity) {
            return Err(deny("lockfile entry lacks a sha512 integrity", target));
        }
        let optional = e.get("optional").and_then(|o| o.as_bool()) == Some(true);
        let skip_platform = optional
            && !(platform_ok(e.get("os"), node_os()) && platform_ok(e.get("cpu"), node_cpu()));
        pkgs.push(PlanPkg {
            path: key.clone(),
            name: name.to_string(),
            version: version.to_string(),
            resolved: resolved.to_string(),
            integrity: integrity.to_string(),
            optional,
            skip_platform,
        });
    }
    pkgs.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Plan { pkgs })
}

fn tokens(sri: &str) -> impl Iterator<Item = (&str, &str)> {
    sri.split_whitespace().filter_map(|t| {
        let (alg, rest) = t.split_once('-')?;
        Some((alg, rest.split('?').next().unwrap_or(rest)))
    })
}

fn has_sha512(sri: &str) -> bool {
    tokens(sri).any(|(a, d)| a == "sha512" && !d.is_empty())
}

/// True when the strongest digest named in `sri` matches `data`.
pub fn verify_sri(sri: &str, data: &[u8]) -> bool {
    let rank = |a: &str| match a {
        "sha256" => 1,
        "sha384" => 2,
        "sha512" => 3,
        _ => 0,
    };
    let best = tokens(sri).map(|(a, _)| rank(a)).max().unwrap_or(0);
    if best == 0 {
        return false;
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    tokens(sri).filter(|(a, _)| rank(a) == best).any(|(a, d)| {
        let Ok(want) = b64.decode(d) else {
            return false;
        };
        let got: Vec<u8> = match a {
            "sha256" => Sha256::digest(data).to_vec(),
            "sha384" => Sha384::digest(data).to_vec(),
            _ => Sha512::digest(data).to_vec(),
        };
        crate::digest::ct_eq(&got, &want)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sri512(data: &[u8]) -> String {
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(data))
        )
    }

    #[test]
    fn sri_checks() {
        let good = sri512(b"abc");
        assert!(verify_sri(&good, b"abc"));
        assert!(!verify_sri(&good, b"abd"));
        // A weak token never rescues a mismatching strong one.
        let mixed = format!("sha1-AAAA {good}");
        assert!(!verify_sri(&mixed, b"abd"));
        assert!(!verify_sri("sha1-AAAA", b"abc"));
        assert!(!verify_sri("", b"abc"));
    }

    fn lock(entry: &str) -> Vec<u8> {
        format!(
            r#"{{"lockfileVersion":3,"packages":{{"":{{"name":"p"}},"node_modules/a":{entry}}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn plan_validation() {
        let reg = Registry::parse("https://registry.npmjs.org/").unwrap();
        let sri = sri512(b"x");
        let ok = format!(
            r#"{{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"{sri}"}}"#
        );
        let plan = parse(&lock(&ok), &reg, 10).unwrap();
        assert_eq!(plan.pkgs[0].name, "a");
        assert!(!plan.pkgs[0].skip_platform);

        for bad in [
            format!(r#"{{"version":"1.0.0","resolved":"https://evil.example/a-1.0.0.tgz","integrity":"{sri}"}}"#),
            format!(r#"{{"version":"1.0.0","resolved":"git+ssh://git@github.com/u/a.git#abc","integrity":"{sri}"}}"#),
            format!(r#"{{"version":"1.0.0","resolved":"file:../a","integrity":"{sri}"}}"#),
            r#"{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}"#.to_string(),
            r#"{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha1-AAAA"}"#.to_string(),
            r#"{"resolved":"file:../a","link":true}"#.to_string(),
            format!(r#"{{"name":"other","version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"{sri}"}}"#),
            format!(r#"{{"version":"1.0.0","inBundle":true,"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"{sri}"}}"#),
        ] {
            let e = parse(&lock(&bad), &reg, 10).unwrap_err();
            assert_eq!(e.code, crate::ResultCode::InvalidInput, "{bad}");
        }
        assert!(parse(br#"{"lockfileVersion":1}"#, &reg, 10).is_err());
        assert_eq!(
            parse(&lock(&ok), &reg, 0).unwrap_err().code,
            crate::ResultCode::IncompleteScan
        );
    }

    #[test]
    fn platform_skip() {
        let reg = Registry::parse("https://registry.npmjs.org/").unwrap();
        let sri = sri512(b"x");
        let other = if node_os() == "win32" {
            "linux"
        } else {
            "win32"
        };
        let e = format!(
            r#"{{"version":"1.0.0","optional":true,"os":["{other}"],"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"{sri}"}}"#
        );
        assert!(parse(&lock(&e), &reg, 10).unwrap().pkgs[0].skip_platform);
        let neg = format!(
            r#"{{"version":"1.0.0","optional":true,"os":["!{}"],"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"{sri}"}}"#,
            node_os()
        );
        assert!(parse(&lock(&neg), &reg, 10).unwrap().pkgs[0].skip_platform);
    }
}
