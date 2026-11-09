//! Effective npm configuration (SPEC-004): the registry is pinned from
//! trusted state only; project `.npmrc` may carry a small allowlist of
//! behavior settings and nothing else.

use crate::paths::TrustedPaths;
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;

pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org/";

/// Settings a project `.npmrc` may carry. Everything else (registry,
/// script-shell, git, prefix, cache, proxies, auth, ...) is untrusted.
const PROJECT_ALLOWED: &[&str] = &[
    "save-exact",
    "save-prefix",
    "legacy-peer-deps",
    "strict-peer-deps",
    "engine-strict",
    "omit",
    "include",
    "install-strategy",
    "prefer-dedupe",
    "loglevel",
    "progress",
    // Accepted but overridden by the staged config.
    "fund",
    "audit",
    "update-notifier",
    "ignore-scripts",
];

/// The pinned registry. `url` always ends with `/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    pub url: String,
    origin: String,
    path: String,
}

#[derive(Debug)]
struct UrlParts<'a> {
    scheme: String,
    /// Lowercase `host[:port]` with the scheme's default port removed.
    authority: String,
    host: &'a str,
    path: &'a str,
}

fn split_url(url: &str) -> Option<UrlParts<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if auth.is_empty() || auth.contains('@') || url.contains(['?', '#', '\\']) {
        return None;
    }
    let (host, port) = match auth.rfind(':') {
        Some(i) if !auth.ends_with(']') => (&auth[..i], Some(&auth[i + 1..])),
        _ => (auth, None),
    };
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let default = match scheme.as_str() {
        "https" => "443",
        "http" => "80",
        _ => return None,
    };
    let authority = match port {
        Some(p) if p == default => host.to_ascii_lowercase(),
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
            format!("{}:{p}", host.to_ascii_lowercase())
        }
        Some(_) => return None,
        None => host.to_ascii_lowercase(),
    };
    Some(UrlParts {
        scheme,
        authority,
        host,
        path,
    })
}

fn is_loopback(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "[::1]"
    )
}

impl Registry {
    pub fn parse(raw: &str) -> Result<Registry> {
        let raw = raw.trim();
        let bad = |why: &str| Error::invalid(format!("untrusted npm registry setting: {why}"));
        let p = split_url(raw).ok_or_else(|| bad("not a plain http(s) URL"))?;
        if p.scheme == "http" && !is_loopback(p.host) {
            return Err(bad("plain http is only allowed for loopback"));
        }
        if p.path.split('/').any(|s| s == ".." || s == ".") {
            return Err(bad("path traversal"));
        }
        let mut path = p.path.to_string();
        if !path.ends_with('/') {
            path.push('/');
        }
        let origin = format!("{}://{}", p.scheme, p.authority);
        Ok(Registry {
            url: format!("{origin}{path}"),
            origin,
            path,
        })
    }

    /// True when `url` is served by this registry (same origin, under the
    /// registry path, no userinfo/query/fragment/traversal).
    pub fn serves(&self, url: &str) -> bool {
        let Some(p) = split_url(url) else {
            return false;
        };
        let origin = format!("{}://{}", p.scheme, p.authority);
        origin == self.origin
            && p.path.starts_with(&self.path)
            && !p.path.split('/').any(|s| s == ".." || s == ".")
    }
}

fn parse_ini(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with(['#', ';']) {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            let v = v.trim().trim_matches(['"', '\'']);
            Some((k.trim().to_string(), v.to_string()))
        })
        .collect()
}

/// Registry from trusted state: `<config_dir>/npmrc`, else the user's
/// `~/.npmrc` (skipped when `FAIL2COMMIT_HOME` relocates trusted state), else
/// the npm default. Only `registry=` is read; credentials are never used.
pub fn trusted_registry(paths: &TrustedPaths) -> Result<Registry> {
    let mut candidates = vec![paths.config_dir.join("npmrc")];
    if std::env::var_os("FAIL2COMMIT_HOME").is_none_or(|v| v.is_empty()) {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
        if let Some(h) = home.filter(|h| !h.is_empty()) {
            candidates.push(Path::new(&h).join(".npmrc"));
        }
    }
    for file in candidates {
        if !file.is_file() {
            continue;
        }
        let bytes = crate::fsutil::read_bounded(&file, 64 * 1024)?;
        let text = String::from_utf8_lossy(&bytes);
        if let Some((_, v)) = parse_ini(&text)
            .into_iter()
            .rev()
            .find(|(k, _)| k == "registry")
        {
            if v.contains("${") {
                return Err(Error::invalid(
                    "untrusted npm registry setting: environment references are not allowed",
                ));
            }
            return Registry::parse(&v);
        }
    }
    Registry::parse(DEFAULT_REGISTRY)
}

/// Allowlisted settings from the project `.npmrc`. Any other key is a hard
/// stop: the guard never silently drops or forwards untrusted settings.
/// Allowlisted settings plus the raw file bytes (for the input fingerprint).
pub type ProjectConfig = (BTreeMap<String, String>, Option<Vec<u8>>);

pub fn project_settings(project: &Path) -> Result<ProjectConfig> {
    let file = project.join(".npmrc");
    if !file.is_file() {
        return Ok((BTreeMap::new(), None));
    }
    let bytes = crate::fsutil::read_bounded(&file, 64 * 1024)?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut out = BTreeMap::new();
    let mut findings = Vec::new();
    for (k, v) in parse_ini(&text) {
        if PROJECT_ALLOWED.contains(&k.as_str()) && !v.contains("${") && !v.contains('\n') {
            out.insert(k, v);
        } else {
            // Report the key only: values may be credentials.
            findings.push(
                Finding::new(
                    FindingKind::UnsupportedInput,
                    FindingAction::Deny,
                    "npm.config",
                    format!("project .npmrc setting `{}` is untrusted", k),
                )
                .location(".npmrc"),
            );
        }
    }
    if !findings.is_empty() {
        return Err(
            Error::invalid("project .npmrc contains untrusted npm settings")
                .with_findings(findings),
        );
    }
    Ok((out, Some(bytes)))
}

/// Contents of the staged `--userconfig`: pinned registry, allowlisted
/// project settings, and the settings the guard always forces.
pub fn staged_userconfig(registry: &Registry, project: &BTreeMap<String, String>) -> String {
    let mut s = String::new();
    for (k, v) in project {
        if !matches!(
            k.as_str(),
            "fund" | "audit" | "update-notifier" | "ignore-scripts"
        ) {
            s.push_str(&format!("{k}={v}\n"));
        }
    }
    s.push_str(&format!("registry={}\n", registry.url));
    s.push_str(
        "ignore-scripts=true\naudit=false\nfund=false\nupdate-notifier=false\n\
         replace-registry-host=never\nfetch-retries=1\nprogress=false\nloglevel=error\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_pinning() {
        let r = Registry::parse("https://registry.npmjs.org").unwrap();
        assert_eq!(r.url, DEFAULT_REGISTRY);
        assert!(r.serves("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"));
        assert!(r.serves("https://REGISTRY.npmjs.org:443/x/-/x-1.0.0.tgz"));
        assert!(!r.serves("https://evil.example/left-pad/-/left-pad-1.3.0.tgz"));
        assert!(!r.serves("http://registry.npmjs.org/x.tgz"));
        assert!(!r.serves("https://registry.npmjs.org@evil.example/x.tgz"));
        assert!(!r.serves("https://registry.npmjs.org/../x.tgz"));
        assert!(Registry::parse("http://registry.example/").is_err());
        assert!(Registry::parse("http://127.0.0.1:4873/").is_ok());
        assert!(Registry::parse("https://u:p@registry.example/").is_err());
        assert!(Registry::parse("git+https://example/x").is_err());
        let sub = Registry::parse("https://mirror.example/npm/").unwrap();
        assert!(sub.serves("https://mirror.example/npm/a/-/a-1.tgz"));
        assert!(!sub.serves("https://mirror.example/other/a-1.tgz"));
    }

    #[test]
    fn project_npmrc_allowlist() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".npmrc"), "save-exact=true\n# c\n").unwrap();
        let (s, _) = project_settings(d.path()).unwrap();
        assert_eq!(s["save-exact"], "true");
        for bad in [
            "registry=https://evil.example/",
            "script-shell=/tmp/x",
            "git=/tmp/git",
            "@s:registry=https://evil.example/",
            "//evil.example/:_authToken=x",
            "omit=${EVIL}",
        ] {
            std::fs::write(d.path().join(".npmrc"), bad).unwrap();
            let e = project_settings(d.path()).unwrap_err();
            assert_eq!(e.code, crate::ResultCode::InvalidInput, "{bad}");
            assert!(
                !e.findings[0].evidence.contains("https://"),
                "values are not echoed"
            );
        }
    }
}
