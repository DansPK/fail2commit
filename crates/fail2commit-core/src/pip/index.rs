//! The pinned registry: policy, project pages (PEP 503 / PEP 691) and
//! hash-checked, size-bounded wheel downloads.

use crate::paths::TrustedPaths;
use crate::Error;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_INDEX: &str = "https://pypi.org/simple";
const DEFAULT_FILE_HOSTS: [&str; 1] = ["files.pythonhosted.org"];
const MAX_PAGE_BYTES: u64 = 32 * 1024 * 1024;

/// Trusted `pip.toml` in the user's config directory. A workspace can never
/// change it, and `PIP_*` / pip config files are rejected, not honored.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct PipSettings {
    index_url: Option<String>,
    /// Extra hosts wheel files may come from (besides the index host).
    file_hosts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexPolicy {
    /// No trailing slash.
    pub url: String,
    pub file_hosts: Vec<String>,
}

impl IndexPolicy {
    pub fn load(paths: &TrustedPaths) -> crate::Result<IndexPolicy> {
        let file = paths.config_dir.join("pip.toml");
        let s: PipSettings = match crate::fsutil::read_bounded(&file, 16 * 1024) {
            Ok(b) => toml::from_str(&String::from_utf8_lossy(&b))
                .map_err(|e| Error::invalid(format!("pip.toml is invalid: {e}")))?,
            Err(_) if !file.exists() => PipSettings::default(),
            Err(e) => return Err(e),
        };
        let url = s.index_url.unwrap_or_else(|| DEFAULT_INDEX.to_string());
        let mut hosts: Vec<String> = s.file_hosts;
        if url.trim_end_matches('/') == DEFAULT_INDEX {
            hosts.extend(DEFAULT_FILE_HOSTS.iter().map(|h| h.to_string()));
        }
        IndexPolicy::new(&url, hosts)
    }

    pub fn new(url: &str, file_hosts: Vec<String>) -> crate::Result<IndexPolicy> {
        let (scheme, host, _) = split_url(url)?;
        if scheme != "https" && !(scheme == "http" && is_loopback(&host)) {
            return Err(Error::invalid(
                "the pip index must use https (http only for loopback test indexes)",
            ));
        }
        Ok(IndexPolicy {
            url: url.trim_end_matches('/').to_string(),
            file_hosts,
        })
    }

    fn host(&self) -> String {
        split_url(&self.url).map(|u| u.1).unwrap_or_default()
    }

    /// Registry-only: files come from the index host or a trusted file host.
    pub fn allows_file_url(&self, url: &str) -> bool {
        let Ok((scheme, host, _)) = split_url(url) else {
            return false;
        };
        let https_ok = scheme == "https" || (scheme == "http" && is_loopback(&host));
        https_ok && (host == self.host() || self.file_hosts.contains(&host))
    }
}

fn is_loopback(host: &str) -> bool {
    let bare = if host.starts_with('[') {
        host.split("]:")
            .next()
            .unwrap_or(host)
            .trim_end_matches(']')
            .to_string()
            + "]"
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h).to_string()
    };
    bare == "localhost" || bare == "127.0.0.1" || bare == "[::1]"
}

/// `(scheme, host[:port], path)`; rejects userinfo.
pub fn split_url(url: &str) -> crate::Result<(String, String, String)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::invalid(format!("not an absolute URL: {url}")))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(Error::invalid("URL must not carry credentials"));
    }
    let host = authority.to_ascii_lowercase();
    Ok((
        scheme.to_ascii_lowercase(),
        strip_default_port(&host),
        path.to_string(),
    ))
}

fn strip_default_port(h: &str) -> String {
    h.strip_suffix(":443")
        .or_else(|| h.strip_suffix(":80"))
        .unwrap_or(h)
        .to_string()
}

/// Resolve `href` against the page URL (absolute, `/path`, or relative).
pub fn join_url(base: &str, href: &str) -> String {
    if href.contains("://") {
        return href.to_string();
    }
    let (scheme, host, path) = match split_url(base) {
        Ok(v) => v,
        Err(_) => return href.to_string(),
    };
    let origin = format!("{scheme}://{host}");
    if href.starts_with('/') {
        return format!("{origin}{}", normalize_path(href));
    }
    let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    format!("{origin}{}", normalize_path(&format!("{dir}/{href}")))
}

fn normalize_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let trailing = if p.ends_with('/') { "/" } else { "" };
    format!("/{}{trailing}", out.join("/"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexFile {
    pub filename: String,
    /// Absolute URL, fragment removed.
    pub url: String,
    pub sha256: Option<String>,
    pub requires_python: Option<String>,
    pub yanked: bool,
}

pub struct IndexClient {
    pub policy: IndexPolicy,
    agent: ureq::Agent,
    pub max_bytes: u64,
}

impl IndexClient {
    pub fn new(policy: IndexPolicy, timeout: Duration, max_bytes: u64) -> IndexClient {
        let cfg = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0) // a redirect could leave the allowlisted hosts
            .build();
        IndexClient {
            policy,
            agent: ureq::Agent::new_with_config(cfg),
            max_bytes,
        }
    }

    /// Files listed for `name` (PEP 503 normalized).
    pub fn project(&self, name: &str) -> crate::Result<Vec<IndexFile>> {
        let page = format!("{}/{}/", self.policy.url, name);
        let mut resp = self
            .agent
            .get(&page)
            .header(
                "Accept",
                "application/vnd.pypi.simple.v1+json, text/html;q=0.1",
            )
            .call()
            .map_err(|e| Error::incomplete(format!("index request for {name} failed: {e}")))?;
        if resp.status().as_u16() != 200 {
            return Err(Error::incomplete(format!(
                "index returned {} for {name}",
                resp.status()
            )));
        }
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_PAGE_BYTES)
            .read_to_string()
            .map_err(|e| Error::incomplete(format!("index page for {name}: {e}")))?;
        if ct.contains("json") {
            parse_json_page(&body, &page)
        } else {
            Ok(parse_html_page(&body, &page))
        }
    }

    /// Download `f` to `dest`, enforcing the size bound and the index-provided
    /// SHA-256. Returns `(sha256, size)`. A mismatch deletes the file.
    pub fn download(&self, f: &IndexFile, dest: &Path) -> crate::Result<(String, u64)> {
        let expected = f.sha256.as_deref().ok_or_else(|| {
            Error::integrity(format!("{} has no SHA-256 from the index", f.filename))
        })?;
        if !self.policy.allows_file_url(&f.url) {
            return Err(Error::rejected(format!(
                "{} is hosted outside the pinned registry",
                f.filename
            )));
        }
        let resp =
            self.agent.get(&f.url).call().map_err(|e| {
                Error::incomplete(format!("download of {} failed: {e}", f.filename))
            })?;
        if resp.status().as_u16() != 200 {
            return Err(Error::incomplete(format!(
                "{} returned {}",
                f.filename,
                resp.status()
            )));
        }
        let mut reader = resp.into_body().into_reader();
        let mut out = std::fs::File::create(dest)?;
        let (mut hash, mut size) = (Sha256::new(), 0u64);
        let mut buf = vec![0u8; 64 * 1024];
        let result = (|| -> crate::Result<()> {
            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| Error::incomplete(format!("download of {}: {e}", f.filename)))?;
                if n == 0 {
                    return Ok(());
                }
                size += n as u64;
                if size > self.max_bytes {
                    return Err(Error::rejected(format!(
                        "{} exceeds the {} byte artifact limit",
                        f.filename, self.max_bytes
                    )));
                }
                hash.update(&buf[..n]);
                out.write_all(&buf[..n])?;
            }
        })();
        drop(out);
        let digest = hex::encode(hash.finalize());
        let outcome = result.and_then(|()| {
            if digest.eq_ignore_ascii_case(expected) {
                Ok(())
            } else {
                Err(Error::integrity(format!(
                    "{} does not match the SHA-256 published by the index",
                    f.filename
                )))
            }
        });
        if let Err(e) = outcome {
            let _ = std::fs::remove_file(dest);
            return Err(e);
        }
        Ok((digest, size))
    }
}

fn parse_json_page(body: &str, page: &str) -> crate::Result<Vec<IndexFile>> {
    #[derive(Deserialize)]
    struct Page {
        files: Vec<File>,
    }
    #[derive(Deserialize)]
    struct File {
        filename: String,
        url: String,
        #[serde(default)]
        hashes: std::collections::HashMap<String, String>,
        #[serde(default, rename = "requires-python")]
        requires_python: Option<String>,
        #[serde(default)]
        yanked: serde_json::Value,
    }
    let p: Page = serde_json::from_str(body)
        .map_err(|e| Error::incomplete(format!("index JSON invalid: {e}")))?;
    Ok(p.files
        .into_iter()
        .map(|f| IndexFile {
            url: join_url(page, f.url.split('#').next().unwrap_or("")),
            sha256: f.hashes.get("sha256").map(|h| h.to_ascii_lowercase()),
            requires_python: f.requires_python,
            yanked: !matches!(
                f.yanked,
                serde_json::Value::Null | serde_json::Value::Bool(false)
            ),
            filename: f.filename,
        })
        .collect())
}

fn parse_html_page(body: &str, page: &str) -> Vec<IndexFile> {
    let anchor = regex::Regex::new(r#"(?is)<a\s([^>]*)>([^<]*)</a>"#).expect("static regex");
    let attr = |attrs: &str, name: &str| -> Option<String> {
        let rx =
            regex::Regex::new(&format!(r#"(?is)\b{name}\s*=\s*(?:"([^"]*)"|'([^']*)')"#)).ok()?;
        let c = rx.captures(attrs)?;
        c.get(1).or_else(|| c.get(2)).map(|m| unescape(m.as_str()))
    };
    let mut out = Vec::new();
    for c in anchor.captures_iter(body) {
        let attrs = &c[1];
        let Some(href) = attr(attrs, "href") else {
            continue;
        };
        let (path, frag) = href.split_once('#').unwrap_or((&href, ""));
        let sha256 = frag.strip_prefix("sha256=").map(|h| h.to_ascii_lowercase());
        let filename = unescape(c[2].trim());
        out.push(IndexFile {
            filename,
            url: join_url(page, path),
            sha256,
            requires_python: attr(attrs, "data-requires-python"),
            yanked: attr(attrs, "data-yanked").is_some() || attrs.contains("data-yanked"),
        });
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy() {
        let p = IndexPolicy::new(
            "https://pypi.org/simple/",
            vec!["files.pythonhosted.org".into()],
        )
        .unwrap();
        assert!(p.allows_file_url("https://files.pythonhosted.org/packages/a/b.whl"));
        assert!(p.allows_file_url("https://pypi.org/x.whl"));
        assert!(!p.allows_file_url("https://evil.test/x.whl"));
        assert!(!p.allows_file_url("http://pypi.org/x.whl"));
        assert!(IndexPolicy::new("http://pypi.org/simple", vec![]).is_err());
        assert!(IndexPolicy::new("http://127.0.0.1:8000/simple", vec![]).is_ok());
        assert!(IndexPolicy::new("https://u:p@pypi.org/simple", vec![]).is_err());
    }

    #[test]
    fn urls_join() {
        assert_eq!(
            join_url("https://h.test/simple/foo/", "../../packages/foo.whl"),
            "https://h.test/packages/foo.whl"
        );
        assert_eq!(
            join_url("https://h.test/simple/foo/", "/f/x.whl"),
            "https://h.test/f/x.whl"
        );
        assert_eq!(
            join_url("https://h.test/simple/foo/", "x.whl"),
            "https://h.test/simple/foo/x.whl"
        );
    }

    #[test]
    fn html_and_json_pages() {
        let h = r#"<a href="../../p/foo-1.0-py3-none-any.whl#sha256=ABCD" data-requires-python="&gt;=3.8">foo-1.0-py3-none-any.whl</a>
<a href="foo-1.0.tar.gz#sha256=ee">foo-1.0.tar.gz</a>"#;
        let f = parse_html_page(h, "https://h.test/simple/foo/");
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].sha256.as_deref(), Some("abcd"));
        assert_eq!(f[0].requires_python.as_deref(), Some(">=3.8"));
        assert_eq!(f[0].url, "https://h.test/p/foo-1.0-py3-none-any.whl");
        let j = r#"{"files":[{"filename":"a-1-py3-none-any.whl","url":"a.whl","hashes":{"sha256":"AA"},"yanked":false}]}"#;
        let f = parse_json_page(j, "https://h.test/simple/a/").unwrap();
        assert_eq!((f[0].yanked, f[0].sha256.as_deref()), (false, Some("aa")));
    }
}
