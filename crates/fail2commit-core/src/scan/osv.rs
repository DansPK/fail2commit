//! OSV advisory client (T-006, SPEC-006).
//!
//! Exact `(ecosystem, name, version)` lookups go through
//! `POST {osv_url}/v1/querybatch`; details come from
//! `GET {osv_url}/v1/vulns/{id}`. Everything is bounded: one agent carrying the
//! configured timeout, chunked batches, a capped page loop, a strict advisory-id
//! charset (ids arrive from the network and are placed in a URL path) and an
//! endpoint check (CR-019): `https://` to any host, `http://` only to a
//! loopback address. TLS uses rustls with the bundled webpki roots and full
//! certificate verification, and no redirect is followed.

use super::{ecosystem_str, PackageId};
use crate::settings::AdvisorySettings;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

/// OSV accepts up to 1000 queries per batch; stay far below that so one request
/// and one response stay small.
pub const MAX_QUERIES_PER_BATCH: usize = 64;
/// Page loop bound. OSV pages are short; more than this means a broken server.
const MAX_PAGES: usize = 32;
/// Longest advisory id accepted from the network.
const MAX_ID_CHARS: usize = 128;
/// Longest base URL accepted from settings.
const MAX_URL_CHARS: usize = 512;

#[derive(serde::Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(serde::Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<BatchVuln>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(serde::Deserialize)]
struct BatchVuln {
    id: String,
}

pub struct Client {
    agent: ureq::Agent,
    base: String,
}

impl Client {
    /// `None` when `osv_url` fails [`normalize_base_url`]. The caller then
    /// treats every lookup as incomplete instead of talking to something else.
    pub fn new(settings: &AdvisorySettings) -> Option<Client> {
        let base = normalize_base_url(&settings.osv_url)?;
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::WebPki)
            .disable_verification(false)
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(
                settings.timeout_secs.clamp(1, 300),
            )))
            .tls_config(tls)
            // A 3xx comes back as a response and is rejected by `body_text`.
            .max_redirects(0)
            .build()
            .into();
        Some(Client { agent, base })
    }

    /// Advisory ids for each package, same order as `pkgs`.
    pub fn batch(&self, pkgs: &[PackageId]) -> Result<Vec<Vec<String>>, ()> {
        let mut out: Vec<Vec<String>> = vec![Vec::new(); pkgs.len()];
        for start in (0..pkgs.len()).step_by(MAX_QUERIES_PER_BATCH) {
            let end = (start + MAX_QUERIES_PER_BATCH).min(pkgs.len());
            for (offset, ids) in self.batch_chunk(&pkgs[start..end])?.into_iter().enumerate() {
                out[start + offset] = dedup(ids);
            }
        }
        Ok(out)
    }

    fn batch_chunk(&self, pkgs: &[PackageId]) -> Result<Vec<Vec<String>>, ()> {
        let url = format!("{}/v1/querybatch", self.base);
        let mut tokens: Vec<Option<String>> = vec![None; pkgs.len()];
        let mut ids: Vec<Vec<String>> = vec![Vec::new(); pkgs.len()];
        let mut pending: Vec<usize> = (0..pkgs.len()).collect();
        for _ in 0..MAX_PAGES {
            if pending.is_empty() {
                return Ok(ids);
            }
            let queries: Vec<serde_json::Value> = pending
                .iter()
                .map(|&i| {
                    let mut query = serde_json::json!({
                        "package": {
                            "name": pkgs[i].name,
                            "ecosystem": ecosystem_str(pkgs[i].ecosystem),
                        },
                        "version": pkgs[i].version,
                    });
                    if let Some(token) = &tokens[i] {
                        query["page_token"] = serde_json::json!(token);
                    }
                    query
                })
                .collect();
            let body = serde_json::to_string(&serde_json::json!({ "queries": queries }))
                .map_err(|_| ())?;
            let text = body_text(
                self.agent
                    .post(&url)
                    .content_type("application/json")
                    .send(body.as_str()),
            )?;
            let parsed: BatchResponse = serde_json::from_str(&text).map_err(|_| ())?;
            if parsed.results.len() != pending.len() {
                return Err(());
            }
            let mut next_pending = Vec::new();
            for (slot, &pkg_index) in pending.iter().enumerate() {
                let result = &parsed.results[slot];
                for vuln in &result.vulns {
                    // An id we cannot address safely is dropped rather than
                    // pasted into a URL; the caller still reports incomplete.
                    if is_safe_id(&vuln.id) {
                        ids[pkg_index].push(vuln.id.clone());
                    }
                }
                match result.next_page_token.as_deref() {
                    Some(token) if !token.is_empty() => {
                        tokens[pkg_index] = Some(token.to_string());
                        next_pending.push(pkg_index);
                    }
                    _ => tokens[pkg_index] = None,
                }
            }
            pending = next_pending;
        }
        Err(())
    }

    /// Full advisory record for one id.
    pub fn vuln(&self, id: &str) -> Result<serde_json::Value, ()> {
        if !is_safe_id(id) {
            return Err(());
        }
        let url = format!("{}/v1/vulns/{id}", self.base);
        let text = body_text(self.agent.get(&url).call())?;
        serde_json::from_str(&text).map_err(|_| ())
    }
}

/// Body of a 2xx response. Anything else, a 3xx included, is a failed lookup.
fn body_text(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<String, ()> {
    let mut response = response.map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    response.body_mut().read_to_string().map_err(|_| ())
}

/// Trim and validate a configured endpoint: `https://` to any host, or
/// `http://` to `localhost`, `127.0.0.0/8` or `[::1]`. No userinfo, query,
/// fragment, backslash or percent-encoded host, so the host checked here is
/// the host a URL parser connects to. Returns the URL with a lowercase scheme.
pub fn normalize_base_url(url: &str) -> Option<String> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed.chars().count() > MAX_URL_CHARS {
        return None;
    }
    // '@' also keeps credentials away from an advisory service.
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '\\' | '?' | '#'))
    {
        return None;
    }
    let (scheme, rest) = trimmed.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split('/').next().unwrap_or_default();
    let loopback = host_is_loopback(authority)?;
    match scheme.as_str() {
        "https" => {}
        "http" if loopback => {}
        _ => return None,
    }
    Some(format!("{scheme}://{rest}"))
}

/// Whether a `host[:port]` authority names a loopback address; `None` when it
/// is not a well-formed host. Only exact forms count: `127.1`, `0x7f.0.0.1`,
/// `localhost.` and IPv4-mapped IPv6 are not treated as loopback.
fn host_is_loopback(authority: &str) -> Option<bool> {
    let (loopback, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (inside, after) = rest.split_once(']')?;
            let ip: Ipv6Addr = inside.parse().ok()?;
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':')?),
            };
            (ip.is_loopback(), port)
        }
        None => {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            if host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
            {
                return None;
            }
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback());
            (loopback, port)
        }
    };
    if let Some(port) = port {
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        port.parse::<u16>().ok()?;
    }
    Some(loopback)
}

/// Advisory ids we are willing to place in a URL path.
pub fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.chars().count() <= MAX_ID_CHARS
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Known malware: an OSV `MAL-` id, or an OpenSSF malicious-packages record.
pub fn is_malware(id: &str, detail: Option<&serde_json::Value>) -> bool {
    if id.to_ascii_uppercase().starts_with("MAL-") {
        return true;
    }
    let Some(record) = detail else {
        return false;
    };
    if record.get("database_specific").is_some_and(looks_malicious) {
        return true;
    }
    record
        .get("affected")
        .and_then(|v| v.as_array())
        .is_some_and(|affected| {
            affected
                .iter()
                .filter_map(|entry| entry.get("database_specific"))
                .any(looks_malicious)
        })
}

fn looks_malicious(specific: &serde_json::Value) -> bool {
    if let Some(source) = specific.get("source").and_then(|v| v.as_str()) {
        let source = source.to_ascii_lowercase();
        if source.contains("malicious-packages") || source.contains("ossf/malicious") {
            return true;
        }
    }
    if specific.get("malicious").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }
    specific
        .get("type")
        .and_then(|v| v.as_str())
        .is_some_and(|kind| {
            kind.eq_ignore_ascii_case("malicious") || kind.eq_ignore_ascii_case("malware")
        })
}

fn dedup(ids: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if seen.insert(id.clone()) {
            out.push(id);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_https_or_loopback_http() {
        for (input, want) in [
            ("https://api.osv.dev/", "https://api.osv.dev"),
            ("HTTPS://API.OSV.DEV", "https://API.OSV.DEV"),
            ("https://api.osv.dev.", "https://api.osv.dev."),
            (
                "https://mirror.example:8443/osv/",
                "https://mirror.example:8443/osv",
            ),
            ("https://[2001:db8::1]:443", "https://[2001:db8::1]:443"),
            (" http://127.0.0.1:8080 ", "http://127.0.0.1:8080"),
            ("http://127.9.8.7", "http://127.9.8.7"),
            ("HTTP://LOCALHOST:9", "http://LOCALHOST:9"),
            ("http://localhost/osv", "http://localhost/osv"),
            ("http://[::1]:8080", "http://[::1]:8080"),
            ("http://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]"),
        ] {
            assert_eq!(normalize_base_url(input).as_deref(), Some(want), "{input}");
        }
        for bad in [
            // Plain HTTP off loopback, never silently upgraded or downgraded.
            "http://api.osv.dev",
            "http://10.0.0.1",
            "http://127.0.0.1.evil.example",
            "http://localhost.evil.example",
            "http://localhost.",
            "http://127.0.0.1.",
            "http://127.1",
            "http://0x7f.0.0.1",
            "http://2130706433",
            "http://[::ffff:127.0.0.1]",
            "http://[::2]",
            // Authority tricks a URL parser reads differently.
            "http://localhost@evil.example",
            "http://evil.example@127.0.0.1",
            "https://user:tok@example.test",
            "http://localhost%2eevil.example",
            "http://127.0.0.1\\@evil.example",
            "http://localhost#@evil.example",
            "http://localhost?@evil.example",
            "http://[::1%25lo]",
            "http://[::1]evil",
            "http://127.0.0.1:",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:80:80",
            "http://",
            "https:///v1",
            // Other schemes and malformed input.
            "file:///etc/passwd",
            "ftp://example.test",
            "httpx://127.0.0.1",
            "//127.0.0.1",
            "https://api.osv.dev /v1",
            "https://api.osv\t.dev",
            "",
        ] {
            assert!(normalize_base_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn agent_verifies_tls_and_follows_no_redirects() {
        let client = Client::new(&AdvisorySettings::default()).expect("default endpoint");
        let config = client.agent.config();
        assert_eq!(config.max_redirects(), 0);
        let tls = config.tls_config();
        assert!(!tls.disable_verification());
        assert_eq!(tls.provider(), TlsProvider::Rustls);
        assert!(matches!(tls.root_certs(), RootCerts::WebPki));
        assert!(
            !config.https_only(),
            "loopback http stays possible for tests"
        );
        assert!(normalize_base_url(&AdvisorySettings::default().osv_url)
            .is_some_and(|url| url.starts_with("https://")));
    }

    #[test]
    fn ids_are_path_safe() {
        for good in ["GHSA-abcd-1234-wxyz", "CVE-2021-1234", "MAL-2024-1"] {
            assert!(is_safe_id(good), "{good}");
        }
        for bad in ["../etc/passwd", "a/b", "id?x=1", "", "a b"] {
            assert!(!is_safe_id(bad), "{bad}");
        }
    }

    #[test]
    fn malware_classification() {
        assert!(is_malware("MAL-2024-1", None));
        assert!(!is_malware("GHSA-1", None));
        let openssf = serde_json::json!({
            "id": "GHSA-2",
            "affected": [{"database_specific": {
                "source": "https://github.com/ossf/malicious-packages"
            }}]
        });
        assert!(is_malware("GHSA-2", Some(&openssf)));
        let plain = serde_json::json!({"id": "GHSA-3", "summary": "a bug"});
        assert!(!is_malware("GHSA-3", Some(&plain)));
    }

    #[test]
    fn dedupes_preserving_order() {
        let ids = vec!["b".to_string(), "a".to_string(), "b".to_string()];
        assert_eq!(dedup(ids), vec!["b".to_string(), "a".to_string()]);
    }
}
