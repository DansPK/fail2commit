//! OSV advisory client (T-006, SPEC-006).
//!
//! Exact `(ecosystem, name, version)` lookups go through
//! `POST {osv_url}/v1/querybatch`; details come from
//! `GET {osv_url}/v1/vulns/{id}`. Everything is bounded: one agent carrying the
//! configured timeout, chunked batches, a capped page loop, a strict advisory-id
//! charset (ids arrive from the network and are placed in a URL path) and an
//! `http`/`https` only endpoint check so trusted settings cannot turn the scan
//! into a local file read.

use super::{ecosystem_str, PackageId};
use crate::settings::AdvisorySettings;
use std::time::Duration;

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
    /// `None` when `osv_url` is not an `http(s)` endpoint or carries userinfo.
    /// The caller then treats every lookup as incomplete instead of talking to
    /// something else.
    pub fn new(settings: &AdvisorySettings) -> Option<Client> {
        let base = normalize_base_url(&settings.osv_url)?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(
                settings.timeout_secs.clamp(1, 300),
            )))
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
            let text = self
                .agent
                .post(&url)
                .content_type("application/json")
                .send(body.as_str())
                .map_err(|_| ())?
                .body_mut()
                .read_to_string()
                .map_err(|_| ())?;
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
        let text = self
            .agent
            .get(&url)
            .call()
            .map_err(|_| ())?
            .body_mut()
            .read_to_string()
            .map_err(|_| ())?;
        serde_json::from_str(&text).map_err(|_| ())
    }
}

/// Trim and validate a configured endpoint.
pub fn normalize_base_url(url: &str) -> Option<String> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed.chars().count() > MAX_URL_CHARS {
        return None;
    }
    if trimmed.chars().any(char::is_whitespace) {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return None;
    }
    let after_scheme = &trimmed[trimmed.find("//")? + 2..];
    if after_scheme.is_empty() || after_scheme.contains('@') {
        // fail2commit never sends credentials to an advisory service.
        return None;
    }
    Some(trimmed.to_string())
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
    fn endpoint_must_be_http_and_credential_free() {
        assert_eq!(
            normalize_base_url("https://api.osv.dev/").as_deref(),
            Some("https://api.osv.dev")
        );
        assert_eq!(
            normalize_base_url(" http://127.0.0.1:8080 ").as_deref(),
            Some("http://127.0.0.1:8080")
        );
        for bad in [
            "file:///etc/passwd",
            "ftp://example.test",
            "https://user:tok@example.test",
            "https://api.osv.dev /v1",
            "",
        ] {
            assert!(normalize_base_url(bad).is_none(), "{bad}");
        }
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
