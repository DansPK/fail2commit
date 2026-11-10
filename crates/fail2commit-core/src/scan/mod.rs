//! Package and script scanning (T-006 · FR-006 · SPEC-006).
//!
//! Two independent checks, both of which only *report*:
//!
//! * [`check_advisories`] asks OSV for the exact `(ecosystem, name, version)`
//!   triples through `POST /v1/querybatch`, fetches each distinct advisory once
//!   through `GET /v1/vulns/{id}`, classifies known malware separately from
//!   CVEs/GHSAs, and keeps what it learned in a bounded, expiring disk cache.
//!   Offline runs and network failures fall back to that cache; when no usable
//!   entry exists the report is explicitly incomplete instead of looking clean.
//!
//! * [`inspect_scripts`] reads lifecycle `scripts` entries and referenced local
//!   files as text and denies clear `git push` force forms. Nothing here is
//!   executed. The rules are **evidence, not an execution boundary**: they can
//!   miss an obfuscated form, so the Git shim (FR-001) and the isolated run
//!   (FR-007) remain the enforcement points.
//!
//! Advisory findings need one explicit one-time approval
//! ([`FindingAction::Approve`]); known malware, a flagged script and script
//! content that was not fully inspected are hard denials
//! ([`FindingAction::Deny`]).

use crate::paths::TrustedPaths;
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::redact;
use crate::settings::AdvisorySettings;

mod cache;
pub mod code;
mod osv;
mod rules;

/// Most advisory ids reported for one package. A longer list is truncated and
/// the report says so.
const MAX_IDS_PER_PACKAGE: usize = 128;
/// Most ids whose records are classified for malware. Ids past the report
/// limit still get a detail lookup so a malware record is never dropped; more
/// than this is a hard denial.
const MAX_IDS_CLASSIFIED: usize = 512;
/// Most script findings returned for one package.
const MAX_SCRIPT_FINDINGS: usize = 256;
/// Bytes of one referenced script file inspected.
const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
/// Characters of evidence kept in one finding.
const MAX_EVIDENCE_CHARS: usize = 400;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "PyPI")]
    PyPI,
}

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct PackageId {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

impl PackageId {
    pub fn display(&self) -> String {
        format!(
            "{}:{}@{}",
            ecosystem_str(self.ecosystem),
            self.name,
            self.version
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvisoryReport {
    pub findings: Vec<Finding>,
    /// False when any lookup, detail fetch or page was not verified. A report
    /// that is not complete must never be read as "no known advisories".
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

pub(super) fn ecosystem_str(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "PyPI",
    }
}

/// Where one package's advisory lookup ended up.
#[derive(Default)]
struct Lookup {
    ids: Vec<String>,
    /// The ids came from a cache entry past its TTL.
    stale: bool,
    /// Neither the network nor the cache produced an answer.
    failed: bool,
}

fn batch_key(pkg: &PackageId) -> String {
    format!(
        "{}:batch:{}:{}@{}",
        cache::KEY_VERSION,
        ecosystem_str(pkg.ecosystem),
        pkg.name,
        pkg.version
    )
}

fn vuln_key(id: &str) -> String {
    format!("{}:vuln:{id}", cache::KEY_VERSION)
}

/// Check exact package versions for known vulnerabilities and malware.
pub fn check_advisories(
    paths: &TrustedPaths,
    settings: &AdvisorySettings,
    pkgs: &[PackageId],
) -> AdvisoryReport {
    let mut findings = Vec::new();
    let mut complete = true;
    if pkgs.is_empty() {
        return AdvisoryReport { findings, complete };
    }

    let root = cache::ensure(paths);
    let client = if settings.offline {
        None
    } else {
        osv::Client::new(settings)
    };

    let mut lookups: Vec<Lookup> = Vec::with_capacity(pkgs.len());
    let mut fetch: Vec<usize> = Vec::new();
    for (index, pkg) in pkgs.iter().enumerate() {
        let path = cache::path_for(&root, &batch_key(pkg));
        match cache::read::<Vec<String>>(&path) {
            Some(entry) if !cache::is_stale(entry.stored_at, settings.ttl_secs) => {
                lookups.push(Lookup {
                    ids: entry.data,
                    stale: false,
                    failed: false,
                });
            }
            _ => {
                // Offline without a usable entry, or a stale entry that still
                // needs a network refresh: settle it in the fetch phase.
                lookups.push(Lookup::default());
                fetch.push(index);
            }
        }
    }

    if !fetch.is_empty() {
        let subset: Vec<PackageId> = fetch.iter().map(|&i| pkgs[i].clone()).collect();
        let fetched = client.as_ref().map(|c| c.batch(&subset));
        match fetched {
            Some(Ok(batch_ids)) => {
                for (slot, &index) in fetch.iter().enumerate() {
                    let ids = batch_ids[slot].clone();
                    let path = cache::path_for(&root, &batch_key(&pkgs[index]));
                    cache::write(&path, &ids, cache::now_secs(), settings.cache_max_bytes);
                    cache::evict(&root, settings.cache_max_bytes);
                    lookups[index] = Lookup {
                        ids,
                        stale: false,
                        failed: false,
                    };
                }
            }
            _ => {
                // Network failure, offline mode or an unusable endpoint: keep
                // going with whatever the cache still holds.
                for &index in &fetch {
                    let path = cache::path_for(&root, &batch_key(&pkgs[index]));
                    lookups[index] = match cache::read::<Vec<String>>(&path) {
                        Some(entry) => Lookup {
                            stale: cache::is_stale(entry.stored_at, settings.ttl_secs),
                            ids: entry.data,
                            failed: false,
                        },
                        None => Lookup {
                            failed: true,
                            ..Lookup::default()
                        },
                    };
                }
            }
        }
    }

    for (index, pkg) in pkgs.iter().enumerate() {
        complete &= collect_package_findings(
            &root,
            settings,
            client.as_ref(),
            pkg,
            &lookups[index],
            &mut findings,
        );
    }

    AdvisoryReport { findings, complete }
}

/// Turn one package's lookup into findings. Returns whether that package is
/// fully verified.
fn collect_package_findings(
    root: &std::path::Path,
    settings: &AdvisorySettings,
    client: Option<&osv::Client>,
    pkg: &PackageId,
    lookup: &Lookup,
    findings: &mut Vec<Finding>,
) -> bool {
    let target = pkg.display();
    if lookup.failed {
        findings.push(
            Finding::new(
                FindingKind::IncompleteScan,
                FindingAction::Approve,
                "osv",
                format!("advisory lookup did not complete for {target}; version is unreviewed"),
            )
            .target(target),
        );
        return false;
    }

    let mut complete = true;
    let mut stale = lookup.stale;
    let mut unseen_details = 0usize;
    let mut ids = lookup.ids.clone();
    // Malware-looking ids first, so the bound below can only cut ordinary ones.
    ids.sort_by_key(|id| !id.to_ascii_uppercase().starts_with("MAL-"));
    if ids.len() > MAX_IDS_CLASSIFIED {
        findings.push(
            Finding::new(
                FindingKind::IncompleteScan,
                FindingAction::Deny,
                "osv",
                format!(
                    "{} advisory ids for {target} exceed the {MAX_IDS_CLASSIFIED}-id classification limit; malware cannot be ruled out",
                    ids.len()
                ),
            )
            .target(target.clone()),
        );
        complete = false;
        ids.truncate(MAX_IDS_CLASSIFIED);
    }
    let mut dropped = 0usize;

    for (position, id) in ids.into_iter().enumerate() {
        let path = cache::path_for(root, &vuln_key(&id));
        let cached = cache::read::<serde_json::Value>(&path);
        let mut detail: Option<serde_json::Value> = None;
        match &cached {
            Some(entry) if !cache::is_stale(entry.stored_at, settings.ttl_secs) => {
                detail = Some(entry.data.clone());
            }
            _ => {
                if let Some(client) = client {
                    if let Ok(record) = client.vuln(&id) {
                        cache::write(&path, &record, cache::now_secs(), settings.cache_max_bytes);
                        cache::evict(root, settings.cache_max_bytes);
                        detail = Some(record);
                    }
                }
                if detail.is_none() {
                    // A stale record still names the advisory; it is better
                    // evidence than the bare id, and staleness is reported.
                    if let Some(entry) = cached {
                        stale |= cache::is_stale(entry.stored_at, settings.ttl_secs);
                        detail = Some(entry.data);
                    }
                }
            }
        }
        if detail.is_none() {
            unseen_details += 1;
        }
        // Known malware is a hard denial (CR-003); other advisories need approval.
        let (kind, action) = if osv::is_malware(&id, detail.as_ref()) {
            (FindingKind::Malware, FindingAction::Deny)
        } else {
            (FindingKind::Advisory, FindingAction::Approve)
        };
        if kind == FindingKind::Advisory && position >= MAX_IDS_PER_PACKAGE {
            dropped += 1;
            continue;
        }
        findings.push(
            Finding::new(kind, action, "osv", summarize(&id, detail.as_ref(), pkg))
                .target(target.clone())
                .advisory(id),
        );
    }
    if dropped > 0 {
        findings.push(
            Finding::new(
                FindingKind::IncompleteScan,
                FindingAction::Approve,
                "osv",
                format!("{dropped} advisory id(s) for {target} were dropped past the {MAX_IDS_PER_PACKAGE}-id limit"),
            )
            .target(target.clone()),
        );
        complete = false;
    }

    if unseen_details > 0 {
        findings.push(
            Finding::new(
                FindingKind::IncompleteScan,
                FindingAction::Approve,
                "osv",
                format!(
                    "{unseen_details} advisory detail(s) for {target} were not fetched; classification may be incomplete"
                ),
            )
            .target(target.clone()),
        );
        complete = false;
    }
    if stale {
        findings.push(
            Finding::new(
                FindingKind::StaleData,
                FindingAction::Approve,
                "osv",
                format!(
                    "cached advisory data for {target} is past its {}-second TTL",
                    settings.ttl_secs
                ),
            )
            .target(target.clone()),
        );
        complete = false;
    }
    complete
}

/// One redacted, bounded evidence line. Advisory text is untrusted input.
/// `ID [severity], fixed in X: summary`. Severity and fix come first so the
/// length bound can only cut the free-text summary.
fn summarize(id: &str, detail: Option<&serde_json::Value>, pkg: &PackageId) -> String {
    let text = detail.and_then(|record| {
        ["summary", "details"]
            .iter()
            .find_map(|key| record.get(*key).and_then(|value| value.as_str()))
            .map(str::trim)
            .filter(|s| !s.is_empty())
    });
    let mut raw = id.to_string();
    if let Some(severity) = detail.and_then(severity) {
        raw.push_str(&format!(" [{severity}]"));
    }
    let fixed = detail.map(|d| fixed_versions(d, pkg)).unwrap_or_default();
    if !fixed.is_empty() {
        raw.push_str(&format!(", fixed in {}", fixed.join(", ")));
    }
    if let Some(text) = text {
        raw.push_str(&format!(": {text}"));
    }
    truncate(&redact::redact_url_credentials(&raw), MAX_EVIDENCE_CHARS)
}

/// GHSA-style `database_specific.severity`, if it is one of the known words.
fn severity(record: &serde_json::Value) -> Option<String> {
    let s = record
        .get("database_specific")?
        .get("severity")?
        .as_str()?
        .to_ascii_lowercase();
    matches!(
        s.as_str(),
        "low" | "moderate" | "medium" | "high" | "critical"
    )
    .then_some(s)
}

/// Versions that fix this advisory for exactly this package (at most three).
fn fixed_versions(record: &serde_json::Value, pkg: &PackageId) -> Vec<String> {
    let norm = |name: &str| match pkg.ecosystem {
        Ecosystem::PyPI => name.to_ascii_lowercase().replace(['_', '.'], "-"),
        Ecosystem::Npm => name.to_string(),
    };
    let want = norm(&pkg.name);
    let mut out: Vec<String> = Vec::new();
    let affected = record.get("affected").and_then(|a| a.as_array());
    for a in affected.into_iter().flatten() {
        let Some(p) = a.get("package") else { continue };
        let eco = p.get("ecosystem").and_then(|e| e.as_str()).unwrap_or("");
        let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if !eco.eq_ignore_ascii_case(ecosystem_str(pkg.ecosystem)) || norm(name) != want {
            continue;
        }
        let ranges = a.get("ranges").and_then(|r| r.as_array());
        for event in ranges
            .into_iter()
            .flatten()
            .filter_map(|r| r.get("events").and_then(|e| e.as_array()))
            .flatten()
        {
            let Some(v) = event.get("fixed").and_then(|f| f.as_str()) else {
                continue;
            };
            let ok = !v.is_empty()
                && v.len() <= 64
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-+~".contains(c));
            if ok && !out.iter().any(|o| o == v) && out.len() < 3 {
                out.push(v.to_string());
            }
        }
    }
    out
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push_str("...");
    out
}

/// Inspect lifecycle script entries and referenced local files for clear
/// `git push` force forms. Nothing is executed; see the module docs on why this
/// is evidence and not an execution boundary.
pub fn inspect_scripts(
    pkg: &PackageId,
    scripts: &[(String, String)],
    files: &[ScriptFile],
) -> Vec<Finding> {
    let target = pkg.display();
    let mut hits: Vec<(String, rules::ForceHit)> = Vec::new();
    let mut overflow = false;
    let mut uninspected: Vec<(&str, &'static str)> = Vec::new();

    'scripts: for (name, command) in scripts {
        for hit in rules::force_push_hits(command) {
            if hits.len() == MAX_SCRIPT_FINDINGS {
                overflow = true;
                break 'scripts;
            }
            hits.push((format!("{name}:{}", hit.line), hit));
        }
    }
    if !overflow {
        'files: for file in files {
            let (text, gap) = script_text(file);
            if let Some(why) = gap {
                uninspected.push((&file.path, why));
            }
            for hit in rules::force_push_hits(&text) {
                if hits.len() == MAX_SCRIPT_FINDINGS {
                    overflow = true;
                    break 'files;
                }
                hits.push((format!("{}:{}", file.path, hit.line), hit));
            }
        }
    }

    let mut findings: Vec<Finding> = hits
        .into_iter()
        .map(|(location, hit)| {
            let evidence = format!(
                "git push {}: {}",
                hit.form,
                redact::redact_url_credentials(&hit.text)
            );
            Finding::new(
                FindingKind::SuspiciousScript,
                FindingAction::Deny,
                "scan.scripts",
                truncate(&evidence, MAX_EVIDENCE_CHARS),
            )
            .target(target.clone())
            .location(location)
        })
        .collect();
    for (path, why) in uninspected {
        findings.push(
            Finding::new(
                FindingKind::IncompleteScan,
                FindingAction::Deny,
                "scan.scripts",
                truncate(
                    &format!("referenced script {path} was not fully inspected: {why}"),
                    MAX_EVIDENCE_CHARS,
                ),
            )
            .target(target.clone())
            .location(path.to_string()),
        );
    }
    if overflow {
        findings.push(
            Finding::new(
                FindingKind::IncompleteScan,
                FindingAction::Deny,
                "scan.scripts",
                format!("more than {MAX_SCRIPT_FINDINGS} force-push forms; inspection stopped"),
            )
            .target(target),
        );
    }
    findings
}

/// Decode one script file for inspection. Returns the text to scan plus why
/// the file is only partly (or not at all) inspected, if so.
fn script_text(file: &ScriptFile) -> (String, Option<&'static str>) {
    let len = file.bytes.len().min(MAX_SCRIPT_BYTES);
    let bytes = &file.bytes[..len];
    // `sh` skips NUL bytes anywhere, so one past the first block still splits tokens.
    if bytes.contains(&0) {
        return (String::new(), Some("binary content cannot be read as text"));
    }
    let gap = (file.bytes.len() > MAX_SCRIPT_BYTES).then_some("longer than the inspected prefix");
    (String::from_utf8_lossy(bytes).into_owned(), gap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg() -> PackageId {
        PackageId {
            ecosystem: Ecosystem::Npm,
            name: "demo".into(),
            version: "1.0.0".into(),
        }
    }

    #[test]
    fn advisory_summary_leads_with_severity_and_fix() {
        let record = serde_json::json!({
            "summary": "Prototype pollution",
            "database_specific": { "severity": "HIGH" },
            "affected": [
                { "package": { "ecosystem": "npm", "name": "other" },
                  "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "9.9.9" }] }] },
                { "package": { "ecosystem": "npm", "name": "demo" },
                  "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "1.0.1" }] },
                             { "events": [{ "introduced": "2.0.0" }, { "fixed": "2.0.3" }, { "fixed": "1.0.1" }] }] }
            ]
        });
        assert_eq!(
            summarize("GHSA-x", Some(&record), &pkg()),
            "GHSA-x [high], fixed in 1.0.1, 2.0.3: Prototype pollution"
        );
        // Unknown severity words, hostile version strings and no detail degrade quietly.
        let odd = serde_json::json!({
            "database_specific": { "severity": "<b>urgent</b>" },
            "affected": [{ "package": { "ecosystem": "npm", "name": "demo" },
                           "ranges": [{ "events": [{ "fixed": "1.0.1; rm -rf /" }] }] }]
        });
        assert_eq!(summarize("GHSA-y", Some(&odd), &pkg()), "GHSA-y");
        assert_eq!(summarize("GHSA-z", None, &pkg()), "GHSA-z");
    }

    #[test]
    fn packages_display_with_ecosystem() {
        assert_eq!(pkg().display(), "npm:demo@1.0.0");
        let py = PackageId {
            ecosystem: Ecosystem::PyPI,
            name: "requests".into(),
            version: "2.31.0".into(),
        };
        assert_eq!(py.display(), "PyPI:requests@2.31.0");
    }

    #[test]
    fn script_findings_are_denials_with_locations() {
        let scripts = vec![
            (
                "postinstall".to_string(),
                "git push --force origin main".to_string(),
            ),
            ("build".to_string(), "npm run x && git push -f".to_string()),
        ];
        let files = vec![ScriptFile {
            path: "scripts/release.sh".into(),
            bytes: b"set -e\ngit push origin :stale-branch\n".to_vec(),
        }];
        let findings = inspect_scripts(&pkg(), &scripts, &files);
        assert_eq!(findings.len(), 3);
        for finding in &findings {
            assert_eq!(finding.kind, FindingKind::SuspiciousScript);
            assert_eq!(finding.action, FindingAction::Deny);
            assert_eq!(finding.target.as_deref(), Some("npm:demo@1.0.0"));
        }
        let locations: Vec<&str> = findings
            .iter()
            .filter_map(|f| f.location.as_deref())
            .collect();
        assert!(locations.contains(&"postinstall:1"));
        assert!(locations.contains(&"build:1"));
        assert!(locations.contains(&"scripts/release.sh:2"));
    }

    #[test]
    fn benign_scripts_are_clean() {
        let scripts = vec![
            ("test".to_string(), "git push origin main".to_string()),
            ("postinstall".to_string(), "node ./build.js".to_string()),
        ];
        let files = vec![ScriptFile {
            path: "build.js".into(),
            bytes: b"console.log('hello');\n".to_vec(),
        }];
        assert!(inspect_scripts(&pkg(), &scripts, &files).is_empty());
    }

    #[test]
    fn evidence_redacts_credentials() {
        let url = [
            "https://ci",
            "-bot:placeholder",
            "-token@example.test/r.git",
        ]
        .concat();
        let scripts = vec![("postinstall".to_string(), format!("git push --force {url}"))];
        let findings = inspect_scripts(&pkg(), &scripts, &[]);
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].evidence.contains("placeholder"));
        assert!(findings[0].evidence.contains("***@example.test"));
    }

    #[test]
    fn binary_and_oversized_files_are_bounded() {
        let binary = ScriptFile {
            path: "blob.bin".into(),
            bytes: b"git push --force\0tail".to_vec(),
        };
        let findings = inspect_scripts(&pkg(), &[], &[binary]);
        assert_eq!(findings.len(), 1, "binary content is an incomplete scan");
        assert_eq!(findings[0].kind, FindingKind::IncompleteScan);
        assert_eq!(findings[0].action, FindingAction::Deny);
        assert_eq!(findings[0].location.as_deref(), Some("blob.bin"));
        assert!(findings[0].evidence.contains("blob.bin"));

        let mut large = vec![b'\n'; MAX_SCRIPT_BYTES + 64];
        large[..20].copy_from_slice(b"git push --force\n\n\n\n");
        let tail = b"git push --force\n";
        let start = MAX_SCRIPT_BYTES + 16;
        large[start..start + tail.len()].copy_from_slice(tail);
        let findings = inspect_scripts(
            &pkg(),
            &[],
            &[ScriptFile {
                path: "big.sh".into(),
                bytes: large,
            }],
        );
        assert_eq!(findings.len(), 2, "prefix hit plus an incomplete scan");
        assert_eq!(findings[0].location.as_deref(), Some("big.sh:1"));
        assert_eq!(findings[1].kind, FindingKind::IncompleteScan);
        assert_eq!(findings[1].action, FindingAction::Deny);
        assert!(findings[1].evidence.contains("big.sh"));
    }

    #[test]
    fn finding_count_is_bounded() {
        let scripts: Vec<(String, String)> = (0..MAX_SCRIPT_FINDINGS + 10)
            .map(|i| (format!("s{i}"), "git push --force".to_string()))
            .collect();
        let findings = inspect_scripts(&pkg(), &scripts, &[]);
        assert_eq!(findings.len(), MAX_SCRIPT_FINDINGS + 1);
        assert_eq!(
            findings.last().map(|f| f.kind),
            Some(FindingKind::IncompleteScan)
        );
        assert!(findings
            .iter()
            .all(|f| matches!(f.action, FindingAction::Deny)));
    }
}
