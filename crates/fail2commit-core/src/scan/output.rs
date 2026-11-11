//! Scan files that sandboxed scripts produced (FR-028, SPEC-015).
//!
//! After lifecycle scripts ran and before anything is committed into the
//! project, every file they created or changed (build output, downloaded
//! binaries, packages they fetched) is checked with the CR-017 code rules,
//! the YARA rules (FR-019) and the offline malware data (CR-020 / FR-018).
//! Script output is untrusted: reads are bounded, and a file a bound skipped
//! is an `incomplete_scan` `approve`, never a clean result.

use super::code::{self, When};
use super::malware_list::Index;
use super::yara::{self, Budget, Matcher, PackageScan};
use super::{truncate, Ecosystem, PackageId, MAX_EVIDENCE_CHARS};
use crate::protocol::{Finding, FindingAction, FindingKind};
use std::collections::BTreeMap;
use std::path::Path;

pub const SOURCE: &str = "scan.output";
/// Produced files scanned for one install; the rest are reported.
const MAX_FILES: usize = 50_000;
const MAX_CODE_FINDINGS: usize = 8;

/// Scan `files` (paths relative to `root`, each tagged with the package whose
/// scripts produced it). `matcher` is `None` when rules are off; `index` is
/// the offline malware index when one is installed and valid.
pub fn scan_tree(
    matcher: Option<&Matcher>,
    index: Option<&Index>,
    root: &Path,
    files: &[(PackageId, String)],
) -> Vec<Finding> {
    let mut by_pkg: BTreeMap<&PackageId, Vec<&str>> = BTreeMap::new();
    for (pkg, rel) in files.iter().take(MAX_FILES) {
        by_pkg.entry(pkg).or_default().push(rel);
    }
    let mut out = Vec::new();
    let mut budget = Budget::default();
    for (pkg, rels) in by_pkg {
        let target = pkg.display();
        let mut scan = matcher.map(|m| PackageScan::new(m, pkg, SOURCE));
        let mut code_hits = 0usize;
        for rel in rels {
            let full = root.join(rel);
            let len = match std::fs::symlink_metadata(&full) {
                Ok(m) if m.is_file() => m.len(),
                Ok(_) => continue,
                Err(_) => {
                    // Gone again (a temp file the script removed): nothing to commit.
                    continue;
                }
            };
            if let Some(s) = scan.as_mut() {
                if !s.admit(rel, len, &budget) {
                    continue;
                }
            } else if len > yara::MAX_FILE {
                out.push(skipped(&target, rel, "larger than the scan limit"));
                continue;
            }
            let Ok(bytes) = std::fs::read(&full) else {
                out.push(skipped(&target, rel, "cannot be read"));
                continue;
            };
            if let Some(s) = scan.as_mut() {
                s.scan(rel, &bytes, yara::When::Load, &mut budget);
            }
            if code::is_candidate(rel, &bytes) && !bytes[..bytes.len().min(8192)].contains(&0) {
                for h in code::hits(&String::from_utf8_lossy(&bytes), When::Runtime) {
                    code_hits += 1;
                    if code_hits > MAX_CODE_FINDINGS {
                        break;
                    }
                    out.push(
                        Finding::new(
                            FindingKind::SuspiciousCode,
                            FindingAction::Approve,
                            SOURCE,
                            truncate(
                                &format!(
                                    "{} in a file an install script produced, which your project may load: `{}`",
                                    h.rule.message(),
                                    h.snippet
                                ),
                                MAX_EVIDENCE_CHARS,
                            ),
                        )
                        .target(target.clone())
                        .location(format!("{rel}:{}", h.line)),
                    );
                }
            }
            if let Some(index) = index {
                out.extend(produced_malware(index, &target, rel, &bytes));
            }
        }
        if let Some(s) = scan {
            out.extend(s.findings());
        }
    }
    if files.len() > MAX_FILES {
        out.push(Finding::new(
            FindingKind::IncompleteScan,
            FindingAction::Approve,
            SOURCE,
            format!(
                "install scripts produced {} files; only the first {MAX_FILES} were scanned",
                files.len()
            ),
        ));
    }
    out
}

fn skipped(target: &str, rel: &str, why: &str) -> Finding {
    Finding::new(
        FindingKind::IncompleteScan,
        FindingAction::Approve,
        SOURCE,
        truncate(
            &format!("file {rel} produced by an install script was not scanned: {why}"),
            MAX_EVIDENCE_CHARS,
        ),
    )
    .target(target.to_string())
    .location(rel.to_string())
}

/// A produced npm manifest or wheel `METADATA` naming a listed package.
fn produced_malware(index: &Index, target: &str, rel: &str, bytes: &[u8]) -> Vec<Finding> {
    let file = rel.rsplit('/').next().unwrap_or(rel);
    let id = if file == "package.json" {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|v| {
                Some(PackageId {
                    ecosystem: Ecosystem::Npm,
                    name: v.get("name")?.as_str()?.to_string(),
                    version: v.get("version")?.as_str()?.to_string(),
                })
            })
    } else if file == "METADATA" && rel.contains(".dist-info/") {
        let text = String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]);
        let field = |k: &str| {
            text.lines()
                .take_while(|l| !l.is_empty())
                .find_map(|l| l.strip_prefix(k))
                .map(|v| v.trim().to_string())
        };
        field("Name:")
            .zip(field("Version:"))
            .map(|(name, version)| PackageId {
                ecosystem: Ecosystem::PyPI,
                name,
                version,
            })
    } else {
        None
    };
    let Some(id) = id else { return Vec::new() };
    index
        .lookup(&id)
        .into_iter()
        .take(4)
        .map(|mal| {
            Finding::new(
                FindingKind::Malware,
                FindingAction::Deny,
                SOURCE,
                truncate(
                    &format!(
                        "{mal}: an install script of {target} produced {}, which is listed as malware",
                        id.display()
                    ),
                    MAX_EVIDENCE_CHARS,
                ),
            )
            .target(target.to_string())
            .location(rel.to_string())
            .advisory(mal.to_string())
        })
        .collect()
}
