//! Pre-install risk checks (FR-025, SPEC-015).
//!
//! Before any package code runs, each package of the plan is compared with
//! its previous release, from registry metadata and the reviewed files:
//! (a) a new install script, (b) changed maintainers or publisher, (c) a very
//! new version, (d) a name that looks like a popular package, (e) newly
//! obfuscated or minified code. A hit is a `risk_signal` that needs approval.
//! A check whose data the registry did not return is reported as not
//! checked (`incomplete_scan`, `info`), never as clean.
//!
//! Registry documents are untrusted: bounded, parsed into the few fields the
//! checks read, and only a compact summary is cached (SPEC-006 cache).

use super::{cache, truncate, Ecosystem, PackageId, MAX_EVIDENCE_CHARS};
use crate::paths::TrustedPaths;
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::settings::Settings;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const SOURCE: &str = "checks";
const NPM_DOC_MAX: u64 = 64 << 20;
const PYPI_DOC_MAX: u64 = 16 << 20;
const TIMEOUT: Duration = Duration::from_secs(60);
const OBF_FILE_MAX: u64 = 4 << 20;
const OBF_FILES: usize = 2_000;
const OBF_PKG_MAX: u64 = 64 << 20;
const MAX_PEOPLE: usize = 64;
const MAX_FIELD: usize = 214;

const NPM_POPULAR: &str = include_str!("popular/npm.txt");
const PYPI_POPULAR: &str = include_str!("popular/pypi.txt");

/// One package of the plan with what the guard already reviewed.
pub struct Candidate {
    pub pkg: PackageId,
    /// npm: the installed package directory; PyPI: the reviewed wheel file.
    pub artifact: std::path::PathBuf,
    /// npm: the reviewed `package.json` has an install-time lifecycle script.
    pub install_script: bool,
}

/// Where registry metadata comes from (trusted settings only).
pub struct Origin<'a> {
    /// npm: the pinned registry URL (`https://registry.npmjs.org/`); PyPI:
    /// the pinned index URL (`https://pypi.org/simple`).
    pub url: &'a str,
    /// PyPI: hosts the index serves files from (wheels of a previous release
    /// are fetched only from these or the index host).
    pub file_hosts: &'a [String],
    pub artifact_max_bytes: u64,
}

// ------------------------------------------------------------------- facts

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
struct Release {
    version: String,
    published: Option<i64>,
    install_script: Option<bool>,
    /// npm maintainer names; PyPI author/maintainer names and emails.
    people: Option<Vec<String>>,
    /// npm `_npmUser`.
    publisher: Option<String>,
    /// URL and digest (npm SRI or `sha256:<hex>`) of an artifact.
    artifact: Option<(String, String)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
struct Facts {
    this: Release,
    prev: Option<Release>,
}

type FetchResult = Result<Facts, String>;

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into()
}

fn get_json(url: &str, max: u64) -> Result<serde_json::Value, String> {
    let mut r = agent()
        .get(url)
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity")
        .call()
        .map_err(|e| match e {
            ureq::Error::StatusCode(404) => "the registry has no record of it".to_string(),
            e => format!("registry metadata could not be fetched: {e}"),
        })?;
    let mut bytes = Vec::new();
    r.body_mut()
        .with_config()
        .limit(u64::MAX)
        .reader()
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("registry metadata could not be read: {e}"))?;
    if bytes.len() as u64 > max {
        return Err(format!("registry metadata is larger than {max} bytes"));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("registry metadata is not valid JSON: {e}"))
}

fn get_bytes(url: &str, max: u64) -> Result<Vec<u8>, String> {
    let mut r = agent()
        .get(url)
        .header("Accept-Encoding", "identity")
        .call()
        .map_err(|e| format!("previous release could not be fetched: {e}"))?;
    r.body_mut()
        .with_config()
        .limit(max)
        .read_to_vec()
        .map_err(|e| format!("previous release could not be read: {e}"))
}

fn clean(s: &str) -> Option<String> {
    let s: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FIELD)
        .collect();
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// `{name, email}` or `"name <email>"`.
fn person_name(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Object(o) => o.get("name").and_then(|n| n.as_str()).and_then(clean),
        serde_json::Value::String(s) => clean(s.split('<').next().unwrap_or(s)),
        _ => None,
    }
}

fn npm_release(version: &str, v: &serde_json::Value, time: Option<i64>) -> Release {
    let scripts = v.get("scripts").and_then(|s| s.as_object());
    let lifecycle = scripts.is_some_and(|s| {
        ["preinstall", "install", "postinstall"]
            .iter()
            .any(|k| s.contains_key(*k))
    });
    let has = v.get("hasInstallScript").and_then(|h| h.as_bool()) == Some(true);
    let people = v.get("maintainers").and_then(|m| m.as_array()).map(|a| {
        let set: BTreeSet<String> = a.iter().take(MAX_PEOPLE).filter_map(person_name).collect();
        set.into_iter().collect::<Vec<_>>()
    });
    let dist = v.get("dist");
    let artifact = dist.and_then(|d| {
        Some((
            d.get("tarball")?.as_str()?.to_string(),
            d.get("integrity")?.as_str()?.to_string(),
        ))
    });
    Release {
        version: version.to_string(),
        published: time,
        install_script: Some(lifecycle || has),
        people: people.filter(|p| !p.is_empty()),
        publisher: v.get("_npmUser").and_then(person_name),
        artifact,
    }
}

/// The previous release: the latest publish time before `this`.
fn previous<'a>(
    times: impl Iterator<Item = (&'a String, i64)>,
    this: &str,
    at: i64,
) -> Option<&'a String> {
    times
        .filter(|(v, t)| v.as_str() != this && *t < at)
        .max_by_key(|(_, t)| *t)
        .map(|(v, _)| v)
}

fn npm_facts(registry: &str, name: &str, version: &str) -> FetchResult {
    let ok_name = !name.is_empty()
        && name.len() <= 214
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@/._~-".contains(&b));
    if !ok_name {
        return Err("package name cannot be looked up on the registry".into());
    }
    let url = format!("{registry}{}", name.replacen('/', "%2f", 1));
    let doc = get_json(&url, NPM_DOC_MAX)?;
    let versions = doc
        .get("versions")
        .and_then(|v| v.as_object())
        .ok_or("registry metadata has no versions")?;
    let v = versions
        .get(version)
        .ok_or_else(|| format!("registry metadata has no version {version}"))?;
    let times: BTreeMap<String, i64> = doc
        .get("time")
        .and_then(|t| t.as_object())
        .map(|t| {
            t.iter()
                .filter(|(k, _)| k.as_str() != "created" && k.as_str() != "modified")
                .filter_map(|(k, v)| Some((k.clone(), rfc3339(v.as_str()?)?)))
                .collect()
        })
        .unwrap_or_default();
    let at = times.get(version).copied();
    let this = npm_release(version, v, at);
    let prev = at
        .and_then(|at| {
            previous(
                times
                    .iter()
                    .filter(|(k, _)| versions.contains_key(*k))
                    .map(|(k, t)| (k, *t)),
                version,
                at,
            )
        })
        .map(|p| npm_release(p, &versions[p], times.get(p).copied()));
    Ok(Facts { this, prev })
}

fn pypi_people(info: &serde_json::Value) -> Option<Vec<String>> {
    let mut set = BTreeSet::new();
    for k in ["author", "author_email", "maintainer", "maintainer_email"] {
        if let Some(s) = info.get(k).and_then(|v| v.as_str()) {
            for part in s.split(',') {
                if let Some(p) = clean(&part.to_lowercase()) {
                    set.insert(p);
                }
            }
        }
    }
    (!set.is_empty()).then(|| set.into_iter().take(MAX_PEOPLE).collect())
}

/// Earliest upload time and a preferred wheel of one release's files.
fn pypi_files(files: &serde_json::Value) -> (Option<i64>, bool, Option<(String, String)>) {
    let files = files.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let published = files
        .iter()
        .filter_map(|f| rfc3339(f.get("upload_time_iso_8601")?.as_str()?))
        .min();
    let yanked = !files.is_empty()
        && files
            .iter()
            .all(|f| f.get("yanked").and_then(|y| y.as_bool()) == Some(true));
    let wheel = |f: &serde_json::Value| -> Option<(String, String, bool)> {
        let name = f.get("filename")?.as_str()?;
        if !name.ends_with(".whl") {
            return None;
        }
        Some((
            f.get("url")?.as_str()?.to_string(),
            format!("sha256:{}", f.get("digests")?.get("sha256")?.as_str()?),
            name.ends_with("-py3-none-any.whl") || name.ends_with("-py2.py3-none-any.whl"),
        ))
    };
    let mut wheels: Vec<_> = files.iter().filter_map(wheel).collect();
    wheels.sort_by_key(|w| !w.2);
    (
        published,
        yanked,
        wheels.into_iter().next().map(|w| (w.0, w.1)),
    )
}

fn pypi_facts(base: &str, name: &str, version: &str) -> FetchResult {
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= MAX_FIELD
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-+!".contains(&b))
    };
    if !ok(name) || !ok(version) {
        return Err("package name or version cannot be looked up on the index".into());
    }
    let doc = get_json(&format!("{base}/pypi/{name}/json"), PYPI_DOC_MAX)?;
    let releases = doc
        .get("releases")
        .and_then(|r| r.as_object())
        .ok_or("index metadata has no releases")?;
    let mut times: BTreeMap<String, i64> = BTreeMap::new();
    for (v, files) in releases {
        if let (Some(t), false, _) = pypi_files(files) {
            times.insert(v.clone(), t);
        }
    }
    let (published, _, _) = releases
        .get(version)
        .map(pypi_files)
        .ok_or_else(|| format!("index metadata has no release {version}"))?;
    let info_of = |v: &str| -> Option<serde_json::Value> {
        let info = doc.get("info")?;
        if info.get("version").and_then(|x| x.as_str()) == Some(v) {
            return Some(info.clone());
        }
        get_json(&format!("{base}/pypi/{name}/{v}/json"), PYPI_DOC_MAX)
            .ok()?
            .get("info")
            .cloned()
    };
    let this = Release {
        version: version.to_string(),
        published,
        install_script: None,
        people: info_of(version).as_ref().and_then(pypi_people),
        publisher: None,
        artifact: None,
    };
    let prev = published
        .and_then(|at| previous(times.iter().map(|(k, t)| (k, *t)), version, at))
        .map(|p| {
            let (t, _, wheel) = pypi_files(&releases[p]);
            Release {
                version: p.clone(),
                published: t,
                install_script: None,
                people: info_of(p).as_ref().and_then(pypi_people),
                publisher: None,
                artifact: wheel,
            }
        });
    Ok(Facts { this, prev })
}

/// Facts for one package, from the cache when fresh.
fn facts(
    paths: &TrustedPaths,
    settings: &Settings,
    origin: &Origin,
    pkg: &PackageId,
) -> FetchResult {
    let root = cache::ensure(paths);
    let key = format!(
        "{}:facts:{}:{}@{}",
        cache::KEY_VERSION,
        super::ecosystem_str(pkg.ecosystem),
        pkg.name,
        pkg.version
    );
    let path = cache::path_for(&root, &key);
    if let Some(e) = cache::read::<Facts>(&path) {
        if !cache::is_stale(e.stored_at, settings.advisories.ttl_secs) {
            return Ok(e.data);
        }
    }
    let got = match pkg.ecosystem {
        Ecosystem::Npm => npm_facts(origin.url, &pkg.name, &pkg.version),
        Ecosystem::PyPI => {
            let base = origin.url.trim_end_matches('/');
            let base = base.strip_suffix("/simple").unwrap_or(base);
            match super::osv::normalize_base_url(base) {
                Some(b) => pypi_facts(&b, &pkg.name, &pkg.version),
                None => Err("the index URL is not https or loopback".into()),
            }
        }
    }?;
    let max = settings.advisories.cache_max_bytes;
    cache::write(&path, &got, cache::now_secs(), max);
    cache::evict(&root, max);
    Ok(got)
}

// --------------------------------------------------------------- artifacts

/// `(file, why)` of obfuscated or minified code in a file, if any.
pub fn obfuscation(name: &str, bytes: &[u8]) -> Option<&'static str> {
    static RX: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (hex_id, py_exec) = RX.get_or_init(|| {
        (
            Regex::new(r"_0x[0-9a-f]{4,6}\b").expect("static"),
            Regex::new(r"exec\s*\(\s*(?:marshal\.loads|zlib\.decompress|base64\.b64decode)\s*\(")
                .expect("static"),
        )
    });
    let lower = name.to_ascii_lowercase();
    let js = [".js", ".cjs", ".mjs"].iter().any(|e| lower.ends_with(e));
    let py = lower.ends_with(".py");
    if !(js || py)
        || bytes.len() as u64 > OBF_FILE_MAX
        || bytes[..bytes.len().min(8192)].contains(&0)
    {
        return None;
    }
    let text = String::from_utf8_lossy(bytes);
    if js && hex_id.find_iter(&text).take(20).count() >= 20 {
        return Some("javascript-obfuscator identifiers");
    }
    if py && (text.contains("__pyarmor__") || text.contains("pyarmor_runtime")) {
        return Some("PyArmor-protected code");
    }
    if py && py_exec.is_match(&text) {
        return Some("code that executes decoded data");
    }
    if text.len() >= 4096
        && text
            .lines()
            .any(|l| l.len() > 1000 && l.bytes().filter(|&b| b == b' ').count() * 50 < l.len())
    {
        return Some("minified code");
    }
    None
}

/// Obfuscated files of one installed npm package directory (bounded).
fn obfuscated_in_dir(dir: &Path) -> Vec<(String, &'static str)> {
    let (files, _) = super::yara::walk(dir);
    let mut out = Vec::new();
    let mut used = 0u64;
    for rel in files.into_iter().take(OBF_FILES) {
        let full = dir.join(&rel);
        let len = std::fs::metadata(&full)
            .map(|m| m.len())
            .unwrap_or(u64::MAX);
        if len > OBF_FILE_MAX || used + len > OBF_PKG_MAX || !looks_code(&rel) {
            continue;
        }
        used += len;
        if let Ok(b) = std::fs::read(&full) {
            if let Some(why) = obfuscation(&rel, &b) {
                out.push((rel, why));
            }
        }
    }
    out
}

fn looks_code(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [".js", ".cjs", ".mjs", ".py"]
        .iter()
        .any(|e| l.ends_with(e))
}

/// Obfuscated files and startup entries of a wheel (zip) or npm tarball.
#[derive(Default)]
struct ArchiveFacts {
    obfuscated: Vec<(String, &'static str)>,
    startup: Vec<String>,
}

fn zip_facts<R: Read + std::io::Seek>(reader: R) -> Result<ArchiveFacts, String> {
    let mut z = zip::ZipArchive::new(reader).map_err(|e| format!("not a wheel: {e}"))?;
    let mut out = ArchiveFacts::default();
    let mut used = 0u64;
    for i in 0..z.len().min(OBF_FILES * 10) {
        let Ok(mut e) = z.by_index(i) else { continue };
        let name = String::from_utf8_lossy(e.name_raw()).replace('\\', "/");
        if super::yara::is_startup_entry(&name) {
            out.startup.push(name.clone());
        }
        if !looks_code(&name) || e.size() > OBF_FILE_MAX || used + e.size() > OBF_PKG_MAX {
            continue;
        }
        used += e.size();
        let mut b = Vec::new();
        if (&mut e).take(OBF_FILE_MAX + 1).read_to_end(&mut b).is_ok() {
            if let Some(why) = obfuscation(&name, &b) {
                out.obfuscated.push((name, why));
            }
        }
    }
    Ok(out)
}

fn tgz_facts(bytes: &[u8]) -> Result<ArchiveFacts, String> {
    let mut a = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    let mut out = ArchiveFacts::default();
    let mut used = 0u64;
    for (n, e) in a.entries().map_err(|e| e.to_string())?.enumerate() {
        let mut e = e.map_err(|e| format!("not a package tarball: {e}"))?;
        if n > OBF_FILES * 10 {
            break;
        }
        let name = e
            .path()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let name = name
            .split_once('/')
            .map_or(name.as_str(), |(_, r)| r)
            .to_string();
        if !e.header().entry_type().is_file()
            || !looks_code(&name)
            || name.split('/').any(|c| c == "node_modules")
            || e.size() > OBF_FILE_MAX
            || used + e.size() > OBF_PKG_MAX
        {
            continue;
        }
        used += e.size();
        let mut b = Vec::new();
        (&mut e)
            .take(OBF_FILE_MAX + 1)
            .read_to_end(&mut b)
            .map_err(|e| format!("not a package tarball: {e}"))?;
        if let Some(why) = obfuscation(&name, &b) {
            out.obfuscated.push((name, why));
        }
    }
    Ok(out)
}

/// `scheme://authority/` of a URL.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let auth = rest.split('/').next()?;
    (!auth.is_empty()).then(|| format!("{}://{auth}/", scheme.to_ascii_lowercase()))
}

fn sri_ok(sri: &str, bytes: &[u8]) -> bool {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    sri.split_whitespace()
        .any(|part| match part.split_once('-') {
            Some(("sha512", d)) => b64
                .decode(d)
                .is_ok_and(|d| d == Sha512::digest(bytes).as_slice()),
            _ => false,
        })
}

/// Download and inspect the previous release's artifact (bounded, verified).
fn previous_artifact(
    eco: Ecosystem,
    origin: &Origin,
    prev: &Release,
) -> Result<ArchiveFacts, String> {
    let (url, digest) = prev
        .artifact
        .as_ref()
        .ok_or("the registry lists no artifact for the previous release")?;
    match eco {
        Ecosystem::Npm => {
            let allowed = origin_of(origin.url);
            if allowed.is_none() || origin_of(url) != allowed {
                return Err("the previous release is not served by the pinned registry".into());
            }
            let bytes = get_bytes(url, origin.artifact_max_bytes)?;
            if !sri_ok(digest, &bytes) {
                return Err("the previous release does not match its registry integrity".into());
            }
            tgz_facts(&bytes)
        }
        Ecosystem::PyPI => {
            let Some(url) = super::osv::normalize_base_url(url) else {
                return Err("the previous wheel URL is not https or loopback".into());
            };
            let host = url
                .split("://")
                .nth(1)
                .and_then(|r| r.split('/').next())
                .unwrap_or("");
            let index_host = origin
                .url
                .split("://")
                .nth(1)
                .and_then(|r| r.split('/').next());
            if !origin.file_hosts.iter().any(|h| h == host) && index_host != Some(host) {
                return Err("the previous wheel is not served by the pinned index".into());
            }
            let bytes = get_bytes(&url, origin.artifact_max_bytes)?;
            let want = digest.strip_prefix("sha256:").unwrap_or("");
            if !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(want) {
                return Err("the previous wheel does not match its index digest".into());
            }
            zip_facts(std::io::Cursor::new(bytes))
        }
    }
}

// -------------------------------------------------------------- look-alike

/// Popular names and their folded forms.
type Popular = (BTreeSet<String>, Vec<(String, String)>);

fn popular(eco: Ecosystem) -> &'static Popular {
    static NPM: OnceLock<Popular> = OnceLock::new();
    static PYPI: OnceLock<Popular> = OnceLock::new();
    let (cell, text) = match eco {
        Ecosystem::Npm => (&NPM, NPM_POPULAR),
        Ecosystem::PyPI => (&PYPI, PYPI_POPULAR),
    };
    cell.get_or_init(|| {
        let names: BTreeSet<String> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| norm(eco, l))
            .collect();
        let folded = names.iter().map(|n| (n.clone(), fold(n))).collect();
        (names, folded)
    })
}

fn norm(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::Npm => name.to_ascii_lowercase(),
        Ecosystem::PyPI => super::malware_list::pypi_name(name),
    }
}

/// Homoglyph and separator folding.
fn fold(name: &str) -> String {
    let s = name.replace("rn", "m").replace("vv", "w");
    s.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .map(|c| match c {
            '0' => 'o',
            '1' | 'i' | '|' => 'l',
            '5' => 's',
            c => c,
        })
        .collect()
}

/// Optimal string alignment distance, `> 1` reported as 2.
fn within_one(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, v) in d[0].iter_mut().enumerate() {
        *v = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[n][m] <= 1
}

/// The popular name `name` imitates, and how. `None` for popular names.
pub fn look_alike(eco: Ecosystem, name: &str) -> Option<(String, &'static str)> {
    let (names, folded) = popular(eco);
    let name = norm(eco, name);
    if names.contains(&name) {
        return None;
    }
    let mine = fold(&name);
    if name.chars().count() >= 3 {
        if let Some((p, _)) = folded.iter().find(|(_, f)| *f == mine) {
            return Some((p.clone(), "a homoglyph or separator swap of"));
        }
    }
    if name.chars().count() >= 5 {
        if let Some(p) = names
            .iter()
            .find(|p| p.chars().count() >= 5 && within_one(&name, p))
        {
            return Some((p.clone(), "one edit away from"));
        }
    }
    None
}

// ------------------------------------------------------------------ checks

fn signal(pkg: &PackageId, letter: char, what: &str, evidence: String) -> Finding {
    Finding::new(
        FindingKind::RiskSignal,
        FindingAction::Approve,
        SOURCE,
        truncate(
            &crate::redact::redact_url_credentials(&format!("({letter}) {what}: {evidence}")),
            MAX_EVIDENCE_CHARS,
        ),
    )
    .target(pkg.display())
}

fn list(v: &BTreeSet<&String>) -> String {
    v.iter()
        .take(5)
        .map(|s| format!("`{s}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Run the checks for one package with its (possibly missing) facts.
fn check_one(
    settings: &Settings,
    origin: &Origin,
    cand: &Candidate,
    facts: FetchResult,
    now: i64,
) -> Vec<Finding> {
    let pkg = &cand.pkg;
    let mut out = Vec::new();
    let mut gaps: Vec<String> = Vec::new();

    // (d) needs no metadata.
    if let Some((popular, how)) = look_alike(pkg.ecosystem, &pkg.name) {
        out.push(signal(
            pkg,
            'd',
            "look-alike name",
            format!("`{}` is {how} the popular package `{popular}`", pkg.name),
        ));
    }

    let facts = match facts {
        Ok(f) => f,
        Err(why) => {
            gaps.push(format!("(a), (b), (c), (e): {why}"));
            out.push(not_checked(pkg, &gaps));
            return out;
        }
    };
    let this = &facts.this;

    // (c) very new.
    match this.published {
        Some(t) => {
            let min = settings.checks.min_age_hours.saturating_mul(3600) as i64;
            let age = now - t;
            if age < min {
                let when = if age < 0 {
                    "in the future".to_string()
                } else {
                    format!("{} hour(s) ago", age / 3600)
                };
                out.push(signal(
                    pkg,
                    'c',
                    "very new version",
                    format!(
                        "{} was published {when} (checks.min_age_hours = {})",
                        pkg.version, settings.checks.min_age_hours
                    ),
                ));
            }
        }
        None => gaps.push("(c): the registry returned no publish time".into()),
    }

    let Some(prev) = &facts.prev else {
        // First release (or no earlier publish time): (a), (b), (e) do not apply.
        if this.published.is_none() {
            gaps.push(
                "(a), (b), (e): the previous release is unknown without publish times".into(),
            );
        }
        if !gaps.is_empty() {
            out.push(not_checked(pkg, &gaps));
        }
        return out;
    };

    // (b) maintainers / publisher.
    match (&this.people, &prev.people) {
        (Some(now_p), Some(old_p)) => {
            let a: BTreeSet<&String> = now_p.iter().collect();
            let b: BTreeSet<&String> = old_p.iter().collect();
            let added: BTreeSet<&String> = a.difference(&b).copied().collect();
            let removed: BTreeSet<&String> = b.difference(&a).copied().collect();
            if !added.is_empty() || !removed.is_empty() {
                let mut ev = format!("since {}", prev.version);
                if !added.is_empty() {
                    ev.push_str(&format!(", added {}", list(&added)));
                }
                if !removed.is_empty() {
                    ev.push_str(&format!(", removed {}", list(&removed)));
                }
                out.push(signal(pkg, 'b', "maintainers changed", ev));
            } else if let (Some(p), Some(pp)) = (&this.publisher, &prev.publisher) {
                if p != pp && !b.contains(p) {
                    out.push(signal(
                        pkg,
                        'b',
                        "new publisher",
                        format!(
                            "published by `{p}`, who was neither a maintainer nor the publisher (`{pp}`) of {}",
                            prev.version
                        ),
                    ));
                }
            }
        }
        _ => gaps.push(
            "(b): the registry returned no maintainers for this or the previous release".into(),
        ),
    }

    // (a) and (e) against the previous release.
    let (cur_script, cur_obf, cur_startup) = match pkg.ecosystem {
        Ecosystem::Npm => (
            cand.install_script || this.install_script == Some(true),
            obfuscated_in_dir(&cand.artifact),
            Vec::new(),
        ),
        Ecosystem::PyPI => match std::fs::File::open(&cand.artifact)
            .map_err(|e| e.to_string())
            .and_then(zip_facts)
        {
            Ok(f) => (false, f.obfuscated, f.startup),
            Err(e) => {
                gaps.push(format!("(a), (e): the reviewed wheel cannot be read: {e}"));
                (false, Vec::new(), Vec::new())
            }
        },
    };
    if pkg.ecosystem == Ecosystem::Npm && cur_script {
        match prev.install_script {
            Some(false) => out.push(signal(
                pkg,
                'a',
                "new install script",
                format!(
                    "{} runs an install script (preinstall/install/postinstall); {} had none",
                    pkg.version, prev.version
                ),
            )),
            Some(true) => {}
            None => gaps.push("(a): the previous release's scripts are unknown".into()),
        }
    }
    let need_prev = !cur_obf.is_empty() || !cur_startup.is_empty();
    if need_prev {
        match previous_artifact(pkg.ecosystem, origin, prev) {
            Ok(old) => {
                if let Some((file, why)) = cur_obf.first() {
                    if old.obfuscated.is_empty() {
                        out.push(signal(
                            pkg,
                            'e',
                            "newly obfuscated code",
                            format!(
                                "{file} is {why}; {} had no obfuscated or minified code ({} file(s) now)",
                                prev.version,
                                cur_obf.len()
                            ),
                        ));
                    }
                }
                if let Some(file) = cur_startup.first() {
                    if old.startup.is_empty() {
                        out.push(signal(
                            pkg,
                            'a',
                            "new startup file",
                            format!(
                                "{} installs {file}, which runs whenever Python starts; {} installed no startup file",
                                pkg.version, prev.version
                            ),
                        ));
                    }
                }
            }
            Err(why) => gaps.push(format!("(a), (e): {why}")),
        }
    }
    if !gaps.is_empty() {
        out.push(not_checked(pkg, &gaps));
    }
    out
}

fn not_checked(pkg: &PackageId, gaps: &[String]) -> Finding {
    Finding::new(
        FindingKind::IncompleteScan,
        FindingAction::Info,
        SOURCE,
        truncate(
            &crate::redact::redact_url_credentials(&format!(
                "pre-install checks not run for {}: {}",
                pkg.display(),
                gaps.join("; ")
            )),
            MAX_EVIDENCE_CHARS,
        ),
    )
    .target(pkg.display())
}

/// Run every check for the plan. Empty when `checks.enabled` is off.
pub fn run(
    paths: &TrustedPaths,
    settings: &Settings,
    origin: &Origin,
    cands: &[Candidate],
) -> Vec<Finding> {
    if !settings.checks.enabled || cands.is_empty() {
        return Vec::new();
    }
    let now = cache::now_secs() as i64;
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Vec<Finding>>> = cands.iter().map(|_| Mutex::default()).collect();
    std::thread::scope(|s| {
        for _ in 0..cands.len().clamp(1, 8) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(c) = cands.get(i) else { break };
                let f = facts(paths, settings, origin, &c.pkg);
                *slots[i].lock().expect("slot") = check_one(settings, origin, c, f, now);
            });
        }
    });
    slots
        .into_iter()
        .flat_map(|s| s.into_inner().expect("slot"))
        .collect()
}

/// RFC 3339 timestamp to Unix seconds (`Z` or `±hh:mm`, optional fraction).
fn rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let d = b.get(r)?;
        d.iter()
            .all(u8::is_ascii_digit)
            .then(|| d.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0')))
    };
    let seps = [(4, b'-'), (7, b'-'), (13, b':'), (16, b':')];
    if b.len() < 19 || seps.iter().any(|&(i, c)| b[i] != c) || !b"Tt ".contains(&b[10]) {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let offset = match b.get(i..)? {
        // PyPI's `upload_time` has no zone; it is UTC.
        b"" | b"Z" | b"z" => 0,
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
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * 86_400 + h * 3600 + mi * 60 + sec - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn look_alikes() {
        for n in ["lodahs", "l0dash", "lodash_", "expresss", "reqeust"] {
            assert!(look_alike(Ecosystem::Npm, n).is_some(), "{n}");
        }
        for n in [
            "lodash",
            "express",
            "react",
            "left-pad-not-popular-xyz",
            "ab",
        ] {
            assert!(look_alike(Ecosystem::Npm, n).is_none(), "{n}");
        }
        assert_eq!(
            look_alike(Ecosystem::PyPI, "reqeusts").map(|p| p.0),
            Some("requests".to_string())
        );
        assert!(look_alike(Ecosystem::PyPI, "Requests").is_none());
        assert!(look_alike(Ecosystem::PyPI, "charset_normalizer").is_none());
    }

    #[test]
    fn osa_distance() {
        assert!(within_one("lodash", "lodahs"));
        assert!(within_one("lodash", "lodas"));
        assert!(within_one("lodash", "lodashx"));
        assert!(!within_one("lodash", "ldahs"));
    }

    #[test]
    fn obfuscation_detector() {
        let obf: String = (0..30).map(|i| format!("var _0x{i:04x}=1;")).collect();
        assert!(obfuscation("a.js", obf.as_bytes()).is_some());
        let min = format!("{}\n", "a=b;".repeat(1500));
        assert_eq!(obfuscation("m.js", min.as_bytes()), Some("minified code"));
        assert!(obfuscation("m.txt", min.as_bytes()).is_none());
        let plain = "function f(a, b) {\n  return a + b;\n}\n".repeat(200);
        assert!(obfuscation("p.js", plain.as_bytes()).is_none());
        assert!(obfuscation("x.py", b"exec(zlib.decompress(b'...'))").is_some());
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339("2026-11-10T09:15:22.123Z"), Some(1_794_302_122));
        assert_eq!(rfc3339("2026-11-10T09:15:22"), Some(1_794_302_122));
        assert_eq!(rfc3339("2026-11-10T10:15:22+01:00"), Some(1_794_302_122));
        assert_eq!(rfc3339("yesterday"), None);
    }

    #[test]
    fn previous_is_latest_earlier_publish() {
        let t: BTreeMap<String, i64> = [
            ("1.0.0".into(), 10),
            ("2.0.0".into(), 30),
            ("1.1.0".into(), 20),
        ]
        .into();
        assert_eq!(
            previous(t.iter().map(|(k, v)| (k, *v)), "2.0.0", 30).map(String::as_str),
            Some("1.1.0")
        );
        assert_eq!(previous(t.iter().map(|(k, v)| (k, *v)), "1.0.0", 10), None);
    }
}
