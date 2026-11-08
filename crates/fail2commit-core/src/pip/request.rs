//! Request parsing (FR-005): everything the guard cannot review is rejected
//! here, before any resolver or network access.
//!
//! Accepted input is plain `name[extras]specifiers; marker` requirements,
//! optionally with `--hash=sha256:...`, from arguments or `-r`/`-c` files
//! that stay inside the top-level file's directory. The resolver never sees
//! the user's text: [`InstallRequest::requirements_txt`] regenerates it.

use crate::{Error, Finding, FindingAction, FindingKind, ResultCode};
use regex::Regex;
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_FILES: usize = 32;
const MAX_DEPTH: usize = 4;
const MAX_REQUIREMENTS: usize = 5000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub extras: Vec<String>,
    pub spec: String,
    pub marker: Option<String>,
    /// Lowercase hex SHA-256 values the user pinned.
    pub hashes: Vec<String>,
}

impl Requirement {
    pub fn canonical(&self) -> String {
        let mut s = self.name.clone();
        if !self.extras.is_empty() {
            s.push_str(&format!("[{}]", self.extras.join(",")));
        }
        s.push_str(&self.spec);
        if let Some(m) = &self.marker {
            s.push_str(&format!(" ; {m}"));
        }
        s
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallRequest {
    pub requirements: Vec<Requirement>,
    pub constraints: Vec<Requirement>,
    pub upgrade: bool,
    pub pre: bool,
}

impl InstallRequest {
    pub fn requirements_txt(&self) -> String {
        lines(&self.requirements)
    }
    pub fn constraints_txt(&self) -> String {
        lines(&self.constraints)
    }
    /// Sorted canonical forms for the approval digest.
    pub fn canonical(&self) -> Vec<String> {
        let mut v: Vec<String> = self.requirements.iter().map(|r| r.canonical()).collect();
        v.extend(
            self.constraints
                .iter()
                .map(|r| format!("-c {}", r.canonical())),
        );
        v.sort();
        v
    }
}

fn lines(reqs: &[Requirement]) -> String {
    reqs.iter().map(|r| r.canonical() + "\n").collect()
}

fn unsupported(source: &str, evidence: String) -> Error {
    Error::new(
        ResultCode::InvalidInput,
        format!("unsupported input: {evidence}"),
    )
    .with_findings(vec![Finding::new(
        FindingKind::UnsupportedInput,
        FindingAction::Deny,
        source,
        evidence,
    )])
}

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("static regex"))
}

/// Parse `install` arguments (everything after the word `install`).
pub fn parse_args(args: &[OsString], cwd: &Path) -> crate::Result<InstallRequest> {
    let mut req = InstallRequest::default();
    let mut st = State::default();
    let mut it = args.iter();
    while let Some(raw) = it.next() {
        let a = raw
            .to_str()
            .ok_or_else(|| Error::invalid("arguments must be valid UTF-8"))?;
        let mut value = |flag: &str| -> crate::Result<String> {
            it.next()
                .and_then(|v| v.to_str().map(str::to_string))
                .ok_or_else(|| Error::invalid(format!("{flag} needs a value")))
        };
        match a {
            "-U" | "--upgrade" => req.upgrade = true,
            "--pre" => req.pre = true,
            "-r" | "--requirement" => {
                let v = value(a)?;
                add_file(&mut req, &mut st, cwd, &v, false, None)?;
            }
            "-c" | "--constraint" => {
                let v = value(a)?;
                add_file(&mut req, &mut st, cwd, &v, true, None)?;
            }
            _ if a.starts_with("--requirement=") => add_file(
                &mut req,
                &mut st,
                cwd,
                &a["--requirement=".len()..],
                false,
                None,
            )?,
            _ if a.starts_with("--constraint=") => add_file(
                &mut req,
                &mut st,
                cwd,
                &a["--constraint=".len()..],
                true,
                None,
            )?,
            _ if a.starts_with('-') => return Err(reject_option(a)),
            _ => {
                let r = parse_requirement(a, "argument")?;
                req.requirements.push(r);
            }
        }
    }
    if req.requirements.is_empty() {
        return Err(Error::invalid("no requirements given"));
    }
    if req.requirements.len() > MAX_REQUIREMENTS {
        return Err(Error::invalid("too many requirements"));
    }
    Ok(req)
}

#[derive(Default)]
struct State {
    seen: HashSet<PathBuf>,
    root: Option<PathBuf>,
}

/// Classify a rejected option: index/editable are policy findings.
fn reject_option(a: &str) -> Error {
    let name = a.split('=').next().unwrap_or(a);
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "-e" | "--editable" => unsupported("pip.request", format!("editable install: {name}")),
        "-i" | "--index-url" | "--extra-index-url" | "-f" | "--find-links" | "--trusted-host"
        | "--no-index" => unsupported(
            "pip.request",
            format!("untrusted index directive: {name} (the index is pinned in trusted settings)"),
        ),
        _ if lower.starts_with("-e") && !lower.starts_with("--") => {
            unsupported("pip.request", "editable install: -e".into())
        }
        _ if lower.starts_with("-i") || lower.starts_with("-f") => unsupported(
            "pip.request",
            format!("untrusted index directive: {}", &lower[..2]),
        ),
        _ => Error::invalid(format!("unsupported option: {name}")),
    }
}

fn add_file(
    req: &mut InstallRequest,
    st: &mut State,
    cwd: &Path,
    path: &str,
    constraint: bool,
    including: Option<(&Path, usize)>,
) -> crate::Result<()> {
    if path.contains("://") || path.contains('$') || path.contains('%') {
        return Err(unsupported(
            "pip.request",
            format!("requirements file must be a local path: {path}"),
        ));
    }
    if including.is_none() {
        st.root = None; // each command-line file defines its own allowed tree
    }
    let base = including.map(|(d, _)| d).unwrap_or(cwd);
    let depth = including.map(|(_, d)| d + 1).unwrap_or(0);
    let p = Path::new(path);
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    };
    let canon = full
        .canonicalize()
        .map_err(|_| Error::invalid(format!("cannot read requirements file {path}")))?;
    if !canon.is_file() {
        return Err(Error::invalid(format!("{path} is not a file")));
    }
    let dir = canon.parent().unwrap_or(&canon).to_path_buf();
    match &st.root {
        None => st.root = Some(dir.clone()),
        Some(root) if !canon.starts_with(root) => {
            return Err(unsupported(
                "pip.request",
                format!("nested file outside the allowed directory: {path}"),
            ))
        }
        Some(_) => {}
    }
    if depth > MAX_DEPTH || st.seen.len() >= MAX_FILES {
        return Err(Error::invalid("requirements files nest too deeply"));
    }
    if !st.seen.insert(canon.clone()) {
        return Ok(()); // already included (also breaks cycles)
    }
    let bytes = crate::fsutil::read_bounded(&canon, MAX_FILE_BYTES)?;
    let text =
        String::from_utf8(bytes).map_err(|_| Error::invalid(format!("{path} is not UTF-8")))?;
    for line in logical_lines(&text) {
        parse_file_line(req, st, &line, &dir, depth, constraint, path)?;
    }
    Ok(())
}

fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for raw in text.lines() {
        let raw = raw.trim_end();
        if let Some(stripped) = raw.strip_suffix('\\') {
            cur.push_str(stripped);
            cur.push(' ');
            continue;
        }
        cur.push_str(raw);
        let line = strip_comment(&cur);
        if !line.is_empty() {
            out.push(line);
        }
        cur.clear();
    }
    let line = strip_comment(&cur);
    if !line.is_empty() {
        out.push(line);
    }
    out
}

fn strip_comment(s: &str) -> String {
    let mut prev_ws = true;
    for (i, c) in s.char_indices() {
        if c == '#' && prev_ws {
            return s[..i].trim().to_string();
        }
        prev_ws = c.is_whitespace();
    }
    s.trim().to_string()
}

fn parse_file_line(
    req: &mut InstallRequest,
    st: &mut State,
    line: &str,
    dir: &Path,
    depth: usize,
    constraint: bool,
    origin: &str,
) -> crate::Result<()> {
    if let Some(opt) = line.strip_prefix('-') {
        let (flag, val) = split_option(&format!("-{opt}"));
        return match flag.as_str() {
            "-r" | "--requirement" | "-c" | "--constraint" => {
                let nested_constraint = constraint || flag == "-c" || flag == "--constraint";
                add_file(
                    req,
                    st,
                    dir,
                    &val.ok_or_else(|| Error::invalid(format!("{flag} needs a value")))?,
                    nested_constraint,
                    Some((dir, depth)),
                )
            }
            _ => Err(reject_option(&flag)),
        };
    }
    let r = parse_requirement(line, origin)?;
    if constraint {
        if !r.hashes.is_empty() {
            return Err(Error::invalid("constraints cannot carry hashes"));
        }
        req.constraints.push(r);
    } else {
        req.requirements.push(r);
    }
    if req.requirements.len() + req.constraints.len() > MAX_REQUIREMENTS {
        return Err(Error::invalid("too many requirements"));
    }
    Ok(())
}

fn split_option(s: &str) -> (String, Option<String>) {
    if let Some(rest) = s.strip_prefix("--") {
        if let Some((k, v)) = rest.split_once(['=', ' ']) {
            return (format!("--{k}"), Some(v.trim().to_string()));
        }
        return (s.to_string(), None);
    }
    // short form: `-r file` or `-rfile`
    let flag: String = s.chars().take(2).collect();
    let rest = s[flag.len()..].trim();
    (flag, (!rest.is_empty()).then(|| rest.to_string()))
}

/// Parse one requirement (plus optional `--hash=` tokens).
pub fn parse_requirement(text: &str, origin: &str) -> crate::Result<Requirement> {
    let mut parts = text.split(" --");
    let head = parts.next().unwrap_or("").trim();
    let mut hashes = Vec::new();
    for opt in parts {
        let opt = opt.trim();
        match opt.strip_prefix("hash=sha256:") {
            Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
                hashes.push(h.to_ascii_lowercase())
            }
            _ => {
                return Err(reject_option(&format!(
                    "--{}",
                    opt.split(['=', ' ']).next().unwrap_or("")
                )))
            }
        }
    }
    check_not_direct(head, origin)?;
    static R: OnceLock<Regex> = OnceLock::new();
    let caps = re(
        &R,
        r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([A-Za-z0-9._,\s-]*)\])?\s*([^;\[\]]*?)\s*(?:;\s*(.+))?$",
    )
    .captures(head)
    .ok_or_else(|| Error::invalid(format!("{origin}: not a plain requirement: {head}")))?;
    let name = caps[1].to_string();
    let extras: Vec<String> = caps
        .get(2)
        .map(|m| {
            m.as_str()
                .split(',')
                .map(|e| e.trim().to_string())
                .filter(|e| !e.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let spec = check_spec(caps.get(3).map_or("", |m| m.as_str()), origin)?;
    let marker = match caps.get(4) {
        Some(m) => {
            static M: OnceLock<Regex> = OnceLock::new();
            let m = m.as_str().trim();
            if !re(&M, r#"^[A-Za-z0-9 ._,'"()<>=!~*-]+$"#).is_match(m) {
                return Err(Error::invalid(format!("{origin}: unsupported marker")));
            }
            Some(m.to_string())
        }
        None => None,
    };
    Ok(Requirement {
        name,
        extras,
        spec,
        marker,
        hashes,
    })
}

fn check_spec(spec: &str, origin: &str) -> crate::Result<String> {
    let spec = spec
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    if spec.is_empty() {
        return Ok(String::new());
    }
    static S: OnceLock<Regex> = OnceLock::new();
    let rx = re(&S, r"^(~=|===|==|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+$");
    let mut out = Vec::new();
    for clause in spec.split(',') {
        let c = clause.trim();
        if !rx.is_match(c) {
            return Err(Error::invalid(format!(
                "{origin}: unsupported version specifier: {c}"
            )));
        }
        out.push(c.replace(' ', ""));
    }
    Ok(out.join(","))
}

/// URLs, VCS, paths and archives are not registry requirements.
fn check_not_direct(head: &str, origin: &str) -> crate::Result<()> {
    let lower = head.to_ascii_lowercase();
    let bad = lower.contains("://")
        || lower.contains('@')
        || ["git+", "hg+", "svn+", "bzr+", "file:"]
            .iter()
            .any(|p| lower.starts_with(p))
        || lower.starts_with(['.', '/', '\\', '~'])
        || lower.contains('/')
        || lower.contains('\\')
        || (lower.len() > 2
            && lower.as_bytes()[1] == b':'
            && lower.as_bytes()[0].is_ascii_alphabetic())
        || [
            ".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar",
        ]
        .iter()
        .any(|e| lower.ends_with(e));
    if bad {
        return Err(unsupported(
            "pip.request",
            format!("{origin}: direct reference, URL, local path or archive: {head}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn kind(e: &Error) -> Option<FindingKind> {
        e.findings.first().map(|f| f.kind)
    }

    #[test]
    fn plain_requirements() {
        let d = tempfile::tempdir().unwrap();
        let r = parse_args(
            &a(&[
                "requests[socks]>=2.0, <3",
                "flask==1.0; python_version >= '3.8'",
            ]),
            d.path(),
        )
        .unwrap();
        assert_eq!(r.requirements[0].canonical(), "requests[socks]>=2.0,<3");
        assert_eq!(
            r.requirements[1].canonical(),
            "flask==1.0 ; python_version >= '3.8'"
        );
    }

    #[test]
    fn rejects_unreviewable_input() {
        let d = tempfile::tempdir().unwrap();
        for bad in [
            "git+https://example.test/x.git",
            "pkg @ https://example.test/pkg-1.whl",
            "https://example.test/pkg-1.whl",
            "./local",
            "..\\local",
            "C:\\x\\pkg-1.whl",
            "pkg-1.0.tar.gz",
            "file:///tmp/x",
            "pkg/sub",
        ] {
            let e = parse_args(&a(&[bad]), d.path()).unwrap_err();
            assert_eq!(kind(&e), Some(FindingKind::UnsupportedInput), "{bad}");
        }
        for bad in [
            &["-e", "."][..],
            &["--editable=."],
            &["-i", "http://evil.test/simple"],
            &["--extra-index-url=http://evil.test"],
            &["--find-links", "x"],
            &["--trusted-host", "evil.test"],
        ] {
            let e = parse_args(&a(bad), d.path()).unwrap_err();
            assert_eq!(kind(&e), Some(FindingKind::UnsupportedInput), "{bad:?}");
        }
        assert!(parse_args(&a(&["--user", "x"]), d.path()).is_err());
        assert!(parse_args(&a(&[]), d.path()).is_err());
    }

    #[test]
    fn requirements_file_rules() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        std::fs::create_dir(p.join("sub")).unwrap();
        std::fs::write(
            p.join("req.txt"),
            "# c\nalpha==1 \\\n  --hash=sha256:".to_string()
                + &"ab".repeat(32)
                + "\n-r sub/more.txt\n",
        )
        .unwrap();
        std::fs::write(p.join("sub/more.txt"), "beta\n-c ../cons.txt\n").unwrap();
        std::fs::write(p.join("cons.txt"), "beta<2\n").unwrap();
        let r = parse_args(&a(&["-r", "req.txt"]), p).unwrap();
        assert_eq!(r.requirements.len(), 2);
        assert_eq!(r.requirements[0].hashes.len(), 1);
        assert_eq!(r.constraints[0].canonical(), "beta<2");

        // untrusted directives and escapes inside files
        for (body, want) in [
            ("--index-url http://evil.test\n", true),
            ("-e .\n", true),
            ("-r ../outside.txt\n", true),
            ("-r http://evil.test/r.txt\n", true),
            ("pkg @ https://evil.test/p.whl\n", true),
            ("--no-binary :all:\nx\n", false),
        ] {
            std::fs::write(p.join("sub/bad.txt"), body).unwrap();
            std::fs::write(p.join("outside.txt"), "x\n").unwrap();
            std::fs::write(p.join("sub/top.txt"), "-r bad.txt\n").unwrap();
            let e = parse_args(&a(&["-r", "sub/top.txt"]), p).unwrap_err();
            assert_eq!(
                kind(&e) == Some(FindingKind::UnsupportedInput),
                want,
                "{body}"
            );
        }
    }
}
