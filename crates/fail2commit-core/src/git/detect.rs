//! Secret detectors. Matched values are never returned, only redacted
//! placeholders (FR-001).

use regex::Regex;
use std::sync::OnceLock;

pub struct Hit {
    pub detector: &'static str,
    pub line: usize,
    /// Already redacted.
    pub evidence: String,
}

struct Rules {
    fixed: Vec<(&'static str, Regex)>,
    generic: Regex,
}

fn rules() -> &'static Rules {
    static R: OnceLock<Rules> = OnceLock::new();
    R.get_or_init(|| {
        let re = |p: &str| Regex::new(p).expect("static regex");
        Rules {
            fixed: vec![
                (
                    "private-key",
                    re(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
                ),
                (
                    "aws-access-key",
                    re(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b"),
                ),
                (
                    "github-token",
                    re(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
                ),
                ("gitlab-token", re(r"\bglpat-[A-Za-z0-9_-]{20,}")),
                ("slack-token", re(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
            ],
            // A quoted value runs to its closing quote (`#`, `,`, `;` are
            // password characters there); only an unquoted value stops at them.
            generic: re(
                r#"(?i)[\w.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)[\w.-]*["']?\s*[:=]\s*(?:"([^"\s]{8,})"|'([^'\s]{8,})'|["']?([^\s"'#,;]{8,}))"#,
            ),
        }
    })
}

/// Shannon entropy in bits per byte.
pub fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    v.starts_with(['$', '<', '{', '%'])
        || [
            "changeme",
            "example",
            "your_",
            "your-",
            "placeholder",
            "password",
            "secret",
            "xxxx",
            "****",
            "redacted",
            "dummy",
        ]
        .iter()
        .any(|p| l.contains(p))
        || v.bytes().all(|b| b == v.as_bytes()[0])
}

/// Scan text for secrets; at most one hit per (detector, line).
pub fn scan_text(text: &str) -> Vec<Hit> {
    let r = rules();
    let mut hits = Vec::new();
    for (i, full) in text.lines().enumerate() {
        // Overlong (minified/binary) lines are scanned in overlapping windows,
        // never skipped, so no byte goes unexamined.
        let first = hits.len();
        for line in windows(full) {
            for (name, re) in &r.fixed {
                if let Some(m) = re.find(line) {
                    hits.push(Hit {
                        detector: name,
                        line: i + 1,
                        evidence: crate::redact::redact(m.as_str()),
                    });
                }
            }
            if let Some(c) = r.generic.captures(line) {
                let v = (1..=3).find_map(|i| c.get(i)).map_or("", |m| m.as_str());
                if !placeholder(v) && entropy(v) >= 3.0 {
                    hits.push(Hit {
                        detector: "generic-assignment",
                        line: i + 1,
                        evidence: crate::redact::redact(v),
                    });
                }
            }
        }
        // at most one hit per (detector, line) across windows
        let mut seen: Vec<&'static str> = Vec::new();
        let mut keep = first;
        for j in first..hits.len() {
            if !seen.contains(&hits[j].detector) {
                seen.push(hits[j].detector);
                hits.swap(keep, j);
                keep += 1;
            }
        }
        hits.truncate(keep);
    }
    hits
}

const WINDOW: usize = 8192;
const OVERLAP: usize = 512;

/// The line itself, or overlapping char-aligned windows when it is long.
fn windows(line: &str) -> Vec<&str> {
    if line.len() <= WINDOW {
        return vec![line];
    }
    let mut out = Vec::new();
    let mut start = 0;
    while start < line.len() {
        let mut end = (start + WINDOW).min(line.len());
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        out.push(&line[start..end]);
        if end == line.len() {
            break;
        }
        let mut next = end - OVERLAP;
        while !line.is_char_boundary(next) {
            next += 1;
        }
        start = next;
    }
    out
}

/// `.env` / `.env.*` by basename bytes, except documented templates.
pub fn is_env_file(path: &[u8]) -> bool {
    let base = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    let base = String::from_utf8_lossy(base).to_ascii_lowercase();
    if base == ".env" {
        return true;
    }
    match base.strip_prefix(".env.") {
        Some(ext) => !matches!(ext, "example" | "sample" | "template"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Found by the Linux full-flow run: `#` inside a quoted password cut the
    /// value to 3 characters, so the push went through unflagged.
    #[test]
    fn quoted_password_with_hash_or_comma_is_flagged() {
        for line in [
            r#"db_password = "Zq8#vT2kPw9xLmR4sQ7""#,
            "api_key: 'Zq8,vT2k;Pw9xLmR4sQ7'",
            r#"{"secret": "Zq8#vT2kPw9xLmR4sQ7"}"#,
        ] {
            let hits = scan_text(line);
            assert_eq!(hits.len(), 1, "{line}");
            assert_eq!(hits[0].detector, "generic-assignment", "{line}");
        }
        // Unquoted: `#` still starts a comment, so only the short head is seen.
        assert!(scan_text("password=Zq8 # trailing comment").is_empty());
        assert!(scan_text(r#"password = "changeme#1234""#).is_empty());
    }

    #[test]
    fn env_names() {
        for p in [".env", "a/b/.env", ".env.local", ".env.production"] {
            assert!(is_env_file(p.as_bytes()), "{p}");
        }
        for p in [
            ".env.example",
            "x/.env.sample",
            ".env.template",
            "env",
            ".envrc",
        ] {
            assert!(!is_env_file(p.as_bytes()), "{p}");
        }
    }

    #[test]
    fn overlong_lines_are_scanned_not_skipped() {
        let aws = ["AKIA", "QX7M2K9P4R8T3V6W"].concat();
        // secret straddling a window boundary and one deep inside a long line
        for pad in [WINDOW - 8, 20_000] {
            let text = format!(
                "{}{aws} {}\nnext\n",
                "a ".repeat(pad / 2),
                "b ".repeat(5000)
            );
            let hits = scan_text(&text);
            assert_eq!(hits.len(), 1, "pad {pad}");
            assert_eq!((hits[0].detector, hits[0].line), ("aws-access-key", 1));
        }
    }

    #[test]
    fn detectors_redact_and_skip_placeholders() {
        let aws = ["AKIA", "QX7M2K9P4R8T3V6W"].concat();
        let pk = ["-----BEGIN ", "RSA PRIVATE KEY-----"].concat();
        let gh = ["ghp", "_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6"].concat();
        let pw = ["pass", "word=", "t9Xq2LmZ8vB4nR7w"].concat();
        let text = format!("a={aws}\n{pk}\n{gh}\n{pw}\npassword=changeme123\nsecret=aaaaaaaaaa\n");
        let hits = scan_text(&text);
        let names: Vec<_> = hits.iter().map(|h| h.detector).collect();
        assert_eq!(
            names,
            [
                "aws-access-key",
                "private-key",
                "github-token",
                "generic-assignment"
            ]
        );
        for h in &hits {
            assert!(!h.evidence.contains("QX7M") && !h.evidence.contains("t9Xq"));
        }
    }
}
