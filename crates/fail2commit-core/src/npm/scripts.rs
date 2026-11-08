//! What an install-time command can run out of the package (SPEC-004/006,
//! CR-004): shell-word tokenizing, path normalization, and `npm run` chains.
//! Everything here is evidence gathering on untrusted text; any command shape
//! it cannot resolve fails closed with a `Deny` finding.

use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};

/// How many `npm run` hops are followed before the chain is a denial.
const MAX_DEPTH: usize = 8;
/// Most chained scripts followed for one package.
const MAX_CHAINED: usize = 64;
/// Nesting depth of quoted command text (`sh -c "sh -c '...'"`).
const MAX_NEST: usize = 4;

fn deny(kind: FindingKind, e: Error, why: String) -> Error {
    e.with_findings(vec![Finding::new(
        kind,
        FindingAction::Deny,
        "npm.scripts",
        why,
    )])
}

fn unsupported(why: String) -> Error {
    deny(
        FindingKind::UnsupportedInput,
        Error::invalid(why.clone()),
        why,
    )
}

fn incomplete(why: String) -> Error {
    deny(
        FindingKind::IncompleteScan,
        Error::incomplete(why.clone()),
        why,
    )
}

/// True for names Windows can also reach by an 8.3 alias (`BUILDH~1.JS`).
pub fn is_short_name(component: &str) -> bool {
    // Win32 drops trailing dots and spaces, so `BUILDH~1.JS.` is the alias too.
    let component = component.trim_end_matches(['.', ' ']);
    let stem = component.rsplit_once('.').map_or(component, |(s, _)| s);
    stem.rsplit_once('~')
        .is_some_and(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

const OPS: &str = ";&|<>()`\n";

/// Split `cmd` into command segments of shell words. `escapes` selects POSIX
/// backslash escapes; without it a backslash is a path separator (cmd.exe).
fn tokenize(cmd: &str, escapes: bool) -> Vec<Vec<String>> {
    let mut segments: Vec<Vec<String>> = Vec::new();
    let mut seg: Vec<String> = Vec::new();
    let mut cur: Option<String> = None;
    let mut chars = cmd.chars().peekable();
    macro_rules! end_word {
        () => {
            if let Some(w) = cur.take() {
                seg.push(w);
            }
        };
    }
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' => end_word!(),
            c if OPS.contains(c) => {
                end_word!();
                if !seg.is_empty() {
                    segments.push(std::mem::take(&mut seg));
                }
                // `$(pwd)/run`: the substituted prefix is unknowable.
                if (c == ')' || c == '`') && chars.peek() == Some(&'/') {
                    cur = Some("$SUBST".into());
                }
            }
            '#' if cur.is_none() => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
            }
            '\'' => {
                let w = cur.get_or_insert_with(String::new);
                for n in chars.by_ref() {
                    if n == '\'' {
                        break;
                    }
                    w.push(n);
                }
            }
            '"' => {
                let w = cur.get_or_insert_with(String::new);
                while let Some(n) = chars.next() {
                    match n {
                        '"' => break,
                        '\\' if escapes => match chars.next() {
                            Some(e @ ('"' | '\\' | '$' | '`')) => w.push(e),
                            Some('\n') | None => {}
                            Some(e) => {
                                w.push('\\');
                                w.push(e);
                            }
                        },
                        '\\' => w.push('/'),
                        n => w.push(n),
                    }
                }
            }
            '\\' if escapes => match chars.next() {
                Some('\n') | None => {}
                Some(e) => cur.get_or_insert_with(String::new).push(e),
            },
            '\\' => cur.get_or_insert_with(String::new).push('/'),
            c => cur.get_or_insert_with(String::new).push(c),
        }
    }
    end_word!();
    if !seg.is_empty() {
        segments.push(seg);
    }
    segments
}

/// Segments of `cmd` plus those of any quoted word that is itself command
/// text (`sh -c "..."`, `node -e "..."`).
fn all_segments(cmd: &str, escapes: bool, depth: usize) -> Vec<Vec<String>> {
    let mut out = tokenize(cmd, escapes);
    if depth < MAX_NEST {
        let nested: Vec<String> = out
            .iter()
            .flatten()
            .filter(|w| w.contains(|c: char| c.is_whitespace() || OPS.contains(c)))
            .cloned()
            .collect();
        for w in nested {
            out.extend(all_segments(&w, escapes, depth + 1));
        }
    }
    out
}

/// Package-relative form of one word, or `None` if it names nothing inside
/// the package. `""` is the package root.
fn to_rel(word: &str) -> Result<Option<String>> {
    let lower = word.to_ascii_lowercase();
    let mut w = word.to_string();
    for var in ["${pwd}", "$pwd", "${init_cwd}", "$init_cwd", "%cd%"] {
        if lower.starts_with(var) && matches!(word.as_bytes().get(var.len()), None | Some(b'/')) {
            w = format!(".{}", &word[var.len()..]);
            break;
        }
    }
    let path_like = w.contains('/') || w == "..";
    if w.contains('$') && path_like {
        return Err(incomplete(format!(
            "lifecycle command path `{word}` uses a variable or substitution that cannot be resolved"
        )));
    }
    if w.starts_with('/') || w.starts_with('~') || w.as_bytes().get(1) == Some(&b':') {
        return Ok(None);
    }
    let mut parts: Vec<&str> = Vec::new();
    for c in w.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() && path_like {
                    return Err(unsupported(format!(
                        "lifecycle command path `{word}` escapes the package root"
                    )));
                }
            }
            c => parts.push(c),
        }
    }
    // `file:stream` addresses the file on NTFS; `file` is the candidate.
    let joined = parts
        .iter()
        .map(|c| c.split(':').next().unwrap_or(c))
        .collect::<Vec<_>>()
        .join("/");
    Ok(Some(joined))
}

/// Every package-relative path (or glob) a command could execute or read.
pub fn paths(cmd: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for escapes in [true, false] {
        for word in all_segments(cmd, escapes, 0).iter().flatten() {
            let mut parts = vec![word.as_str()];
            if let Some((_, v)) = word.split_once('=') {
                parts.push(v);
            }
            for part in parts {
                if !part.starts_with('-') && part.split('/').any(is_short_name) {
                    return Err(unsupported(format!(
                        "lifecycle command names `{part}`, an 8.3 short-name alias that cannot be reviewed"
                    )));
                }
                if let Some(p) = to_rel(part)? {
                    out.insert(p);
                }
            }
        }
    }
    Ok(out)
}

/// The command word (no path separator) of every segment of `cmd`, after
/// leading `VAR=value` words. Looked up on PATH, so `.bin` dirs can answer.
pub fn first_words(cmd: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for escapes in [true, false] {
        for seg in all_segments(cmd, escapes, 0) {
            if let Some(w) = seg.iter().find(|w| !w.contains('=')) {
                if !w.contains(['/', '$', '*', '?']) {
                    out.insert(w.clone());
                }
            }
        }
    }
    out
}

/// `*` and `?` glob over one path, neither crossing `/`.
pub fn glob_match(pat: &[u8], name: &[u8]) -> bool {
    match (pat.first(), name.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            glob_match(&pat[1..], name)
                || name
                    .first()
                    .is_some_and(|&c| c != b'/' && glob_match(pat, &name[1..]))
        }
        (Some(b'?'), Some(&c)) if c != b'/' => glob_match(&pat[1..], &name[1..]),
        (Some(p), Some(n)) if p == n => glob_match(&pat[1..], &name[1..]),
        _ => false,
    }
}

fn tool(word: &str) -> Option<&'static str> {
    let lower = word.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or("");
    let base = base
        .strip_suffix(".cmd")
        .or_else(|| base.strip_suffix(".exe"))
        .or_else(|| base.strip_suffix(".ps1"))
        .unwrap_or(base);
    ["npm", "yarn", "pnpm"].into_iter().find(|t| *t == base)
}

/// Script names a segment's `npm|yarn|pnpm` invocations would run.
fn run_targets(words: &[String]) -> Result<Vec<String>> {
    const BLIND: [&str; 11] = [
        "-w",
        "--workspace",
        "--workspaces",
        "-ws",
        "--prefix",
        "-C",
        "--dir",
        "--cwd",
        "--filter",
        "-F",
        "-r",
    ];
    let mut names = Vec::new();
    for (i, w) in words.iter().enumerate() {
        let Some(t) = tool(w) else { continue };
        let mut rest = words[i + 1..].iter();
        let next_plain = |rest: &mut std::slice::Iter<'_, String>| {
            for a in rest.by_ref() {
                if a == "--" {
                    continue;
                }
                let flag = a.split('=').next().unwrap_or(a);
                if a.starts_with('-') {
                    if BLIND.contains(&flag) || flag == "--recursive" {
                        return Err(incomplete(format!(
                            "`{t} {a}` runs scripts outside this package's scripts map and cannot be followed"
                        )));
                    }
                    continue;
                }
                return Ok(Some(a.clone()));
            }
            Ok(None)
        };
        let Some(sub) = next_plain(&mut rest)? else {
            continue;
        };
        let wanted: Vec<String> = match (t, sub.as_str()) {
            (_, "run" | "run-script") | ("npm", "rum" | "urn") => {
                next_plain(&mut rest)?.into_iter().collect()
            }
            ("npm", "test" | "t" | "tst") => vec!["test".into()],
            ("npm", "start" | "stop") => vec![sub.clone()],
            ("npm", "restart") => vec!["stop".into(), "restart".into(), "start".into()],
            ("npm", _) => vec![],
            _ => vec![sub.clone()],
        };
        for n in wanted {
            if n.contains(['$', '*', '`', '%']) {
                return Err(incomplete(format!(
                    "`{t}` runs script `{n}`, a name that cannot be resolved"
                )));
            }
            names.push(n);
        }
    }
    Ok(names)
}

/// Scripts in `map` reachable from `roots` through `npm run`, `yarn` and
/// `pnpm` (including their `pre`/`post` hooks). Cycles are cut; too deep or
/// too wide a chain, or a run that cannot be followed, is an `IncompleteScan`.
pub fn follow(
    roots: &[(String, String)],
    map: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>> {
    let mut seen: BTreeSet<String> = roots.iter().map(|(n, _)| n.clone()).collect();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut work: Vec<(String, usize)> = roots.iter().map(|(_, c)| (c.clone(), 0)).collect();
    while let Some((cmd, depth)) = work.pop() {
        let mut names = Vec::new();
        for words in all_segments(&cmd, true, 0) {
            names.extend(run_targets(&words)?);
        }
        for name in names {
            for n in [format!("pre{name}"), name.clone(), format!("post{name}")] {
                let Some(body) = map.get(&n) else { continue };
                if !seen.insert(n.clone()) {
                    continue;
                }
                if depth + 1 > MAX_DEPTH || out.len() >= MAX_CHAINED {
                    return Err(incomplete(format!(
                        "`npm run` chain reaches script `{n}` past the depth or size limit"
                    )));
                }
                out.push((n, body.clone()));
                work.push((body.clone(), depth + 1));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(cmd: &str) -> Vec<String> {
        paths(cmd).unwrap().into_iter().collect()
    }

    #[test]
    fn quoting_and_normalization() {
        assert!(p("sh \"./my script\"").contains(&"my script".to_string()));
        assert!(p("sh .//run").contains(&"run".to_string()));
        assert!(p("sh ./a/../run").contains(&"run".to_string()));
        assert!(p("sh $PWD/run").contains(&"run".to_string()));
        assert!(p("sh \"${INIT_CWD}/run\"").contains(&"run".to_string()));
        assert!(p("sh %cd%\\run").contains(&"run".to_string()));
        assert!(p("sh .\\sub\\run").contains(&"sub/run".to_string()));
        assert!(p("sh r\\un").contains(&"run".to_string()));
        assert!(p("sh -c \"node ./x && echo 'sh ./y'\"").contains(&"y".to_string()));
        assert!(p("FOO=./z node q").contains(&"z".to_string()));
        assert!(p("node .").contains(&String::new()));
    }

    #[test]
    fn unresolvable_or_escaping_paths_fail_closed() {
        for bad in ["sh ../x", "sh ./a/../../x", "sh $PWD/../x", "cd .."] {
            let e = paths(bad).unwrap_err();
            assert_eq!(e.findings[0].kind, FindingKind::UnsupportedInput, "{bad}");
            assert_eq!(e.findings[0].action, FindingAction::Deny);
        }
        for bad in ["sh $HOME/x", "sh $(pwd)/x", "sh `pwd`/x"] {
            let e = paths(bad).unwrap_err();
            assert_eq!(e.findings[0].kind, FindingKind::IncompleteScan, "{bad}");
        }
        let e = paths("sh ./BUILDH~1.JS").unwrap_err();
        assert_eq!(e.findings[0].kind, FindingKind::UnsupportedInput);
        assert!(paths("echo hi > /dev/null; sh /usr/bin/x").is_ok());
    }

    #[test]
    fn short_names() {
        assert!(is_short_name("BUILD~1.JS") && is_short_name("PROGRA~12"));
        assert!(!is_short_name("a~b.js") && !is_short_name("x~.js") && !is_short_name("plain.js"));
    }

    #[test]
    fn globs() {
        assert!(glob_match(b"r*n", b"run") && glob_match(b"r?n", b"run"));
        assert!(!glob_match(b"r*", b"a/run") && !glob_match(b"*", b"a/b"));
    }

    fn map(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn root(cmd: &str) -> Vec<(String, String)> {
        vec![("postinstall".into(), cmd.into())]
    }

    #[test]
    fn run_chains_are_followed_with_hooks_and_cycles() {
        let m = map(&[
            ("postinstall", "npm run build"),
            ("prebuild", "echo pre"),
            ("build", "yarn run mid && pnpm cleanup"),
            ("mid", "npm run-script build"),
            ("cleanup", "echo c"),
            ("other", "echo not reached"),
        ]);
        let names: Vec<String> = follow(&root("npm run build"), &m)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        for n in ["prebuild", "build", "mid", "cleanup"] {
            assert!(names.contains(&n.to_string()), "{names:?}");
        }
        assert!(!names.contains(&"other".to_string()));
        assert!(!names.contains(&"postinstall".to_string()));
        let m = map(&[("test", "echo")]);
        assert_eq!(follow(&root("npm test --silent"), &m).unwrap().len(), 1);
        assert_eq!(follow(&root("sh -c \"npm t\""), &m).unwrap().len(), 1);
    }

    #[test]
    fn unfollowable_chains_are_incomplete() {
        let m = map(&[("a", "echo")]);
        for bad in [
            "npm run -w pkg a",
            "npm run $X",
            "pnpm -r run a",
            "npm run a*",
        ] {
            let e = follow(&root(bad), &m).unwrap_err();
            assert_eq!(e.findings[0].kind, FindingKind::IncompleteScan, "{bad}");
        }
        // Deeper than MAX_DEPTH.
        let mut items: Vec<(String, String)> = (0..12)
            .map(|i| (format!("s{i}"), format!("npm run s{}", i + 1)))
            .collect();
        items.push(("s12".into(), "echo".into()));
        let m: BTreeMap<_, _> = items.into_iter().collect();
        let e = follow(&root("npm run s0"), &m).unwrap_err();
        assert_eq!(e.findings[0].kind, FindingKind::IncompleteScan);
    }
}
