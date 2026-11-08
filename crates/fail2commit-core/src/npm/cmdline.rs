//! Argument classification (SPEC-004). Deny by default: an argument or
//! command the guard does not understand is never handed to npm.

use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::{Error, Result};
use std::ffi::OsString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Ci,
    Install,
}

/// A validated, project-scoped install request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub verb: Verb,
    /// Registry package specs (`name`, `name@range`, `@scope/name@tag`).
    pub specs: Vec<String>,
    /// `--save-dev`, `--save-optional`, `--save-prod` or `--no-save`.
    pub save_flag: Option<&'static str>,
    pub save_exact: bool,
    /// The user asked for no lifecycle scripts at all.
    pub ignore_scripts: bool,
    pub project: std::path::PathBuf,
}

#[derive(Debug)]
pub enum Action {
    Guarded(Request),
    /// Commands that cannot install packages; run by the real npm.
    Passthrough(Vec<OsString>),
}

const INSTALL: &[&str] = &[
    "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
    "add",
];
const CI: &[&str] = &[
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
];

/// Commands that never install, link or fetch-and-run packages.
const PASSTHROUGH: &[&str] = &[
    "run",
    "run-script",
    "rum",
    "urn",
    "test",
    "t",
    "tst",
    "start",
    "stop",
    "restart",
    "ls",
    "list",
    "ll",
    "la",
    "view",
    "v",
    "info",
    "show",
    "search",
    "s",
    "se",
    "find",
    "help",
    "config",
    "c",
    "get",
    "set",
    "outdated",
    "explain",
    "why",
    "pkg",
    "prefix",
    "root",
    "bin",
    "whoami",
    "ping",
    "doctor",
];

fn unsupported(msg: String, target: &str) -> Error {
    Error::invalid(msg.clone()).with_findings(vec![Finding::new(
        FindingKind::UnsupportedInput,
        FindingAction::Deny,
        "npm.args",
        crate::redact::redact_url_credentials(&msg),
    )
    .target(crate::redact::redact_url_credentials(target))])
}

/// A registry package spec. Git, URL, file, link, alias, workspace and
/// tarball specs are all rejected (npm-package-arg would treat them as
/// non-registry sources).
pub fn validate_spec(spec: &str) -> Result<()> {
    let name_ok = |n: &str| {
        !n.is_empty()
            && n.len() <= 214
            && n.bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'~')
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
    };
    let (name, range) = match spec[1.min(spec.len())..].find('@') {
        Some(i) => (&spec[..i + 1], Some(&spec[i + 2..])),
        None => (spec, None),
    };
    let name_valid = match name.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(s, n)| name_ok(s) && name_ok(n)),
        None => name_ok(name),
    };
    let lower = name.to_ascii_lowercase();
    let filename = [".tgz", ".tar.gz", ".tar"]
        .iter()
        .any(|e| lower.ends_with(e));
    let range_ok = range.is_none_or(|r| {
        !r.is_empty()
            && r.len() <= 256
            && r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" .^~<>=|*+_-".contains(&b))
    });
    if name_valid && !filename && range_ok {
        Ok(())
    } else {
        Err(unsupported(
            "only plain registry package specs are supported (no git, URL, file, link, alias or tarball sources)".into(),
            spec,
        ))
    }
}

/// Dependency values in package.json / overrides must also be registry
/// ranges, never a source.
pub fn validate_dep_range(name: &str, range: &str) -> Result<()> {
    let bad = range.is_empty()
        || range.contains([':', '/', '\\', '@'])
        || range.to_ascii_lowercase().ends_with(".tgz")
        || range.starts_with('.');
    if bad {
        Err(unsupported(
            format!("dependency `{name}` uses a non-registry source"),
            name,
        ))
    } else {
        Ok(())
    }
}

pub fn parse(args: &[OsString], cwd: &std::path::Path) -> Result<Action> {
    let strs: Vec<&str> = args
        .iter()
        .map(|a| {
            a.to_str()
                .ok_or_else(|| Error::invalid("npm arguments must be valid UTF-8"))
        })
        .collect::<Result<_>>()?;
    let Some(first) = strs.first().copied() else {
        return Err(Error::invalid("missing npm command"));
    };
    if matches!(first, "--version" | "-v" | "--help" | "-h") && strs.len() == 1 {
        return Ok(Action::Passthrough(args.to_vec()));
    }
    let verb = if INSTALL.contains(&first) {
        Verb::Install
    } else if CI.contains(&first) {
        Verb::Ci
    } else if PASSTHROUGH.contains(&first) {
        return Ok(Action::Passthrough(args.to_vec()));
    } else {
        return Err(unsupported(
            format!("npm command `{first}` is not supported by the guard and was not run"),
            first,
        ));
    };

    let mut specs = Vec::new();
    let mut save_flag = None;
    let mut save_exact = false;
    let mut ignore_scripts = false;
    for a in &strs[1..] {
        match *a {
            "-D" | "--save-dev" => save_flag = Some("--save-dev"),
            "-O" | "--save-optional" => save_flag = Some("--save-optional"),
            "-P" | "--save-prod" => save_flag = Some("--save-prod"),
            "--no-save" => save_flag = Some("--no-save"),
            "-E" | "--save-exact" => save_exact = true,
            "--ignore-scripts" => ignore_scripts = true,
            "--save" | "--no-audit" | "--no-fund" => {}
            f if f.starts_with('-') => {
                return Err(unsupported(
                    format!(
                        "npm option `{}` is not supported by the guard",
                        f.split('=').next().unwrap_or(f)
                    ),
                    first,
                ))
            }
            spec => {
                validate_spec(spec)?;
                specs.push(spec.to_string());
            }
        }
    }
    if verb == Verb::Ci && (!specs.is_empty() || save_flag.is_some() || save_exact) {
        return Err(Error::invalid(
            "`npm ci` installs exactly the lockfile and takes no packages or save options",
        ));
    }
    if specs.is_empty() && (save_flag.is_some_and(|f| f != "--no-save") || save_exact) {
        return Err(Error::invalid("save options need at least one package"));
    }
    Ok(Action::Guarded(Request {
        verb,
        specs,
        save_flag,
        save_exact,
        ignore_scripts,
        project: find_project(cwd)?,
    }))
}

/// Nearest ancestor of `cwd` that holds a package.json.
pub fn find_project(cwd: &std::path::Path) -> Result<std::path::PathBuf> {
    let mut dir = Some(cwd);
    while let Some(d) = dir {
        if d.join("package.json").is_file() {
            return d.canonicalize().map_err(Into::into);
        }
        dir = d.parent();
    }
    Err(Error::invalid(
        "no package.json found; run inside an npm project",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn specs() {
        for ok in [
            "left-pad",
            "left-pad@1.3.0",
            "@scope/pkg@^1.2 || 2",
            "a@latest",
        ] {
            validate_spec(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "git+https://x/y.git",
            "github:u/r",
            "u/r",
            "file:../x",
            "link:../x",
            "../x",
            "./x.tgz",
            "x.tgz",
            "https://x/y.tgz",
            "npm:other@1",
            "a@git+ssh://x",
            "a@file:../x",
            "a@u/r",
            "-rf",
            "@scope",
            "",
        ] {
            assert!(validate_spec(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dep_ranges() {
        for ok in ["^1.2.3", "~1", ">=1 <2", "1.x || 2", "latest", "*", ""] {
            if ok.is_empty() {
                assert!(validate_dep_range("a", ok).is_err());
            } else {
                validate_dep_range("a", ok).unwrap();
            }
        }
        for bad in [
            "git+ssh://x",
            "github:u/r",
            "u/r",
            "file:../x",
            "link:x",
            "http://x/y.tgz",
            "npm:b@1",
            "workspace:*",
            "./x",
        ] {
            assert!(validate_dep_range("a", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn classification() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("package.json"), "{}").unwrap();
        let cwd = d.path();
        assert!(matches!(
            parse(&os(&["ci"]), cwd).unwrap(),
            Action::Guarded(Request { verb: Verb::Ci, .. })
        ));
        for v in ["i", "install", "isntall", "add"] {
            assert!(matches!(
                parse(&os(&[v, "left-pad", "-D"]), cwd).unwrap(),
                Action::Guarded(Request {
                    verb: Verb::Install,
                    save_flag: Some("--save-dev"),
                    ..
                })
            ));
        }
        assert!(matches!(
            parse(&os(&["run", "build"]), cwd).unwrap(),
            Action::Passthrough(_)
        ));
        assert!(matches!(
            parse(&os(&["--version"]), cwd).unwrap(),
            Action::Passthrough(_)
        ));
        for bad in [
            &["install", "git+https://x/y.git"][..],
            &["install", "--registry=https://evil.example/"],
            &["install", "--prefix", "/tmp"],
            &["install", "-g", "x"],
            &["update"],
            &["exec", "x"],
            &["rebuild"],
            &["link"],
            &["audit", "fix"],
            &["--prefix", "x", "install"],
            &["ci", "left-pad"],
            &[],
        ] {
            assert!(parse(&os(bad), cwd).is_err(), "{bad:?}");
        }
    }
}
