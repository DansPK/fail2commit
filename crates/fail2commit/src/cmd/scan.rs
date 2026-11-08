//! `fail2commit scan` (T-006 · FR-006 · SPEC-006).
//!
//! Advisory and script checks for exact package versions. Package code is never
//! executed here: script inspection reads lifecycle `scripts` entries and the
//! local files they reference as text (see [`fail2commit_core::scan`]).

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::protocol::{Finding, FindingAction, FindingKind};
use fail2commit_core::redact::redact_url_credentials;
use fail2commit_core::scan::{self, Ecosystem, PackageId, ScriptFile};
use fail2commit_core::Error;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Largest `package.json` read for `--dir`.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Most `scripts` entries inspected from one manifest.
const MAX_SCRIPT_ENTRIES: usize = 64;
/// Most referenced local files read for one package.
const MAX_REFERENCED_FILES: usize = 64;
/// Bytes of one referenced local file read.
const MAX_REFERENCED_FILE_BYTES: u64 = 1024 * 1024;
/// Characters of one script command kept for inspection.
const MAX_COMMAND_CHARS: usize = 8192;
/// Longest package name or version accepted from a spec or manifest.
const MAX_FIELD_CHARS: usize = 214;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Use only cached advisory data; never contact the network.
    #[arg(long)]
    pub offline: bool,
    /// Inspect a local package directory (`package.json` scripts) without
    /// running anything.
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Exact packages: `npm:<name>@<version>` or `PyPI:<name>@<version>`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "PACKAGE"
    )]
    pub packages: Vec<OsString>,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let mut settings = ctx.settings.advisories.clone();
    if args.offline {
        settings.offline = true;
    }
    if args.packages.is_empty() && args.dir.is_none() {
        return Err(Error::invalid(
            "scan needs npm:<name>@<version>, PyPI:<name>@<version> or --dir <path>",
        ));
    }

    let mut packages = Vec::new();
    for spec in &args.packages {
        packages.push(parse_package(&spec.to_string_lossy())?);
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut complete = true;
    if !packages.is_empty() {
        let report = scan::check_advisories(&ctx.paths, &settings, &packages);
        findings.extend(report.findings);
        complete &= report.complete;
    }

    let mut targets: Vec<String> = packages.iter().map(PackageId::display).collect();
    let mut scripts_inspected = 0usize;
    if let Some(dir) = &args.dir {
        let local = inspect_dir(dir)?;
        targets.push(local.package.display());
        scripts_inspected = local.scripts.len() + local.files.len();
        findings.extend(scan::inspect_scripts(
            &local.package,
            &local.scripts,
            &local.files,
        ));
    }

    // Deny findings can never be approved away, so they also fail the command.
    let denied = findings
        .iter()
        .filter(|finding| finding.action == FindingAction::Deny)
        .count();
    if denied > 0 {
        return Err(
            Error::rejected(format!("{denied} deny finding(s) block this package"))
                .with_findings(findings),
        );
    }
    if !complete {
        return Err(Error::incomplete(
            "advisory scan did not complete; results are not verified clean",
        )
        .with_findings(findings));
    }

    let advisories = findings
        .iter()
        .filter(|finding| matches!(finding.kind, FindingKind::Advisory | FindingKind::Malware))
        .count();
    let message = if advisories == 0 {
        "no known advisories for the requested versions".to_string()
    } else {
        format!("{advisories} advisory finding(s) need one-time approval")
    };
    let data = serde_json::json!({
        "complete": complete,
        "packages": targets,
        "scriptsInspected": scripts_inspected,
    });
    Ok(Outcome {
        message,
        findings,
        tool_exit: None,
        data,
    })
}

/// Parse `npm:<name>@<version>` / `PyPI:<name>@<version>`.
fn parse_package(spec: &str) -> Result<PackageId, Error> {
    let (ecosystem, rest) = spec
        .split_once(':')
        .ok_or_else(|| Error::invalid("expected <ecosystem>:<name>@<version>"))?;
    let ecosystem = match ecosystem.to_ascii_lowercase().as_str() {
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::PyPI,
        _ => return Err(Error::invalid("supported ecosystems are npm and PyPI")),
    };
    // A scoped npm name starts with `@`, so the version separator is the last
    // `@` that is not the first character.
    let at = rest
        .rfind('@')
        .filter(|&index| index > 0)
        .ok_or_else(|| Error::invalid("expected <name>@<version>"))?;
    let (name, version) = (&rest[..at], &rest[at + 1..]);
    validate_field(name)?;
    validate_field(version)?;
    Ok(PackageId {
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
    })
}

/// Names and versions reach the OSV request body and the cache key, so bound
/// and restrict them to what a package manager can actually publish.
fn validate_field(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.chars().count() > MAX_FIELD_CHARS {
        return Err(Error::invalid(
            "package name or version is empty or too long",
        ));
    }
    if !value.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '@' | '/' | '.' | '-' | '_' | '+' | '~' | ':')
    }) {
        return Err(Error::invalid(format!(
            "unsupported character in package name or version: {}",
            redact_url_credentials(value)
        )));
    }
    Ok(())
}

/// A package directory read for `--dir`, with the scripts it references.
struct LocalPackage {
    package: PackageId,
    scripts: Vec<(String, String)>,
    files: Vec<ScriptFile>,
}

/// Untrusted metadata: strip control characters and cap the length.
fn bound(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FIELD_CHARS)
        .collect()
}

fn inspect_dir(dir: &Path) -> Result<LocalPackage, Error> {
    let manifest_path = dir.join("package.json");
    let bytes = fail2commit_core::fsutil::read_bounded(&manifest_path, MAX_MANIFEST_BYTES)
        .map_err(|_| Error::invalid("cannot read package.json in the given directory"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| Error::invalid("package.json is not valid JSON"))?;

    let package = PackageId {
        ecosystem: Ecosystem::Npm,
        name: bound(
            manifest
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("local-package"),
        ),
        version: bound(
            manifest
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0"),
        ),
    };

    let mut scripts: Vec<(String, String)> = Vec::new();
    if let Some(entries) = manifest.get("scripts").and_then(|v| v.as_object()) {
        for (name, value) in entries.iter().take(MAX_SCRIPT_ENTRIES) {
            if let Some(command) = value.as_str() {
                let command: String = command.chars().take(MAX_COMMAND_CHARS).collect();
                scripts.push((bound(name), command));
            }
        }
    }

    let root = dir
        .canonicalize()
        .map_err(|_| Error::invalid("cannot resolve the given directory"))?;
    let mut files: Vec<ScriptFile> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    'commands: for (_, command) in &scripts {
        for candidate in referenced_paths(command) {
            if files.len() == MAX_REFERENCED_FILES {
                break 'commands;
            }
            let Ok(relative) = safe_relative(&candidate) else {
                continue;
            };
            let Ok(canonical) = root.join(&relative).canonicalize() else {
                continue;
            };
            // A symlink must not walk out of the package directory.
            if !canonical.starts_with(&root) || !canonical.is_file() {
                continue;
            }
            if !seen.insert(canonical.clone()) {
                continue;
            }
            let Ok(bytes) =
                fail2commit_core::fsutil::read_bounded(&canonical, MAX_REFERENCED_FILE_BYTES)
            else {
                continue;
            };
            files.push(ScriptFile {
                path: relative.to_string_lossy().replace('\\', "/"),
                bytes,
            });
        }
    }

    Ok(LocalPackage {
        package,
        scripts,
        files,
    })
}

/// A relative path inside the package directory, or why it is not one.
fn safe_relative(candidate: &str) -> Result<PathBuf, ()> {
    let cleaned = candidate.trim_matches(|c: char| matches!(c, '"' | '\'' | '`'));
    if cleaned.is_empty() || cleaned.contains("://") {
        return Err(());
    }
    let path = Path::new(cleaned);
    if path.is_absolute() {
        return Err(());
    }
    // `./scripts/x.js` is an ordinary relative reference, so a leading `.` is
    // dropped. `..`, a root and a drive prefix would leave the package
    // directory and are rejected before any filesystem access.
    let relative: PathBuf = path
        .components()
        .map(|component| match component {
            Component::CurDir => Ok(None),
            Component::Normal(part) => Ok(Some(part)),
            _ => Err(()),
        })
        .collect::<Result<Vec<_>, ()>>()?
        .into_iter()
        .flatten()
        .collect();
    if relative.as_os_str().is_empty() {
        return Err(());
    }
    Ok(relative)
}

/// Paths a script command appears to reference locally, e.g. `node ./a.js`.
fn referenced_paths(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in command.split_whitespace() {
        let token = token.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | ';' | '(' | ')'));
        let lower = token.to_ascii_lowercase();
        let looks_local = [
            ".js", ".cjs", ".mjs", ".ts", ".sh", ".bash", ".zsh", ".py", ".ps1", ".cmd", ".bat",
        ]
        .iter()
        .any(|extension| lower.ends_with(extension));
        if looks_local && !token.starts_with('-') && !out.iter().any(|seen| seen == token) {
            out.push(token.to_string());
        }
    }
    out
}
