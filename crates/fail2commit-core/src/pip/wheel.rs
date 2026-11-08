//! Defensive wheel inspection. Nothing is extracted to disk or executed.

use super::interp::normalize;
use std::io::Read;
use std::path::Path;

const MAX_ENTRIES: usize = 200_000;
const MAX_METADATA: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelInfo {
    pub name: String,
    pub version: String,
    pub requires_dist: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WheelError {
    /// Malformed or hostile archive.
    Invalid(String),
    /// A dependency is a direct reference (`name @ url`, VCS, path).
    DirectReference(String),
}

/// `(name, version)` from `name-version(-build)?-py-abi-platform.whl`.
pub fn parse_filename(filename: &str) -> Option<(String, String)> {
    let stem = filename.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    if !(parts.len() == 5 || parts.len() == 6) || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let ok = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+!".contains(&b))
    };
    if !parts.iter().all(|p| ok(p)) {
        return None;
    }
    Some((normalize(parts[0]), parts[1].to_ascii_lowercase()))
}

fn same_version(a: &str, b: &str) -> bool {
    let n = |s: &str| s.to_ascii_lowercase().replace('-', "_");
    n(a) == n(b)
}

/// Validate the archive at `path` against its advertised `filename`.
pub fn inspect(
    path: &Path,
    filename: &str,
    max_uncompressed: u64,
) -> Result<WheelInfo, WheelError> {
    let bad = |m: String| WheelError::Invalid(m);
    let (fname, fver) =
        parse_filename(filename).ok_or_else(|| bad(format!("bad wheel filename {filename}")))?;
    let file = std::fs::File::open(path).map_err(|e| bad(format!("open: {e}")))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| bad(format!("not a zip archive: {e}")))?;
    if zip.is_empty() || zip.len() > MAX_ENTRIES {
        return Err(bad(format!("{} entries", zip.len())));
    }
    let mut total: u64 = 0;
    let mut metadata_name: Option<String> = None;
    let mut has_wheel = false;
    let mut has_record = false;
    for i in 0..zip.len() {
        let entry = zip
            .by_index_raw(i)
            .map_err(|e| bad(format!("entry {i}: {e}")))?;
        let name = String::from_utf8_lossy(entry.name_raw()).into_owned();
        check_entry_name(&name).map_err(bad)?;
        if entry.is_symlink() || entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            return Err(bad(format!("symlink entry {name}")));
        }
        total = total.saturating_add(entry.size());
        if total > max_uncompressed {
            return Err(bad("uncompressed size exceeds the limit".into()));
        }
        if let Some((dir, leaf)) = name.split_once('/') {
            if dir.ends_with(".dist-info") {
                match leaf {
                    "METADATA" => {
                        if metadata_name.replace(dir.to_string()).is_some() {
                            return Err(bad("more than one METADATA".into()));
                        }
                    }
                    "WHEEL" => has_wheel = true,
                    "RECORD" => has_record = true,
                    _ => {}
                }
            }
        }
    }
    let dist_info = metadata_name.ok_or_else(|| bad("no .dist-info/METADATA".into()))?;
    if !has_wheel || !has_record {
        return Err(bad("missing WHEEL or RECORD".into()));
    }
    let mut text = String::new();
    zip.by_name(&format!("{dist_info}/METADATA"))
        .map_err(|e| bad(format!("METADATA: {e}")))?
        .take(MAX_METADATA)
        .read_to_string(&mut text)
        .map_err(|_| bad("METADATA is not UTF-8".into()))?;
    let info = parse_metadata(&text)?;
    if normalize(&info.name) != fname || !same_version(&info.version, &fver) {
        return Err(bad(format!(
            "METADATA {} {} does not match filename {filename}",
            info.name, info.version
        )));
    }
    Ok(info)
}

/// A file the wheel installs into `purelib`/`platlib` that CPython's `site`
/// module executes at every interpreter start of that environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupFile {
    /// Entry name inside the wheel.
    pub entry: String,
    pub why: &'static str,
}

/// A wheel entry that would change the interpreter's own layout or the
/// guard's tools (RP-003, RP-004). Never approvable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutViolation {
    pub entry: String,
    pub why: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    pub startup: Vec<StartupFile>,
    pub denied: Vec<LayoutViolation>,
}

/// Where in the environment an entry would land.
enum Dest<'a> {
    /// `purelib`/`platlib` (root entries and `*.data/purelib|platlib`).
    Site(Vec<&'a str>),
    /// `*.data/data`: relative to `sys.prefix`.
    Data(Vec<&'a str>),
    /// `*.data/scripts`: the venv's `Scripts`/`bin` directory.
    Scripts(Vec<&'a str>),
    Other,
}

fn classify(name: &str) -> Dest<'_> {
    let comps: Vec<&str> = name
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let Some(first) = comps.first() else {
        return Dest::Other;
    };
    if first.to_ascii_lowercase().ends_with(".data") {
        if comps.len() < 3 {
            return Dest::Other;
        }
        let rest = comps[2..].to_vec();
        return match comps[1].to_ascii_lowercase().as_str() {
            "purelib" | "platlib" => Dest::Site(rest),
            "data" => Dest::Data(rest),
            "scripts" => Dest::Scripts(rest),
            _ => Dest::Other,
        };
    }
    Dest::Site(comps)
}

/// Does CPython's `site.addpackage` execute a line of this `.pth` file?
/// It decodes UTF-8 (BOM allowed), splits like `str.splitlines` (bare CR and
/// the other separators included) and executes lines starting `import ` or
/// `import\t`. Content that is not UTF-8 is decoded with the locale, which we
/// cannot know, so it is flagged.
pub(crate) fn pth_executes(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return true;
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    text.split(|c| {
        matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        )
    })
    .any(|l| l.starts_with("import ") || l.starts_with("import\t"))
}

fn is_startup_name(leaf: &str) -> bool {
    let lower = leaf.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or("");
    lower.ends_with(".pth") || stem == "sitecustomize" || stem == "usercustomize"
}

/// First `data` component that is part of the interpreter's own layout.
const DATA_RESERVED: [&str; 9] = [
    "pyvenv.cfg",
    "lib",
    "lib64",
    "include",
    "bin",
    "scripts",
    "dlls",
    "libs",
    "tools",
];

/// `pip`, `pip3`, `pip3.12`, `pip-script.py`: the guard's own tool names.
fn is_pip_script(base: &str) -> bool {
    base == "pip"
        || base.starts_with("pip-script")
        || base
            .strip_prefix("pip")
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()))
}

/// Why a `scripts` entry may not be installed, if it may not.
/// `reserved` holds the lower-cased file names of the interpreter executable.
fn bad_script(rest: &[&str], reserved: &[String]) -> Option<String> {
    if rest.len() > 1 {
        return Some("a nested path under the interpreter's scripts directory".into());
    }
    let leaf = rest.first()?.to_ascii_lowercase();
    let base = leaf.split('.').next().unwrap_or("");
    let hit = base.starts_with("python")
        || is_pip_script(base)
        || leaf == "pyvenv.cfg"
        || base.starts_with("activate")
        || base.starts_with("deactivate")
        || reserved.contains(&leaf);
    hit.then(|| format!("{leaf} is an interpreter or pip executable of the environment"))
}

/// Inspect one wheel for entries that run at interpreter start-up (CR-001) and
/// for entries that must never be installed through the guard (RP-003/RP-004).
/// `dist` is the wheel's normalized project name; `reserved` the lower-cased
/// file names of the target interpreter. Nothing is extracted.
pub fn scan(path: &Path, dist: &str, reserved: &[String]) -> Result<Scan, WheelError> {
    let bad = |m: String| WheelError::Invalid(m);
    let file = std::fs::File::open(path).map_err(|e| bad(format!("open: {e}")))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| bad(format!("not a zip archive: {e}")))?;
    let mut out = Scan::default();
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| bad(format!("entry {i}: {e}")))?;
        let name = String::from_utf8_lossy(entry.name_raw()).replace('\\', "/");
        let mut deny: Option<String> = None;
        let mut startup: Option<&'static str> = None;
        match classify(&name) {
            Dest::Site(rel) => {
                let first = rel[0].to_ascii_lowercase();
                let is_pip_dist = first
                    .strip_prefix("pip-")
                    .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
                    && first.ends_with(".dist-info");
                if first == "pip" || is_pip_dist {
                    deny = Some(if dist == "pip" {
                        "upgrading pip through fail2commit is not supported: pip is the guard's own tool and its files are never replaced".into()
                    } else {
                        "the wheel overwrites files of pip, the guard's own tool".into()
                    });
                } else if rel.len() == 1 && first.ends_with(".pth") {
                    let mut head = Vec::new();
                    let _ = (&mut entry).take(MAX_METADATA + 1).read_to_end(&mut head);
                    if head.len() as u64 > MAX_METADATA {
                        startup = Some(".pth too large to inspect; Python may run import lines in it at every start");
                    } else if pth_executes(&head) {
                        startup = Some(".pth import line run by Python at every start");
                    }
                } else if matches!(
                    first.split('.').next(),
                    Some("sitecustomize" | "usercustomize")
                ) {
                    startup = Some("imported by Python at every start");
                }
            }
            Dest::Data(rest) => {
                let first = rest[0].to_ascii_lowercase();
                if DATA_RESERVED.contains(&first.as_str()) || first.starts_with("python") {
                    deny = Some(format!(
                        "the data scheme would write {first} under the interpreter prefix (its layout, site directories or executables)"
                    ));
                } else if is_startup_name(rest[rest.len() - 1]) {
                    deny = Some("a startup hook (.pth, sitecustomize, usercustomize) through the data scheme".into());
                }
            }
            Dest::Scripts(rest) => deny = bad_script(&rest, reserved),
            Dest::Other => {}
        }
        if let Some(why) = deny {
            out.denied.push(LayoutViolation {
                entry: name.clone(),
                why,
            });
        }
        if let Some(why) = startup {
            out.startup.push(StartupFile { entry: name, why });
        }
    }
    Ok(out)
}

fn check_entry_name(name: &str) -> Result<(), String> {
    let p = name.replace('\\', "/");
    if p.starts_with('/')
        || p.split('/').any(|c| c == "..")
        || (p.len() > 1 && p.as_bytes()[1] == b':')
        || p.contains('\0')
    {
        return Err(format!("unsafe entry path {name}"));
    }
    Ok(())
}

/// Headers up to the first blank line; `Requires-Dist` must be registry names.
pub fn parse_metadata(text: &str) -> Result<WheelInfo, WheelError> {
    let (mut name, mut version, mut deps) = (None, None, Vec::new());
    for line in text.lines() {
        if line.trim().is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "name" => name = Some(v.to_string()),
            "version" => version = Some(v.to_string()),
            "requires-dist" => {
                let req = v.split(';').next().unwrap_or("").trim();
                if req.contains('@')
                    || req.contains("://")
                    || req.contains('/')
                    || req.contains('\\')
                {
                    return Err(WheelError::DirectReference(v.to_string()));
                }
                deps.push(v.to_string());
            }
            _ => {}
        }
    }
    match (name, version) {
        (Some(name), Some(version)) => Ok(WheelInfo {
            name,
            version,
            requires_dist: deps,
        }),
        _ => Err(WheelError::Invalid("METADATA lacks Name or Version".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build(entries: &[(&str, &str)]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        let mut z = zip::ZipWriter::new(f.reopen().unwrap());
        let o = zip::write::SimpleFileOptions::default();
        for (n, c) in entries {
            z.start_file(*n, o).unwrap();
            z.write_all(c.as_bytes()).unwrap();
        }
        z.finish().unwrap();
        f
    }

    const MD: &str =
        "Metadata-Version: 2.1\nName: Foo_Bar\nVersion: 1.0\nRequires-Dist: baz (>=1)\n";

    fn ok_entries() -> Vec<(&'static str, &'static str)> {
        vec![
            ("foo_bar-1.0.dist-info/METADATA", MD),
            ("foo_bar-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n"),
            ("foo_bar-1.0.dist-info/RECORD", ""),
            ("foo_bar.py", "x=1\n"),
        ]
    }

    #[test]
    fn accepts_valid_wheel() {
        let f = build(&ok_entries());
        let i = inspect(f.path(), "foo_bar-1.0-py3-none-any.whl", 1 << 20).unwrap();
        assert_eq!((i.name.as_str(), i.requires_dist.len()), ("Foo_Bar", 1));
    }

    #[test]
    fn rejects_hostile_wheels() {
        let mut e = ok_entries();
        e.push(("../evil.py", "x"));
        assert!(matches!(
            inspect(build(&e).path(), "foo_bar-1.0-py3-none-any.whl", 1 << 20),
            Err(WheelError::Invalid(_))
        ));
        // name/version substitution
        assert!(inspect(
            build(&ok_entries()).path(),
            "other-1.0-py3-none-any.whl",
            1 << 20
        )
        .is_err());
        assert!(inspect(
            build(&ok_entries()).path(),
            "foo_bar-2.0-py3-none-any.whl",
            1 << 20
        )
        .is_err());
        // size bound
        assert!(inspect(
            build(&ok_entries()).path(),
            "foo_bar-1.0-py3-none-any.whl",
            4
        )
        .is_err());
        // not a zip
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), b"MZ not a zip").unwrap();
        assert!(inspect(f.path(), "foo_bar-1.0-py3-none-any.whl", 1 << 20).is_err());
        // transitive direct reference
        let md = "Name: foo_bar\nVersion: 1.0\nRequires-Dist: evil @ https://evil.test/e.whl\n";
        let e = vec![
            ("foo_bar-1.0.dist-info/METADATA", md),
            ("foo_bar-1.0.dist-info/WHEEL", "x"),
            ("foo_bar-1.0.dist-info/RECORD", ""),
        ];
        assert!(matches!(
            inspect(build(&e).path(), "foo_bar-1.0-py3-none-any.whl", 1 << 20),
            Err(WheelError::DirectReference(_))
        ));
    }

    fn scan_of(e: &[(&str, &str)]) -> Scan {
        let mut all = ok_entries();
        all.extend_from_slice(e);
        scan(build(&all).path(), "foo-bar", &["python.exe".into()]).unwrap()
    }

    fn startup_names(s: &Scan) -> Vec<&str> {
        s.startup.iter().map(|s| s.entry.as_str()).collect()
    }

    #[test]
    fn startup_files_are_found_where_site_would_run_them() {
        let s = scan_of(&[
            ("x.pth", "import os\n"),
            ("plain.pth", "/some/dir\n# import not a command\n"),
            ("sitecustomize.py", "x=1\n"),
            ("foo_bar-1.0.data/purelib/y.pth", "import sys\n"),
            (
                "foo_bar-1.0.data/platlib/sitecustomize.cpython-312.pyc",
                "x",
            ),
            ("foo_bar-1.0.data/scripts/z.pth", "import sys\n"),
            ("pkg/inner.pth", "import sys\n"),
        ]);
        assert_eq!(
            startup_names(&s),
            [
                "x.pth",
                "sitecustomize.py",
                "foo_bar-1.0.data/purelib/y.pth",
                "foo_bar-1.0.data/platlib/sitecustomize.cpython-312.pyc"
            ]
        );
        assert!(s.denied.is_empty(), "{:?}", s.denied);
        assert_eq!(scan_of(&[]), Scan::default());
    }

    #[test]
    fn pth_lines_are_detected_like_site_addpackage() {
        // RP-001: bare CR, other separators, a BOM, and the tab form.
        for ok in [
            "import os\n",
            "# pad\rimport os\n",
            "/dir\r\nimport\tos",
            "\u{feff}import os\n",
            "/d\u{2028}import os",
            "/d\x0cimport os",
        ] {
            assert!(pth_executes(ok.as_bytes()), "{ok:?}");
        }
        for no in [
            "",
            "/dir\n# import os\n",
            "imports os\n",
            " import os\n",
            "importos\n",
        ] {
            assert!(!pth_executes(no.as_bytes()), "{no:?}");
        }
        assert!(pth_executes(&[0xff, 0xfe, b'i']), "undecodable is flagged");
    }

    #[test]
    fn oversized_pth_is_flagged_not_skipped() {
        let big = format!("{}\nimport os\n", "/x".repeat(MAX_METADATA as usize));
        let s = scan_of(&[("big.pth", big.as_str())]);
        assert_eq!(startup_names(&s), ["big.pth"]);
    }

    #[test]
    fn layout_entries_are_denied() {
        // RP-004: interpreter layout, the guard's tools, startup hooks in data.
        let hostile = [
            "foo_bar-1.0.data/data/pyvenv.cfg",
            "foo_bar-1.0.data/data/Lib/site-packages/a.py",
            "foo_bar-1.0.data/data/lib/python3.12/site-packages/a.py",
            "foo_bar-1.0.data/data/lib64/x",
            "foo_bar-1.0.data/data/include/x.h",
            "foo_bar-1.0.data/data/bin/python",
            "foo_bar-1.0.data/data/Scripts/python.exe",
            "foo_bar-1.0.data/data/share/evil.pth",
            "foo_bar-1.0.data/data/share/sitecustomize.py",
            "foo_bar-1.0.data/scripts/python3.12",
            "foo_bar-1.0.data/scripts/Python.EXE",
            "foo_bar-1.0.data/scripts/pip3.exe",
            "foo_bar-1.0.data/scripts/pip",
            "foo_bar-1.0.data/scripts/pyvenv.cfg",
            "foo_bar-1.0.data/scripts/sub/tool",
            "foo_bar-1.0.data/purelib/pip/__init__.py",
            "foo_bar-1.0.data/platlib/pip-24.0.dist-info/METADATA",
            "pip/__init__.py",
            "pip-25.0.dist-info/RECORD",
        ];
        for h in hostile {
            let s = scan_of(&[(h, "x")]);
            assert_eq!(s.denied.len(), 1, "{h}: {:?}", s.denied);
        }
        // reserved interpreter names come from the caller
        let mut all = ok_entries();
        all.push(("foo_bar-1.0.data/scripts/Custom.exe", "x"));
        let s = scan(build(&all).path(), "foo-bar", &["custom.exe".into()]).unwrap();
        assert_eq!(s.denied.len(), 1);
        // allowed look-alikes
        for ok in [
            "foo_bar-1.0.data/data/share/jupyter/x.json",
            "foo_bar-1.0.data/data/etc/x.conf",
            "foo_bar-1.0.data/scripts/pipx",
            "foo_bar-1.0.data/scripts/black.exe",
            "foo_bar-1.0.data/headers/x.h",
            "pip_tools/__init__.py",
            "pip-tools-1.0.dist-info/RECORD",
            "pipdeptree.py",
        ] {
            let s = scan_of(&[(ok, "x")]);
            assert!(s.denied.is_empty(), "{ok}: {:?}", s.denied);
        }
    }

    #[test]
    fn upgrading_pip_itself_is_denied_with_its_own_reason() {
        let mut all = ok_entries();
        all.push(("pip/__init__.py", "x"));
        let s = scan(build(&all).path(), "pip", &[]).unwrap();
        assert!(s.denied[0].why.contains("upgrading pip"), "{:?}", s.denied);
    }

    #[test]
    fn filenames() {
        assert_eq!(
            parse_filename("Foo_Bar-1.0-1-cp312-cp312-win_amd64.whl"),
            Some(("foo-bar".into(), "1.0".into()))
        );
        assert_eq!(parse_filename("foo-1.0.tar.gz"), None);
        assert_eq!(parse_filename("foo-1.0.whl"), None);
    }
}
