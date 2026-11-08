//! TC-006 script inspection. Text fixtures only: fail2commit reads lifecycle
//! entries and referenced files, it never runs them.

#[allow(dead_code)]
mod scan_support;

use fail2commit_core::protocol::{FindingAction, FindingKind};
use fail2commit_core::scan::{self, Ecosystem, PackageId, ScriptFile};

fn pkg() -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: "demo".to_string(),
        version: "1.0.0".to_string(),
    }
}

fn script(name: &str, command: &str) -> Vec<(String, String)> {
    vec![(name.to_string(), command.to_string())]
}

#[test]
fn every_force_form_is_denied() {
    let cases = [
        ("postinstall", "git push --force origin main"),
        ("prepare", "git push --force-with-lease origin main"),
        ("publish", "git push -f origin main"),
        ("mirror", "git push --mirror origin"),
        ("cleanup", "git push --delete origin old"),
        ("rewrite", "git push origin +main"),
        ("drop", "git push origin :stale-branch"),
    ];
    for (name, command) in cases {
        let findings = scan::inspect_scripts(&pkg(), &script(name, command), &[]);
        assert_eq!(findings.len(), 1, "{command}");
        assert_eq!(findings[0].kind, FindingKind::SuspiciousScript);
        assert_eq!(findings[0].action, FindingAction::Deny);
        assert!(
            findings[0]
                .location
                .as_deref()
                .is_some_and(|location| location == format!("{name}:1")),
            "{command} -> {:?}",
            findings[0].location
        );
        assert_eq!(findings[0].target.as_deref(), Some("npm:demo@1.0.0"));
        assert_eq!(findings[0].source, "scan.scripts");
    }
}

#[test]
fn wrapped_aliases_are_denied() {
    let cases = [
        ("postinstall", "sh -c \"git push --force origin main\""),
        ("postinstall", "bash -lc 'git push -f origin main'"),
        ("postinstall", "npx --no-install git push --force"),
        (
            "postinstall",
            "node -e \"require('child_process').exec('git push -f origin main')\"",
        ),
    ];
    for (name, command) in cases {
        let findings = scan::inspect_scripts(&pkg(), &script(name, command), &[]);
        assert_eq!(findings.len(), 1, "{command}");
        assert_eq!(findings[0].action, FindingAction::Deny);
    }
}

#[test]
fn benign_hooks_are_not_flagged() {
    let scripts = vec![
        ("test".to_string(), "jest --ci".to_string()),
        (
            "postinstall".to_string(),
            "node ./scripts/install.js".to_string(),
        ),
        ("docs".to_string(), "git push origin main".to_string()),
        (
            "status".to_string(),
            "git status && git diff --stat".to_string(),
        ),
        ("fetch".to_string(), "git fetch --force origin".to_string()),
    ];
    let files = vec![ScriptFile {
        path: "scripts/install.js".to_string(),
        bytes: b"console.log('git push origin main is fine');\n".to_vec(),
    }];
    assert!(scan::inspect_scripts(&pkg(), &scripts, &files).is_empty());
}

#[test]
fn credentials_in_evidence_are_redacted() {
    let url = [
        "https://deploy",
        "-bot:synthetic",
        "-placeholder@example.test/r.git",
    ]
    .concat();
    let findings = scan::inspect_scripts(
        &pkg(),
        &script("postinstall", &format!("git push --force {url} main")),
        &[],
    );
    assert_eq!(findings.len(), 1);
    let evidence = &findings[0].evidence;
    assert!(!evidence.contains("placeholder"), "{evidence}");
    assert!(!evidence.contains("synthetic"), "{evidence}");
    assert!(evidence.contains("***@example.test"), "{evidence}");
}

#[test]
fn referenced_files_report_paths_and_lines() {
    let files = vec![
        ScriptFile {
            path: "scripts/release.sh".to_string(),
            bytes: b"#!/bin/sh\nset -eu\ngit push --force origin main\n".to_vec(),
        },
        ScriptFile {
            path: "scripts/other.sh".to_string(),
            bytes: b"git push origin feature\n".to_vec(),
        },
    ];
    let findings = scan::inspect_scripts(&pkg(), &[], &files);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].location.as_deref(),
        Some("scripts/release.sh:3")
    );
    assert_eq!(findings[0].action, FindingAction::Deny);
}

#[test]
fn suspicious_fixture_package_is_denied() {
    let manifest = scan_support::fixture("pkg-suspicious/package.json");
    let script_file = scan_support::fixture("pkg-suspicious/scripts/postinstall.js");
    let parsed: serde_json::Value = serde_json::from_str(&manifest).expect("fixture json");
    let scripts: Vec<(String, String)> = parsed["scripts"]
        .as_object()
        .expect("scripts object")
        .iter()
        .map(|(name, value)| (name.clone(), value.as_str().unwrap_or_default().to_string()))
        .collect();
    let files = vec![ScriptFile {
        path: "scripts/postinstall.js".to_string(),
        bytes: script_file.into_bytes(),
    }];
    let findings = scan::inspect_scripts(&pkg(), &scripts, &files);
    assert!(
        findings.len() >= 3,
        "prepare, deploy and postinstall are all flagged: {findings:?}"
    );
    assert!(findings
        .iter()
        .all(|f| f.action == FindingAction::Deny && f.kind == FindingKind::SuspiciousScript));
    let locations: Vec<&str> = findings
        .iter()
        .filter_map(|f| f.location.as_deref())
        .collect();
    assert!(locations.contains(&"prepare:1"), "{locations:?}");
    assert!(locations.contains(&"deploy:1"), "{locations:?}");
    assert!(
        locations.contains(&"scripts/postinstall.js:5"),
        "{locations:?}"
    );
}

#[test]
fn binary_files_are_an_incomplete_scan_deny() {
    let files = vec![ScriptFile {
        path: "blob.bin".to_string(),
        bytes: b"git push --force\0\x01\x02tail".to_vec(),
    }];
    let findings = scan::inspect_scripts(&pkg(), &[], &files);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, FindingKind::IncompleteScan);
    assert_eq!(findings[0].action, FindingAction::Deny);
    assert!(findings[0].evidence.contains("blob.bin"));
}

#[test]
fn oversized_files_are_truncated_not_crashing() {
    let mut bytes = vec![b'\n'; 1024 * 1024 + 4096];
    let head = b"git push -f origin main\n";
    bytes[..head.len()].copy_from_slice(head);
    let findings = scan::inspect_scripts(
        &pkg(),
        &[],
        &[ScriptFile {
            path: "huge.sh".to_string(),
            bytes,
        }],
    );
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].location.as_deref(), Some("huge.sh:1"));
    assert_eq!(findings[1].kind, FindingKind::IncompleteScan);
    assert_eq!(findings[1].action, FindingAction::Deny);
    assert!(findings[1].evidence.contains("huge.sh"));
}
