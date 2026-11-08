//! Independent wave-2 security-review reproductions (W2-003).
//!
//! `scan::inspect_scripts` decodes a referenced script file with
//! `script_text`, which silently returns an empty string when any of the first
//! 8192 bytes is NUL. No incompleteness is reported, so a package whose
//! `postinstall` runs a file that starts with 8 KiB of NUL bytes is reviewed as
//! clean even though the same file contains a force-push form that is denied
//! outright when it is plain text.

use fail2commit_core::protocol::FindingAction;
use fail2commit_core::scan::{inspect_scripts, Ecosystem, PackageId, ScriptFile};

fn pkg() -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: "demo".into(),
        version: "1.0.0".into(),
    }
}

fn script(name: &str, command: &str) -> Vec<(String, String)> {
    vec![(name.to_string(), command.to_string())]
}

#[test]
fn plain_referenced_script_with_a_force_push_is_denied() {
    // Control case: the rule itself works on text.
    let files = vec![ScriptFile {
        path: "setup.js".into(),
        bytes: b"#!/bin/sh\ngit push --force origin main\n".to_vec(),
    }];
    let findings = inspect_scripts(&pkg(), &script("postinstall", "node ./setup.js"), &files);
    assert!(
        findings
            .iter()
            .any(|f| f.action == FindingAction::Deny
                && f.location.as_deref() == Some("setup.js:2")),
        "the control case must be denied"
    );
}

#[test]
fn nul_prefixed_referenced_script_is_reported_clean() {
    // Same file, same force push, 8 KiB of NUL bytes in front of it.
    let mut bytes = vec![0u8; 8192];
    bytes.extend_from_slice(b"#!/bin/sh\ngit push --force origin main\n");
    let files = vec![ScriptFile {
        path: "setup.js".into(),
        bytes,
    }];
    let findings = inspect_scripts(&pkg(), &script("postinstall", "node ./setup.js"), &files);
    assert!(
        findings
            .iter()
            .any(|f| f.action == FindingAction::Deny
                && f.location.as_deref() == Some("setup.js:2")),
        "W2-003: a referenced script containing a force push must be denied \
         (or reported as an incomplete scan), not silently skipped"
    );
}

#[test]
fn script_file_beyond_the_scan_prefix_is_silently_ignored() {
    // A force push past the 1 MiB inspection prefix is also invisible, and the
    // report is still complete.
    let mut bytes = vec![b'\n'; 1024 * 1024 + 64];
    let tail = b"git push --force origin main\n";
    let start = 1024 * 1024 + 16;
    bytes[start..start + tail.len()].copy_from_slice(tail);
    let findings = inspect_scripts(
        &pkg(),
        &script("postinstall", "node ./setup.js"),
        &[ScriptFile {
            path: "setup.js".into(),
            bytes,
        }],
    );
    assert!(
        !findings.is_empty(),
        "W2-003: inspection stopped at the prefix without reporting incompleteness"
    );
}
