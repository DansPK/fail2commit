//! The reviewed plan: exact wheels (from pip's report, mapped back to files
//! the staging index verified) and the digest approvals bind to.

use super::interp::{normalize, Interpreter};
use super::proxy::Proxy;
use crate::digest::Digest;
use crate::scan::{Ecosystem, PackageId};
use crate::{Error, Finding, FindingAction, FindingKind, ResultCode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanWheel {
    pub name: String,
    pub version: String,
    pub filename: String,
    pub sha256: String,
    pub size: u64,
}

impl PlanWheel {
    pub fn package(&self) -> PackageId {
        PackageId {
            ecosystem: Ecosystem::PyPI,
            name: self.name.clone(),
            version: self.version.clone(),
        }
    }
    /// One line of the generated `--require-hashes` file.
    pub fn hash_line(&self) -> String {
        format!(
            "{}=={} --hash=sha256:{}\n",
            self.name, self.version, self.sha256
        )
    }
}

#[derive(Serialize)]
struct DigestInput<'a> {
    interpreter: InterpId<'a>,
    index: &'a str,
    requested: &'a [String],
    wheels: &'a [PlanWheel],
}

#[derive(Serialize)]
struct InterpId<'a> {
    executable: &'a str,
    prefix: &'a str,
    in_venv: bool,
    implementation: &'a str,
    python_version: &'a str,
    platform: &'a str,
    machine: &'a str,
    tags: &'a [String],
}

fn interp_id(interp: &Interpreter) -> InterpId<'_> {
    InterpId {
        executable: &interp.executable,
        prefix: &interp.prefix,
        in_venv: interp.in_venv,
        implementation: &interp.implementation,
        python_version: &interp.python_version,
        platform: &interp.platform,
        machine: &interp.machine,
        tags: &interp.tags,
    }
}

/// Digest over interpreter identity, tags, index and the exact ordered
/// wheel set with hashes.
pub fn plan_digest(
    interp: &Interpreter,
    index: &str,
    requested: &[String],
    wheels: &[PlanWheel],
) -> crate::Result<Digest> {
    Digest::of(
        "pip.install",
        &DigestInput {
            interpreter: interp_id(interp),
            index,
            requested,
            wheels,
        },
    )
}

#[derive(Serialize)]
struct RecoverInput<'a> {
    interpreter: InterpId<'a>,
    remaining: &'a [PlanWheel],
}

/// Digest of a recovery approval: the interpreter and the wheels that are
/// still to be installed. It never equals an install digest (W2-002).
pub fn recover_digest(interp: &Interpreter, remaining: &[PlanWheel]) -> crate::Result<Digest> {
    Digest::of(
        "pip.recover",
        &RecoverInput {
            interpreter: interp_id(interp),
            remaining,
        },
    )
}

fn unsupported(evidence: String, target: Option<String>) -> Error {
    let mut f = Finding::new(
        FindingKind::UnsupportedInput,
        FindingAction::Deny,
        "pip.report",
        evidence.clone(),
    );
    f.target = target;
    Error::new(
        ResultCode::InvalidInput,
        format!("unsupported input: {evidence}"),
    )
    .with_findings(vec![f])
}

/// Turn pip's `--report` JSON into the plan. Every entry must be a registry
/// wheel that our staging index verified, with the hash we computed.
pub fn from_report(
    report: &[u8],
    proxy: &Proxy,
) -> crate::Result<Vec<(PlanWheel, std::path::PathBuf)>> {
    let v: serde_json::Value = serde_json::from_slice(report)
        .map_err(|e| Error::internal(format!("pip report is not JSON: {e}")))?;
    if v["version"] != "1" {
        return Err(Error::invalid("unsupported pip report version"));
    }
    let items = v["install"]
        .as_array()
        .ok_or_else(|| Error::internal("pip report has no install list"))?;
    let mut out: Vec<(PlanWheel, std::path::PathBuf)> = Vec::new();
    for item in items {
        let name = item["metadata"]["name"].as_str().unwrap_or("");
        let version = item["metadata"]["version"].as_str().unwrap_or("");
        let url = item["download_info"]["url"].as_str().unwrap_or("");
        let target = format!("PyPI:{name}@{version}");
        if item["is_direct"].as_bool().unwrap_or(false)
            || item["download_info"]["dir_info"].is_object()
        {
            return Err(unsupported(
                format!("{name} is a direct reference"),
                Some(target),
            ));
        }
        let Some(file) = proxy.lookup(url) else {
            return Err(unsupported(
                format!("{name} {version} is not a verified registry wheel"),
                Some(target),
            ));
        };
        let reported = item["download_info"]["archive_info"]["hashes"]["sha256"]
            .as_str()
            .unwrap_or("");
        if !reported.eq_ignore_ascii_case(&file.sha256) {
            return Err(Error::integrity(format!(
                "pip's report disagrees with the verified hash for {}",
                file.filename
            )));
        }
        let Some((wname, _)) = super::wheel::parse_filename(&file.filename) else {
            return Err(unsupported(
                format!("{} is not a wheel", file.filename),
                Some(target),
            ));
        };
        if wname != normalize(name) {
            return Err(Error::integrity(format!(
                "{} does not match {name}",
                file.filename
            )));
        }
        out.push((
            PlanWheel {
                name: wname,
                version: version.to_string(),
                filename: file.filename,
                sha256: file.sha256,
                size: file.size,
            },
            file.path,
        ));
    }
    out.sort_by(|a, b| (&a.0.name, &a.0.version).cmp(&(&b.0.name, &b.0.version)));
    if out.windows(2).any(|w| w[0].0.name == w[1].0.name) {
        return Err(Error::integrity("plan lists one package twice"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_binds_every_part() {
        let i = Interpreter {
            executable: "/v/bin/python".into(),
            prefix: "/v".into(),
            base_prefix: "/usr".into(),
            in_venv: true,
            implementation: "cpython".into(),
            python_version: "3.12.1".into(),
            platform: "linux".into(),
            machine: "x86_64".into(),
            pip_version: "24.0".into(),
            tags: vec!["cp312-cp312-linux_x86_64".into()],
        };
        let w = vec![PlanWheel {
            name: "a".into(),
            version: "1".into(),
            filename: "a-1-py3-none-any.whl".into(),
            sha256: "00".repeat(32),
            size: 1,
        }];
        let base = plan_digest(&i, "https://pypi.org/simple", &["a".into()], &w).unwrap();
        let mut w2 = w.clone();
        w2[0].sha256 = "11".repeat(32);
        assert_ne!(
            base,
            plan_digest(&i, "https://pypi.org/simple", &["a".into()], &w2).unwrap()
        );
        let mut i2 = i.clone();
        i2.tags.push("py3-none-any".into());
        assert_ne!(
            base,
            plan_digest(&i2, "https://pypi.org/simple", &["a".into()], &w).unwrap()
        );
        let mut i3 = i.clone();
        i3.prefix = "/other".into();
        assert_ne!(
            base,
            plan_digest(&i3, "https://pypi.org/simple", &["a".into()], &w).unwrap()
        );
        assert_ne!(
            base,
            plan_digest(&i, "https://example.test/simple", &["a".into()], &w).unwrap()
        );
        assert_eq!(
            base,
            plan_digest(&i, "https://pypi.org/simple", &["a".into()], &w).unwrap()
        );
    }
}
