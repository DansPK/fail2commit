//! A disposable npm world: offline registry, offline OSV stub (the trusted
//! `advisories.osv_url` setting), a project and a trusted fail2commit home.

use super::npm::Registry;
use super::scan::{Response, TestServer};
use super::World;
use std::path::PathBuf;

/// OSV stub: every package is clean except names in `advisory`, which get one
/// ordinary (approvable) advisory.
pub fn osv_stub(advisory: &'static [&'static str]) -> TestServer {
    TestServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/v1/querybatch") => {
            let body: serde_json::Value = serde_json::from_str(&req.body).unwrap_or_default();
            let results: Vec<serde_json::Value> = body["queries"]
                .as_array()
                .map(|qs| {
                    qs.iter()
                        .map(|q| {
                            let name = q["package"]["name"].as_str().unwrap_or("");
                            if advisory.contains(&name) {
                                serde_json::json!({"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]})
                            } else {
                                serde_json::json!({"vulns": []})
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            Response::json(serde_json::json!({ "results": results }).to_string())
        }
        ("GET", "/v1/vulns/GHSA-aaaa-bbbb-cccc") => Response::json(
            r#"{"id":"GHSA-aaaa-bbbb-cccc","summary":"Synthetic advisory used by fail2commit e2e tests"}"#,
        ),
        _ => Response::with_status(404, "{}"),
    })
}

pub struct NpmWorld {
    pub w: World,
    pub reg: Registry,
    pub osv: TestServer,
    pub project: PathBuf,
}

impl NpmWorld {
    /// `sandbox` is the trusted `sandbox.enabled` setting.
    pub fn new(advisory: &'static [&'static str], sandbox: bool) -> NpmWorld {
        let w = World::new();
        w.paths.ensure().unwrap();
        let reg = Registry::start();
        let osv = osv_stub(advisory);
        std::fs::write(
            w.paths.config_dir.join("npmrc"),
            format!("registry={}\n", reg.url),
        )
        .unwrap();
        std::fs::write(
            w.paths.settings_file(),
            format!(
                "[advisories]\nosv_url = \"{}\"\n\n[sandbox]\nenabled = {sandbox}\n",
                osv.url()
            ),
        )
        .unwrap();
        let project = w.env.root.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"e2e-app","version":"1.0.0","private":true}"#,
        )
        .unwrap();
        let project = project.canonicalize().unwrap();
        NpmWorld {
            w,
            reg,
            osv,
            project,
        }
    }

    /// Files left behind in the sandbox stage root (must be none).
    pub fn stage_leftovers(&self) -> Vec<String> {
        let root = self.w.paths.cache_dir.join("sandbox-stage");
        match std::fs::read_dir(&root) {
            Ok(rd) => rd
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            // No stage root yet is "nothing left"; any other failure is not.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => panic!("cannot list {}: {e}", root.display()),
        }
    }
}
