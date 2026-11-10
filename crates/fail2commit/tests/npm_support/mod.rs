//! Shared helpers for the npm tests (T-004): an offline loopback registry
//! that serves packuments and tarballs built at test time, signed (CR-018)
//! with a P-256 key generated per registry, disposable
//! project/home directories, and doubles for the collaborating areas.
#![allow(dead_code)]

use base64::Engine as _;
use fail2commit_core::approver::ApproverChoice;
use fail2commit_core::exec::ScriptRun;
use fail2commit_core::isolation::{JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend};
use fail2commit_core::npm::Deps;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::policy::{script_decision, ScriptDecision, ScriptSituation};
use fail2commit_core::protocol::{ApprovalRequest, Decision, Finding};
use fail2commit_core::scan::{AdvisoryReport, PackageId, ScriptFile};
use fail2commit_core::settings::Settings;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey as _;
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/npm");

// ---------------------------------------------------------------- archives

pub fn tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let mut h = tar::Header::new_gnu();
        let name = path.as_bytes();
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append(&h, *data).unwrap();
    }
    let raw = b.into_inner().unwrap();
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(&raw).unwrap();
    e.finish().unwrap()
}

pub fn sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
    )
}

// ---------------------------------------------------------------- registry

#[derive(Clone, Default)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub deps: Vec<(String, String)>,
    pub optional_deps: Vec<(String, String)>,
    pub scripts: Vec<(String, String)>,
    pub files: Vec<(String, Vec<u8>)>,
    /// `os` constraint written into the packument (optional platform skip).
    pub os: Option<String>,
    /// Version written into the tarball's own package.json, when different.
    pub archive_version: Option<String>,
    /// Extra raw tar entries (hostile paths); written after package.json.
    pub raw_entries: Vec<(String, Vec<u8>)>,
    /// Published with Sigstore build provenance (`dist.attestations`).
    pub provenance: bool,
}

impl Pkg {
    pub fn new(name: &str, version: &str) -> Pkg {
        Pkg {
            name: name.into(),
            version: version.into(),
            ..Default::default()
        }
    }
    pub fn dep(mut self, n: &str, range: &str) -> Pkg {
        self.deps.push((n.into(), range.into()));
        self
    }
    pub fn script(mut self, event: &str, cmd: &str) -> Pkg {
        self.scripts.push((event.into(), cmd.into()));
        self
    }
    pub fn file(mut self, path: &str, body: &str) -> Pkg {
        self.files.push((path.into(), body.as_bytes().to_vec()));
        self
    }
    pub fn provenance(mut self) -> Pkg {
        self.provenance = true;
        self
    }

    fn manifest(&self, version: &str) -> serde_json::Value {
        let map = |v: &[(String, String)]| -> serde_json::Value {
            v.iter()
                .map(|(k, r)| (k.clone(), serde_json::json!(r)))
                .collect::<serde_json::Map<_, _>>()
                .into()
        };
        let mut m = serde_json::json!({ "name": self.name, "version": version });
        if !self.deps.is_empty() {
            m["dependencies"] = map(&self.deps);
        }
        if !self.optional_deps.is_empty() {
            m["optionalDependencies"] = map(&self.optional_deps);
        }
        if !self.scripts.is_empty() {
            m["scripts"] = map(&self.scripts);
        }
        if let Some(os) = &self.os {
            m["os"] = serde_json::json!([os]);
        }
        m
    }

    pub fn tarball(&self) -> Vec<u8> {
        let version = self
            .archive_version
            .clone()
            .unwrap_or_else(|| self.version.clone());
        let pj = serde_json::to_vec(&self.manifest(&version)).unwrap();
        let mut entries: Vec<(String, Vec<u8>)> = vec![("package/package.json".into(), pj)];
        entries.extend(
            self.files
                .iter()
                .map(|(p, b)| (format!("package/{p}"), b.clone())),
        );
        entries.extend(self.raw_entries.clone());
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(p, b)| (p.as_str(), b.as_slice()))
            .collect();
        tgz(&refs)
    }
}

pub const KEYID: &str = "SHA256:loopback-test-key";

impl RegState {
    /// `dist.signatures` over npm's message, with the current key.
    fn signatures(&self, name: &str, version: &str, integrity: &str) -> serde_json::Value {
        let sig: Signature = self
            .signer
            .sign(format!("{name}@{version}:{integrity}").as_bytes());
        serde_json::json!([{
            "keyid": self.keyid,
            "sig": base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()),
        }])
    }

    fn public_key(&self) -> String {
        let der = self.signer.verifying_key().to_public_key_der().unwrap();
        base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
    }
}

struct RegState {
    packuments: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// Publish time per package and version (`time` map of the full doc).
    times: BTreeMap<String, BTreeMap<String, String>>,
    tarballs: BTreeMap<String, Vec<u8>>,
    /// Requests from npm and from the guard's tarball downloads.
    hits: Vec<String>,
    /// Requests from the guard's signature check (keys and metadata).
    sig_hits: Vec<String>,
    signer: SigningKey,
    keyid: String,
    key_expires: Option<String>,
    /// Replaces the keys document: `(status line, body)`.
    keys_response: Option<(String, Vec<u8>)>,
}

/// A fresh P-256 key from process randomness; no key material is stored.
fn test_signer() -> SigningKey {
    use std::hash::{BuildHasher, Hasher};
    loop {
        let mut h = sha2::Sha256::new();
        for _ in 0..4 {
            let mut x = std::collections::hash_map::RandomState::new().build_hasher();
            x.write_u128(std::time::UNIX_EPOCH.elapsed().unwrap().as_nanos());
            h.update(x.finish().to_le_bytes());
        }
        if let Ok(k) = SigningKey::from_slice(&h.finalize()) {
            return k;
        }
    }
}

pub struct Registry {
    pub url: String,
    pub port: u16,
    state: Arc<Mutex<RegState>>,
}

impl Registry {
    pub fn start() -> Registry {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(RegState {
            packuments: BTreeMap::new(),
            times: BTreeMap::new(),
            tarballs: BTreeMap::new(),
            hits: vec![],
            sig_hits: vec![],
            signer: test_signer(),
            keyid: KEYID.into(),
            key_expires: None,
            keys_response: None,
        }));
        let st = state.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let st = st.clone();
                std::thread::spawn(move || serve(conn, st));
            }
        });
        Registry {
            url: format!("http://127.0.0.1:{port}/"),
            port,
            state,
        }
    }

    pub fn publish(&self, p: &Pkg) {
        self.publish_at(p, &self.url.clone());
    }

    /// Publish with the packument's tarball URL on `base` (another origin).
    pub fn publish_at(&self, p: &Pkg, base: &str) {
        let bytes = p.tarball();
        self.publish_bytes(p, base, &bytes, &bytes);
    }

    /// Packument advertises `advertised`'s integrity but serves `served`.
    pub fn publish_bytes(&self, p: &Pkg, base: &str, advertised: &[u8], served: &[u8]) {
        let file = format!("{}-{}.tgz", p.name.rsplit('/').next().unwrap(), p.version);
        let path = format!("/{}/-/{file}", p.name);
        let mut manifest = p.manifest(&p.version);
        let integrity = sri(advertised);
        let mut s = self.state.lock().unwrap();
        manifest["dist"] = serde_json::json!({
            "tarball": format!("{}{}", base.trim_end_matches('/'), path),
            "integrity": integrity,
            "signatures": s.signatures(&p.name, &p.version, &integrity),
        });
        if p.provenance {
            manifest["dist"]["attestations"] = serde_json::json!({
                "url": format!("{}-/npm/v1/attestations/{}@{}", self.url, p.name, p.version),
                "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
            });
        }
        let n = s.times.values().map(BTreeMap::len).sum::<usize>();
        s.times.entry(p.name.clone()).or_default().insert(
            p.version.clone(),
            format!(
                "2026-01-01T{:02}:{:02}:{:02}.000Z",
                n / 3600,
                n / 60 % 60,
                n % 60
            ),
        );
        s.packuments
            .entry(p.name.clone())
            .or_default()
            .insert(p.version.clone(), manifest);
        s.tarballs.insert(path, served.to_vec());
    }

    /// A lockfile (v3) for `root_deps` and the whole `pkgs` set, built without
    /// running npm. Every package is placed at the top level.
    pub fn lockfile(&self, root_deps: &[&str], pkgs: &[&Pkg]) -> String {
        let mut packages = serde_json::Map::new();
        let deps: serde_json::Map<String, serde_json::Value> = root_deps
            .iter()
            .map(|d| (d.to_string(), serde_json::json!("^1.0.0")))
            .collect();
        packages.insert(
            String::new(),
            serde_json::json!({"name": "clean-app", "version": "1.0.0", "dependencies": deps}),
        );
        for p in pkgs {
            let file = format!("{}-{}.tgz", p.name.rsplit('/').next().unwrap(), p.version);
            let mut e = serde_json::json!({
                "version": p.version,
                "resolved": format!("{}{}/-/{file}", self.url, p.name),
                "integrity": sri(&p.tarball()),
            });
            if !p.deps.is_empty() {
                e["dependencies"] = p
                    .deps
                    .iter()
                    .map(|(k, r)| (k.clone(), serde_json::json!(r)))
                    .collect::<serde_json::Map<_, _>>()
                    .into();
            }
            packages.insert(format!("node_modules/{}", p.name), e);
        }
        let doc = serde_json::json!({"name": "clean-app", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": packages});
        serde_json::to_string_pretty(&doc).unwrap()
            + "
"
    }

    /// Change the published `dist` of `name@version` (tamper tests).
    pub fn edit_dist(&self, name: &str, version: &str, f: impl FnOnce(&mut serde_json::Value)) {
        let mut s = self.state.lock().unwrap();
        f(&mut s
            .packuments
            .get_mut(name)
            .unwrap()
            .get_mut(version)
            .unwrap()["dist"]);
    }

    /// This registry's current key, as if built into fail2commit like npm's.
    pub fn pinned(&self) -> fail2commit_core::npm::PinnedKeys {
        let s = self.state.lock().unwrap();
        fail2commit_core::npm::PinnedKeys {
            registry: self.url.clone(),
            keys: vec![fail2commit_core::npm::PinnedKey {
                keyid: s.keyid.clone(),
                key: s.public_key(),
                expires: s.key_expires.clone(),
            }],
        }
    }

    /// Switch to a fresh key under `keyid`, re-sign every published version
    /// and serve the new key: a mirror that signs with its own key.
    pub fn rotate_key(&self, keyid: &str) {
        let mut s = self.state.lock().unwrap();
        s.signer = test_signer();
        s.keyid = keyid.into();
        let mut packs = std::mem::take(&mut s.packuments);
        for (name, vers) in packs.iter_mut() {
            for (v, m) in vers.iter_mut() {
                let integrity = m["dist"]["integrity"].as_str().unwrap().to_string();
                m["dist"]["signatures"] = s.signatures(name, v, &integrity);
            }
        }
        s.packuments = packs;
    }

    /// Expiry of the signing key in the keys document (RFC 3339).
    pub fn set_key_expires(&self, t: Option<&str>) {
        self.state.lock().unwrap().key_expires = t.map(str::to_string);
    }

    /// Answer the keys endpoint with `status` (e.g. `404 Not Found`) and `body`.
    pub fn set_keys_response(&self, status: &str, body: &[u8]) {
        self.state.lock().unwrap().keys_response = Some((status.into(), body.to_vec()));
    }

    /// Serve the registry's real keys document again.
    pub fn clear_keys_response(&self) {
        self.state.lock().unwrap().keys_response = None;
    }

    pub fn sig_hits(&self) -> Vec<String> {
        self.state.lock().unwrap().sig_hits.clone()
    }

    pub fn hits(&self) -> Vec<String> {
        self.state.lock().unwrap().hits.clone()
    }

    pub fn clear_hits(&self) {
        self.state.lock().unwrap().hits.clear();
    }

    pub fn tarball_hits(&self) -> Vec<String> {
        self.hits()
            .into_iter()
            .filter(|h| h.ends_with(".tgz"))
            .collect()
    }
}

fn serve(mut conn: TcpStream, st: Arc<Mutex<RegState>>) {
    let mut buf = [0u8; 8192];
    let mut req = Vec::new();
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&req).into_owned();
    let line = text.lines().next().unwrap_or("").to_string();
    let header = |name: &str| {
        text.lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    let from_verifier = header("user-agent").starts_with("fail2commit-signatures/");
    let corgi = header("accept").contains("application/vnd.npm.install-v1+json");
    let path = line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .replace("%2f", "/")
        .replace("%2F", "/");
    let mut s = st.lock().unwrap();
    if from_verifier {
        s.sig_hits.push(path.clone());
    } else {
        s.hits.push(path.clone());
    }
    let keys_doc;
    let (status, ctype, body): (&str, &str, Vec<u8>) = if path == "/-/npm/v1/keys" {
        keys_doc = match &s.keys_response {
            Some(r) => r.clone(),
            None => {
                let doc = serde_json::json!({"keys": [{
                    "keyid": s.keyid,
                    "keytype": "ecdsa-sha2-nistp256",
                    "scheme": "ecdsa-sha2-nistp256",
                    "key": s.public_key(),
                    "expires": s.key_expires,
                }]});
                ("200 OK".to_string(), serde_json::to_vec(&doc).unwrap())
            }
        };
        (keys_doc.0.as_str(), "application/json", keys_doc.1.clone())
    } else if let Some(b) = s.tarballs.get(&path) {
        ("200 OK", "application/octet-stream", b.clone())
    } else if let Some(vers) = s.packuments.get(path.trim_start_matches('/')) {
        let name = path.trim_start_matches('/');
        let mut latest: Vec<&String> = vers.keys().collect();
        latest.sort();
        let mut doc = serde_json::json!({
            "name": name,
            "dist-tags": { "latest": latest.last().unwrap() },
            "versions": vers,
        });
        // Like the real registry: the abbreviated document has no `time`.
        if !corgi {
            doc["time"] = serde_json::json!(s.times.get(name));
        }
        (
            "200 OK",
            "application/json",
            serde_json::to_vec(&doc).unwrap(),
        )
    } else {
        (
            "404 Not Found",
            "application/json",
            br#"{"error":"not found"}"#.to_vec(),
        )
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = conn.write_all(head.as_bytes());
    let _ = conn.write_all(&body);
}

// ----------------------------------------------------------------- project

pub struct Env {
    pub tmp: tempfile::TempDir,
    pub paths: TrustedPaths,
    pub settings: Settings,
    pub project: PathBuf,
    /// Built-in signing keys (CR-018): production's npm keys by default.
    pub pinned_keys: Vec<fail2commit_core::npm::PinnedKeys>,
}

impl Env {
    /// Disposable trusted home pinned to `registry`, plus an empty project
    /// with the given package.json.
    pub fn new(registry: &Registry, package_json: &str) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let paths = TrustedPaths::under(&tmp.path().join("home"));
        paths.ensure().unwrap();
        std::fs::write(
            paths.config_dir.join("npmrc"),
            format!("registry={}\n", registry.url),
        )
        .unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("package.json"), package_json).unwrap();
        let project = project.canonicalize().unwrap();
        Env {
            tmp,
            paths,
            settings: Settings::default(),
            project,
            pinned_keys: fail2commit_core::npm::builtin_keys(),
        }
    }

    pub fn request(&self, args: &[&str]) -> fail2commit_core::npm::Request {
        let os: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
        match fail2commit_core::npm::parse(&os, &self.project) {
            Ok(fail2commit_core::npm::Action::Guarded(r)) => r,
            other => panic!("not a guarded request: {other:?}"),
        }
    }
}

/// Every file under `dir` (relative path -> bytes). Directories appear as
/// empty-name entries so an empty directory is not lost.
pub fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    fn walk(d: &Path, root: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if p.is_dir() {
                out.insert(format!("{rel}/"), vec![]);
                walk(&p, root, out);
            } else {
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

/// No leftover scratch trees in the project.
pub fn assert_no_scratch(project: &Path) {
    let left: Vec<_> = std::fs::read_dir(project)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".f2c-npm-"))
        .collect();
    assert!(left.is_empty(), "scratch left behind: {left:?}");
}

// ------------------------------------------------------------------ doubles

/// Sandbox double: records jobs and optionally runs them on the host with the
/// exact environment/cwd of the JobSpec, to prove the lifecycle context.
pub struct FakeBackend {
    pub available: bool,
    pub execute: bool,
    pub jobs: Mutex<Vec<JobSpec>>,
}

impl FakeBackend {
    pub fn new(available: bool, execute: bool) -> FakeBackend {
        FakeBackend {
            available,
            execute,
            jobs: Mutex::new(vec![]),
        }
    }
    pub fn jobs(&self) -> Vec<JobSpec> {
        self.jobs.lock().unwrap().clone()
    }
}

impl SandboxBackend for FakeBackend {
    fn probe(&self) -> ProbeReport {
        ProbeReport {
            backend: "fake",
            available: self.available,
            detail: "test double".into(),
            controls: vec![],
        }
    }
    fn run(&self, job: &JobSpec) -> fail2commit_core::Result<JobOutcome> {
        self.jobs.lock().unwrap().push(job.clone());
        let status = if self.execute {
            let out = std::process::Command::new(&job.program)
                .args(&job.args)
                .current_dir(&job.cwd)
                .env_clear()
                .envs(job.env.iter().map(|(k, v)| (k, v)))
                .output()
                .unwrap();
            JobStatus::Exited(out.status.code().unwrap_or(-1))
        } else {
            JobStatus::Exited(0)
        };
        Ok(JobOutcome {
            status,
            stdout: vec![],
            stderr: vec![],
            truncated: false,
            exported: vec![],
        })
    }
}

type AdvisoryFn = Box<dyn Fn(&[PackageId]) -> AdvisoryReport + Send + Sync>;
type InspectFn =
    Box<dyn Fn(&PackageId, &[(String, String)], &[ScriptFile]) -> Vec<Finding> + Send + Sync>;

/// How the injected collaborators behave in one run.
pub struct Behavior {
    pub decision: Decision,
    pub host_decision: Decision,
    pub advisories: AdvisoryFn,
    pub inspect: InspectFn,
    /// Runs inside the approval call, before the decision is returned.
    pub on_approval: Box<dyn Fn(&ApprovalRequest) + Send + Sync>,
}

pub fn clean_advisories(_: &[PackageId]) -> AdvisoryReport {
    AdvisoryReport {
        findings: vec![],
        complete: true,
    }
}

impl Default for Behavior {
    fn default() -> Self {
        Behavior {
            decision: Decision::ApproveOnce,
            host_decision: Decision::Cancel,
            advisories: Box::new(clean_advisories),
            inspect: Box::new(|_, _, _| vec![]),
            on_approval: Box::new(|_| {}),
        }
    }
}

pub struct Run<'a> {
    pub env: &'a Env,
    pub backend: &'a FakeBackend,
    pub requests: Arc<Mutex<Vec<ApprovalRequest>>>,
    pub host_asked: Arc<Mutex<Vec<String>>>,
}

impl<'a> Run<'a> {
    pub fn new(env: &'a Env, backend: &'a FakeBackend) -> Run<'a> {
        Run {
            env,
            backend,
            requests: Arc::default(),
            host_asked: Arc::default(),
        }
    }

    /// `Deps` wired to doubles. The script decision uses the shared FR-008
    /// table (`policy::script_decision`), as `exec::authorize_scripts` does.
    pub fn deps(&self, b: Behavior) -> Deps<'a> {
        let b = Arc::new(b);
        let requests = self.requests.clone();
        let host_asked = self.host_asked.clone();
        let backend = self.backend;
        let sandbox_on = self.env.settings.sandbox.enabled;
        let (b1, b2, b3, b4) = (b.clone(), b.clone(), b.clone(), b.clone());
        Deps {
            paths: &self.env.paths,
            settings: &self.env.settings,
            backend,
            approve: Box::new(move |req| {
                requests.lock().unwrap().push(req.clone());
                (b1.on_approval)(req);
                Ok(b1.decision)
            }),
            authorize: Box::new(
                move |sit: ScriptSituation, summary, _digest| match script_decision(
                    sandbox_on,
                    backend.probe().available,
                    sit,
                ) {
                    ScriptDecision::NoScripts => Ok(ScriptRun::NoScripts),
                    ScriptDecision::RunSandboxed => Ok(ScriptRun::Sandboxed),
                    ScriptDecision::SkipScripts => Ok(ScriptRun::Skipped),
                    ScriptDecision::AskHostOnce => {
                        host_asked.lock().unwrap().push(summary.to_string());
                        if b2.host_decision == Decision::RunOnHostOnce {
                            Ok(ScriptRun::Host)
                        } else {
                            Err(fail2commit_core::Error::rejected("host execution declined"))
                        }
                    }
                    ScriptDecision::Deny(_) => Err(fail2commit_core::Error::isolation_unavailable(
                        "sandbox unavailable or script flagged",
                    )),
                },
            ),
            advisories: Box::new(move |p| (b3.advisories)(p)),
            inspect: Box::new(move |p, s, f| (b4.inspect)(p, s, f)),
            crash: None,
            pinned_keys: self.env.pinned_keys.clone(),
        }
    }
}

pub fn kinds(f: &[Finding]) -> BTreeSet<String> {
    f.iter().map(|f| format!("{:?}", f.kind)).collect()
}

pub fn approver_none() -> ApproverChoice {
    ApproverChoice::None
}

/// Node and npm are a hard prerequisite of these tests.
pub fn require_node() {
    let probe = std::process::Command::new("node").arg("--version").output();
    assert!(
        probe.is_ok_and(|o| o.status.success()),
        "node and npm must be on PATH to run the npm tests"
    );
}
