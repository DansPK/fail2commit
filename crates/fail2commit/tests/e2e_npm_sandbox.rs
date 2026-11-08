//! FR-004, FR-007, FR-008 end to end: `fail2commit npm install` from the built
//! binary against an offline registry and OSV stub, with lifecycle scripts run
//! by the real platform sandbox (AppContainer on Windows, bubblewrap on Linux).
//!
//! Toolchain staged into the sandbox (docs/e2e.md): the host `node` binary and
//! the npm tree are copied read-only into the job stage, plus `cmd.exe` on
//! Windows. The "native build" is a staged node script that writes a build
//! artifact; Linux additionally compiles C with the system `cc` when it is
//! installed (skipped, and listed as pending evidence, otherwise).

mod e2e_support;

use e2e_support::approval::answer;
use e2e_support::npm::{require_node, snapshot, Pkg};
use e2e_support::npm_world::NpmWorld;
use fail2commit_core::protocol::{ApprovalKind, Decision, ResultCode};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const BUILD_JS: &str = r#"
const fs = require('fs');
fs.mkdirSync('build', { recursive: true });
fs.writeFileSync('build/artifact.txt', 'artifact:' + [1, 2, 3].map((x) => x * x).join(','));
fs.writeFileSync('build/where.txt', process.cwd());
"#;

fn js(s: &std::path::Path) -> String {
    serde_json::to_string(&s.to_string_lossy()).unwrap()
}

fn hostile_js(
    canary: &std::path::Path,
    checkout: &std::path::Path,
    outside: &std::path::Path,
    port: u16,
) -> String {
    format!(
        r#"
const fs = require('fs'), net = require('net');
const r = {{}};
const attempt = (k, f) => {{ try {{ r[k] = f(); }} catch (e) {{ r[k] = 'blocked:' + (e.code || e.name); }} }};
attempt('read_home_canary', () => 'READ:' + fs.readFileSync({canary}, 'utf8'));
attempt('list_checkout', () => 'LISTED:' + fs.readdirSync({checkout}).join(','));
attempt('write_outside', () => {{ fs.writeFileSync({outside}, 'x'); return 'WRITTEN'; }});
r.cwd = process.cwd();
const finish = () => {{
  fs.mkdirSync('build', {{ recursive: true }});
  fs.writeFileSync('build/report.json', JSON.stringify(r));
  process.exit(0);
}};
const s = net.connect({{ host: '127.0.0.1', port: {port} }});
s.on('connect', () => {{ r.net = 'CONNECTED'; finish(); }});
s.on('error', (e) => {{ r.net = 'blocked:' + e.code; finish(); }});
setTimeout(() => {{ r.net = r.net || 'blocked:timeout'; finish(); }}, 4000);
"#,
        canary = js(canary),
        checkout = js(checkout),
        outside = js(outside),
    )
}

fn no_scratch(project: &std::path::Path) {
    e2e_support::npm::assert_no_scratch(project);
}

#[test]
fn native_build_runs_in_the_real_sandbox_and_its_artifact_is_installed() {
    require_node();
    let n = NpmWorld::new(&[], true);
    n.reg.publish(
        &Pkg::new("native-build", "1.0.0")
            .script("install", "node build.js")
            .file("build.js", BUILD_JS),
    );
    let r = n.w.run(
        &n.project,
        &[
            "--json",
            "--approver",
            "none",
            "npm",
            "install",
            "native-build",
        ],
    );
    assert_eq!(r.code, 0, "{}\n{}\n{}", r.stdout, r.stderr, r.json);
    let pkg = n.project.join("node_modules/native-build");
    assert_eq!(
        std::fs::read_to_string(pkg.join("build/artifact.txt")).unwrap(),
        "artifact:1,4,9",
        "the build artifact written inside the sandbox was merged into the install"
    );
    let cwd = std::fs::read_to_string(pkg.join("build/where.txt")).unwrap();
    assert!(
        cwd.contains("sandbox-stage"),
        "script cwd must be a CR-007 job stage, was {cwd}"
    );
    assert_eq!(r.json["data"]["scripts"], "Sandboxed", "{}", r.json);
    assert!(n.project.join("package-lock.json").is_file());
    assert!(n.stage_leftovers().is_empty(), "{:?}", n.stage_leftovers());
    no_scratch(&n.project);
}

#[test]
fn hostile_script_cannot_reach_network_home_or_checkout() {
    require_node();
    let n = NpmWorld::new(&[], true);
    let canary = n.w.env.home.join("home-secret.txt");
    std::fs::write(&canary, ["synthetic", "-home-", "canary"].concat()).unwrap();
    let checkout_file = n.project.join("checkout-secret.txt");
    std::fs::write(&checkout_file, "checkout canary").unwrap();
    let outside = n.w.env.root.join("written-by-package.txt");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    std::thread::spawn(move || loop {
        match listener.accept() {
            Ok(_) => {
                c2.fetch_add(1, Ordering::SeqCst);
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
        }
    });

    n.reg.publish(
        &Pkg::new("hostile", "1.0.0")
            .script("install", "node hostile.js")
            .file(
                "hostile.js",
                &hostile_js(&canary, &n.project, &outside, port),
            ),
    );
    let before_checkout = std::fs::read(&checkout_file).unwrap();
    let r = n.w.run(
        &n.project,
        &["--json", "--approver", "none", "npm", "install", "hostile"],
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(n.project.join("node_modules/hostile/build/report.json")).unwrap(),
    )
    .unwrap();
    // `write_outside` may succeed inside bubblewrap's private /tmp; the host
    // check below is what proves nothing escaped.
    for k in ["read_home_canary", "list_checkout"] {
        let v = report[k].as_str().unwrap();
        assert!(v.starts_with("blocked:"), "{k} reached the host: {v}");
    }
    let net = report["net"].as_str().unwrap();
    assert!(net.starts_with("blocked:"), "network reachable: {net}");
    assert!(report["cwd"].as_str().unwrap().contains("sandbox-stage"));
    assert_eq!(
        conns.load(Ordering::SeqCst),
        0,
        "the loopback listener saw a connection"
    );
    assert!(!outside.exists(), "package wrote outside its stage");
    assert_eq!(std::fs::read(&checkout_file).unwrap(), before_checkout);
    assert!(n.stage_leftovers().is_empty(), "{:?}", n.stage_leftovers());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_native_c_build_through_the_sandbox() {
    require_node();
    if !std::path::Path::new("/usr/bin/cc").exists() {
        assert!(
            std::env::var_os("F2C_REQUIRE_NATIVE_BUILD").is_none(),
            "F2C_REQUIRE_NATIVE_BUILD set but /usr/bin/cc is missing"
        );
        eprintln!(
            "SKIPPED linux_native_c_build_through_the_sandbox: no /usr/bin/cc (pending evidence)"
        );
        return;
    }
    let n = NpmWorld::new(&[], true);
    n.reg.publish(
        &Pkg::new("native-c", "1.0.0")
            .script(
                "install",
                "mkdir -p build && cc -O2 -o build/addon addon.c && ./build/addon > build/artifact.txt",
            )
            .file(
                "addon.c",
                "#include <stdio.h>\nint main(void){printf(\"native-c:%d\\n\", 6*7);return 0;}\n",
            ),
    );
    let r = n.w.run(
        &n.project,
        &["--json", "--approver", "none", "npm", "install", "native-c"],
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(
        std::fs::read_to_string(n.project.join("node_modules/native-c/build/artifact.txt"))
            .unwrap(),
        "native-c:42\n"
    );
}

fn host_script_pkg(n: &NpmWorld, marker: &std::path::Path) {
    // The "node-gyp" word makes the script required (FR-008), so with the
    // sandbox off it needs one host-execution approval.
    let script = format!(
        "node -e \"require('fs').writeFileSync({}, 'ran-on-host')\" && echo node-gyp",
        js(marker).replace('"', "'")
    );
    n.reg
        .publish(&Pkg::new("needs-host", "1.0.0").script("install", &script));
}

#[test]
fn sandbox_off_required_script_fails_closed_without_an_approver() {
    require_node();
    let n = NpmWorld::new(&[], false);
    let marker = n.w.env.root.join("host-ran.txt");
    host_script_pkg(&n, &marker);
    let before = snapshot(&n.project);
    let r = n.w.run(
        &n.project,
        &[
            "--json",
            "--approver",
            "none",
            "npm",
            "install",
            "needs-host",
        ],
    );
    assert_eq!(r.code, 11, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["code"], "approval_unavailable");
    assert!(!marker.exists());
    assert_eq!(snapshot(&n.project), before);
    no_scratch(&n.project);
}

#[test]
fn sandbox_off_declined_host_run_changes_nothing_and_approval_runs_it_once() {
    require_node();
    let n = NpmWorld::new(&[], false);
    let marker = n.w.env.root.join("host-ran.txt");
    host_script_pkg(&n, &marker);
    let before = snapshot(&n.project);

    let mut api = n.w.api(&n.project, &["npm", "install", "needs-host"]);
    let req = api.approval_request();
    assert_eq!(req.kind, ApprovalKind::HostExecution);
    assert_eq!(req.allowed, vec![Decision::RunOnHostOnce]);
    api.send(&fail2commit_core::protocol::ClientMessage::Cancel {
        request_id: req.request_id.clone(),
    });
    let (resp, exit, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Rejected, "{out}");
    assert_eq!(exit, 10);
    assert!(!marker.exists(), "a declined host run must not execute");
    assert_eq!(
        snapshot(&n.project),
        before,
        "a declined host run changes nothing"
    );
    no_scratch(&n.project);

    // The same plan approved for host execution runs the script exactly once.
    let mut api = n.w.api(&n.project, &["npm", "install", "needs-host"]);
    let req = api.approval_request();
    assert_eq!(req.kind, ApprovalKind::HostExecution);
    api.send(&answer(&req, Decision::RunOnHostOnce, None));
    let (resp, exit, out) = api.finish();
    assert_eq!(resp.code, ResultCode::Ok, "{out}");
    assert_eq!(exit, 0);
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ran-on-host");
}

#[test]
fn sandbox_off_optional_script_is_skipped_without_asking() {
    require_node();
    let n = NpmWorld::new(&[], false);
    let marker = n.w.env.root.join("skipped.txt");
    n.reg.publish(&Pkg::new("optional-script", "1.0.0").script(
        "install",
        &format!(
            "node -e \"require('fs').writeFileSync({}, 'x')\"",
            js(&marker).replace('"', "'")
        ),
    ));
    let r = n.w.run(
        &n.project,
        &[
            "--json",
            "--approver",
            "none",
            "npm",
            "install",
            "optional-script",
        ],
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["data"]["scripts"], "Skipped");
    assert!(!marker.exists());
}
