import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, SpawnOptions } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ApprovalRequest, LineSplitter, MAX_MESSAGE_BYTES, runApi, SpawnFn } from "../src/client";
import { resolveCli, trustedSetting } from "../src/cli";

const fake = path.resolve(__dirname, "..", "..", "test", "fake-cli.js");
const synthetic = () => "pw-" + ["synth", "etic", String(Date.now())].join("-");

function harness(mode: string) {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "f2c-vsc-")), "rec.json");
  const calls: { cmd: string; args: string[]; opts: SpawnOptions }[] = [];
  const spawnFn: SpawnFn = (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    // Run the fake via node; the extension still believes `cmd` is the CLI.
    return spawn(process.execPath, [fake, ...args], opts);
  };
  const env = { ...process.env, F2C_FAKE_MODE: mode, F2C_FAKE_OUT: out };
  const rec = () => JSON.parse(fs.readFileSync(out, "utf8"));
  return { calls, spawnFn, env, rec };
}

test("no shell, argv array, password only on stdin", async () => {
  const h = harness("password");
  const pw = synthetic();
  const logs: string[] = [];
  const res = await runApi({
    cli: "fail2commit", argv: ["git", "push", "origin", "main; rm -rf x"], cwd: process.cwd(), spawnFn: h.spawnFn, env: h.env,
    ui: {
      progress: (m) => logs.push(m),
      approve: async (r: ApprovalRequest) => { logs.push(r.summary); return { decision: "approve_once", password: pw }; },
    },
  });
  assert.equal(res.message, "decision=approve_once");
  assert.equal(h.calls[0].opts.shell, false);
  assert.deepEqual(h.calls[0].args, ["api"]);
  const rec = h.rec();
  assert.deepEqual(rec.argv, ["api"]);
  assert.ok(!JSON.stringify(rec.argv).includes(pw));
  assert.ok(!JSON.stringify(rec.env).includes(pw));
  assert.ok(!logs.join("\n").includes(pw));
  const [reqLine, respLine] = rec.stdin;
  assert.deepEqual(JSON.parse(reqLine).argv, ["git", "push", "origin", "main; rm -rf x"]);
  const resp = JSON.parse(respLine);
  assert.equal(resp.password, pw);
  assert.deepEqual([resp.request_id, resp.nonce, resp.digest, resp.version], ["r1", "n1", "d1", 1]);
});

test("dismissed or throwing dialog sends cancel", async () => {
  for (const approve of [async () => undefined, async () => { throw new Error("x"); }]) {
    const h = harness("password");
    const res = await runApi({ cli: "c", argv: ["status"], spawnFn: h.spawnFn, env: h.env, ui: { progress() {}, approve } });
    assert.equal(res.message, "decision=cancel");
    assert.equal(JSON.parse(h.rec().stdin[1]).password, undefined);
  }
});

test("a decision that was not offered becomes cancel", async () => {
  const h = harness("approve");
  const res = await runApi({ cli: "c", argv: ["status"], spawnFn: h.spawnFn, env: h.env, ui: { progress() {}, approve: async () => ({ decision: "run_on_host_once" }) } });
  assert.equal(res.message, "decision=cancel");
});

test("oversized line is rejected and the child is killed", async () => {
  const h = harness("huge");
  await assert.rejects(runApi({ cli: "c", argv: ["status"], spawnFn: h.spawnFn, env: h.env, ui: { progress() {}, approve: async () => undefined } }), /MAX_MESSAGE_BYTES/);
});

test("LineSplitter bounds lines across chunks", () => {
  const s = new LineSplitter();
  assert.deepEqual(s.push(Buffer.from('{"a":1}\n{"b"')), ['{"a":1}']);
  assert.deepEqual(s.push(Buffer.from(":2}\n")), ['{"b":2}']);
  assert.throws(() => new LineSplitter().push(Buffer.alloc(MAX_MESSAGE_BYTES + 1, 97)));
});

test("workspace-scoped cliPath is ignored; in-workspace paths are rejected", () => {
  assert.equal(trustedSetting({ globalValue: undefined, ...{ workspaceValue: "C:\\repo\\evil.exe" } } as never), undefined);
  assert.equal(trustedSetting({ globalValue: " /opt/f2c " }), "/opt/f2c");
  const base = { platform: "linux" as const, env: { PATH: "/work/repo/bin:/usr/bin" }, home: "/home/u", folders: ["/work/repo"] };
  const only = (...p: string[]) => (x: string) => p.includes(x);
  assert.deepEqual(resolveCli("/work/repo/fail2commit", { ...base, exists: () => true, realpath: (x) => x }), { error: "fail2commit.cliPath points inside a workspace folder and was rejected" });
  assert.deepEqual(resolveCli(undefined, { ...base, exists: only("/work/repo/bin/fail2commit", "/usr/bin/fail2commit"), realpath: (x) => x }), { path: "/usr/bin/fail2commit" });
  // a symlink out of a trusted-looking dir into the workspace is rejected
  assert.ok("error" in resolveCli(undefined, { ...base, exists: only("/usr/bin/fail2commit"), realpath: () => "/work/repo/x" }));
  const win = { platform: "win32" as const, env: { LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local", PATH: "" }, home: "C:\\Users\\u", folders: ["C:\\Work\\Repo"], realpath: (x: string) => x };
  const exe = "C:\\Users\\u\\AppData\\Local\\Programs\\fail2commit\\fail2commit.exe";
  assert.deepEqual(resolveCli(undefined, { ...win, exists: only(exe) }), { path: exe });
  assert.ok("error" in resolveCli("c:\\work\\repo\\f.exe", { ...win, exists: () => true }));
});

test("package.json declares machine scope, trust and workspace extensionKind", () => {
  const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "..", "package.json"), "utf8"));
  assert.equal(pkg.contributes.configuration.properties["fail2commit.cliPath"].scope, "machine");
  assert.equal(pkg.capabilities.untrustedWorkspaces.supported, false);
  assert.equal(pkg.capabilities.virtualWorkspaces.supported, false);
  assert.deepEqual(pkg.extensionKind, ["workspace"]);
});
