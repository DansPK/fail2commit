// The extension's protocol client against the built `fail2commit` binary (FR-010).
// Set F2C_BIN to the CLI; the tests are skipped when it is absent. Everything runs
// in a disposable HOME, FAIL2COMMIT_HOME, Git config and PATH target.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ApprovalRequest, runApi } from "../src/client";

const cli = process.env.F2C_BIN;
const skip = !cli || !fs.existsSync(cli) ? "F2C_BIN is not set to a built fail2commit" : false;

function world() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "f2c-vsc-real-"));
  const home = path.join(root, "home");
  fs.mkdirSync(path.join(home, "AppData", "Local"), { recursive: true });
  const gitcfg = path.join(root, "gitconfig");
  fs.writeFileSync(gitcfg, "[user]\n\tname = T\n\temail = t@example.test\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n[protocol \"file\"]\n\tallow = always\n");
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of Object.keys(env)) if (k.startsWith("FAIL2COMMIT_")) delete env[k];
  Object.assign(env, {
    HOME: home, USERPROFILE: home, GIT_CONFIG_GLOBAL: gitcfg, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0",
    FAIL2COMMIT_HOME: path.join(root, "f2c"), FAIL2COMMIT_PATH_TARGET: path.join(root, "profile"),
  });
  const git = (cwd: string, ...a: string[]) => execFileSync("git", a, { cwd, env, encoding: "utf8" }).trim();
  return { root, env, git };
}

test("status through runApi matches the real CLI protocol", { skip }, async () => {
  const w = world();
  const res = await runApi({ cli: cli!, argv: ["status"], cwd: w.root, env: w.env, ui: { progress() {}, approve: async () => undefined } });
  assert.equal(res.version, 1);
  assert.equal(res.id !== undefined, true);
  assert.equal(res.code, "ok");
  assert.match(res.message, /sandbox/i);
});

test("a cancelled approval stops a real force push", { skip }, async () => {
  const w = world();
  // Setup writes a PATH target and hooks into the disposable home only; never run it
  // when a tray binary sits beside the CLI (it would register a sign-in Run value).
  assert.ok(!fs.readdirSync(path.dirname(cli!)).some((f) => f.startsWith("fail2commit-tray")), "tray binary beside the CLI");
  const remote = path.join(w.root, "remote.git");
  fs.mkdirSync(remote);
  w.git(remote, "init", "-q", "--bare");
  const work = path.join(w.root, "work");
  fs.mkdirSync(work);
  w.git(work, "init", "-q");
  w.git(work, "remote", "add", "origin", remote);
  fs.writeFileSync(path.join(work, "a.txt"), "1\n");
  w.git(work, "add", "-A");
  w.git(work, "commit", "-q", "-m", "one");
  w.git(work, "push", "-q", "-u", "origin", "main");
  execFileSync(cli!, ["setup"], { cwd: w.root, env: w.env });
  const old = w.git(work, "rev-parse", "HEAD");
  w.git(work, "commit", "-q", "--amend", "-m", "rewritten");

  const seen: ApprovalRequest[] = [];
  const res = await runApi({
    cli: cli!, argv: ["git", "push", "--force", "origin", "main"], cwd: work, env: w.env,
    ui: { progress() {}, approve: async (r) => { seen.push(r); return undefined; } },
  });
  assert.equal(seen.length, 1, "exactly one approval_request reached the extension");
  assert.deepEqual(seen[0].allowed, ["approve_once"]);
  assert.equal(seen[0].digest.length, 64);
  assert.ok((seen[0].findings ?? []).length > 0);
  assert.equal(res.tool_exit, 1, "git aborted the push after the cancel");
  assert.equal(w.git(remote, "rev-parse", "main"), old, "the remote keeps its commit");
});
