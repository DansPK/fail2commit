import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// The SCM view runs plain `git push`; coverage there is whatever Git's hook does.
// Disposable repo + bare remote; hook stands in for the installed fail2commit pre-push.
test("plain git push (what the SCM view runs) invokes pre-push and a failing hook blocks it", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "f2c-scm-"));
  const cfg = path.join(root, "gitconfig");
  fs.writeFileSync(cfg, "[user]\n\tname = t\n\temail = t@example.invalid\n");
  const env = { ...process.env, GIT_CONFIG_GLOBAL: cfg, GIT_CONFIG_NOSYSTEM: "1" };
  const git = (cwd: string, ...a: string[]) => spawnSync("git", a, { cwd, env, shell: false, encoding: "utf8" });
  const bare = path.join(root, "remote.git");
  const work = path.join(root, "work");
  fs.mkdirSync(work);
  assert.equal(git(root, "init", "-q", "--bare", bare).status, 0);
  git(work, "init", "-q", "-b", "main");
  git(work, "remote", "add", "origin", bare);
  fs.writeFileSync(path.join(work, "a.txt"), "x");
  git(work, "add", ".");
  assert.equal(git(work, "commit", "-q", "-m", "c").status, 0);
  const marker = path.join(root, "hook-ran").replace(/\\/g, "/");
  const hook = path.join(work, ".git", "hooks", "pre-push");
  fs.writeFileSync(hook, `#!/bin/sh\necho ran > "${marker}"\nexit 1\n`, { mode: 0o755 });
  const r = git(work, "push", "origin", "main");
  assert.notEqual(r.status, 0);
  assert.ok(fs.existsSync(marker.replace(/\//g, path.sep)), "pre-push hook ran");
  assert.equal(git(bare, "rev-parse", "--verify", "-q", "refs/heads/main").status, 1);
});
