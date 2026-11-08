// Fake `fail2commit api`: records argv/env/stdin to F2C_FAKE_OUT, emulates the stdio protocol.
const fs = require("node:fs");
const readline = require("node:readline");
const mode = process.env.F2C_FAKE_MODE || "approve";
const rec = { argv: process.argv.slice(2), env: process.env, stdin: [] };
const save = () => fs.writeFileSync(process.env.F2C_FAKE_OUT, JSON.stringify(rec));
const out = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const result = (message) => out({ type: "result", version: 1, code: "ok", message, findings: [] });
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  rec.stdin.push(line);
  const msg = JSON.parse(line);
  if (msg.argv) {
    if (mode === "huge") return process.stdout.write("x".repeat(300 * 1024) + "\n");
    out({ type: "progress", message: "working" });
    return out({
      type: "approval_request", version: 1, request_id: "r1", nonce: "n1", digest: "d1", session: "s", kind: "operation",
      summary: "git push --force origin main", details: [], findings: [], expires_at: 9999999999,
      password_required: mode === "password", allowed: ["approve_once"],
    });
  }
  result("decision=" + msg.decision);
  save();
  process.exit(0);
});
rl.on("close", save);
