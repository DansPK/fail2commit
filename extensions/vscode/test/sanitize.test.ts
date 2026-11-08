import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitize } from "../src/sanitize";

test("credentials in URLs never reach display text (W1-004)", () => {
  const user = ["us", "er"].join("");
  const token = ["tok", "en", String(Date.now())].join("-");
  const out = sanitize(`pip install git+https://${user}:${token}@example.test/pkg.git`);
  assert.ok(!out.includes(user) && !out.includes(token), out);
  assert.ok(out.includes("https://***@example.test/pkg.git"), out);
});

test("bidi, zero-width and control characters are escaped (W1-005)", () => {
  for (const cp of [0x202e, 0x202a, 0x2066, 0x2069, 0x200b, 0x1b, 0x0a, 0x85]) {
    const ch = String.fromCodePoint(cp);
    const out = sanitize(`refs/heads/release-${ch}txt`);
    assert.ok(!out.includes(ch), `U+${cp.toString(16)} survived`);
    assert.ok(out.includes(`\\u{${cp.toString(16)}}`), out);
  }
  assert.equal(sanitize("refs/heads/main a..b"), "refs/heads/main a..b");
});

test("invisible, separator and tag characters are escaped; userinfo with @ fully redacted (R1-004)", () => {
  for (const cp of [0x061c, 0x2060, 0x2064, 0xfeff, 0x2028, 0x2029, 0x00ad, 0xe0041]) {
    const ch = String.fromCodePoint(cp);
    const out = sanitize(`refs/heads/x${ch}y`);
    assert.ok(!out.includes(ch), `U+${cp.toString(16)} survived`);
  }
  const pw = ["p", "@", "ss x"].join("");
  assert.equal(sanitize(`https://user:${pw}@host.test/r and more`), "https://***@host.test/r and more");
  assert.equal(sanitize("see https://host.test/a@b"), "see https://host.test/a@b");
});
