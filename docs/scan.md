# Package and script scanning

**Scope:** FR-006 / SPEC-006 / TC-006 · `crates/fail2commit-core/src/scan/**`,
`crates/fail2commit/src/cmd/scan.rs`.
Owner: T-006. Consumers: npm (T-004) and pip (T-005) install guards, VS Code and
tray through the shared CLI/JSON protocol.

## What it does

`fail2commit scan` answers two independent questions about a *resolved, exact*
package version and never executes package code to answer them:

1. **Advisories and malware.** `POST {osv_url}/v1/querybatch` for the exact
   `(ecosystem, name, version)` triples, then `GET {osv_url}/v1/vulns/{id}` once
   per distinct advisory id for detail and classification.
2. **Script evidence.** Lifecycle `scripts` entries and the local files they
   reference are read as *text* and checked for clear Git force-push forms.

Nothing from an inspected package is run. The scan is evidence that feeds the
approval decision; isolation (SPEC-007) and the Git shim (FR-001) are the
enforcement points.

## CLI

```text
fail2commit scan [--offline] [--dir <path>] npm:<name>@<version> PyPI:<name>@<version> ...
```

Flags before the first package are options; everything after it is treated as a
package list (`--json` is a global flag and may appear before the subcommand).

| Invocation | Meaning |
|---|---|
| `fail2commit scan npm:left-pad@1.3.0` | Advisory + malware lookup for one exact version. |
| `fail2commit scan --offline PyPI:requests@2.31.0` | Cache only; never opens a socket. |
| `fail2commit scan --dir ./pkg` | Read `package.json` `scripts` and referenced local files; no registry access. |
| `fail2commit --json scan ...` | One versioned `Response` object on stdout (`protocol::PROTOCOL_VERSION`). |

Exit status follows the frozen `ResultCode` table:

| Situation | Code | Exit |
|---|---|---|
| Complete lookup, no findings | `ok` | 0 |
| Complete lookup with advisory findings | `ok` (findings need one-time approval) | 0 |
| Any `Deny` finding (known malware, flagged or uninspected script) | `rejected` | 10 |
| Lookup or detail fetch did not complete, or data is stale | `incomplete_scan` | 12 |
| Bad package spec, unusable `--dir`, no target | `invalid_input` | 2 |

`--json` error responses keep the findings but carry no `data` object, so the
completeness flag is surfaced through the `code` (`incomplete_scan`) and the
`incomplete_scan` finding instead.

## Findings

| Kind | Action | Target | Meaning |
|---|---|---|---|
| `advisory` | `approve` | `npm:name@ver` | CVE/GHSA-style advisory, `advisory_id` set. |
| `malware` | `deny` | `npm:name@ver` | OSV `MAL-` id or an OpenSSF malicious-packages record (CR-003). |
| `suspicious_script` | `deny` | `npm:name@ver` | `location` is `<script>:<line>` or `<file>:<line>`. |
| `stale_data` | `approve` | `npm:name@ver` | Cached answer past its TTL was used. |
| `incomplete_scan` | `approve` | `npm:name@ver` | No usable answer, or more than 128 advisory ids (the count dropped is in `evidence`; `MAL-` ids are kept first); treat the version as unreviewed. |
| `incomplete_scan` | `deny` | `npm:name@ver` | Referenced script content was not fully inspected: binary content, longer than the 1 MiB prefix, or dropped by the npm archive caps (CR-004). `location` and `evidence` name the file. |

Malware is deliberately a separate kind, and a hard denial: an operator may
approve a vulnerability, but a known-malicious package cannot be approved away. Every `evidence` string is redacted (`redact::redact_url_credentials`) and
length-bounded before it leaves the module.

## OSV client

* Endpoint comes from trusted settings (`[advisories] osv_url`), which must be
  `http://` or `https://` and must not carry userinfo. Anything else makes every
  lookup incomplete instead of redirecting the scan at another scheme (for
  example `file://`).
* One `ureq` agent per call carries `settings.timeout_secs` as a global timeout
  (clamped to 1..=300 s).
* Batches are chunked to 64 queries, and each query follows `next_page_token`
  for at most 32 pages; a mismatch or a runaway page loop is a failed lookup,
  never a partial "clean" answer.
* Advisory ids from the network must match `[A-Za-z0-9._-]{1,128}` because they
  become a URL path segment.
* Live-internet coverage is a single `#[ignore]` smoke test; CI uses loopback
  fixtures (`tests/fixtures/scan/osv/*.json`).

## Bounded disk cache

`<cache_dir>/osv/<sha256(key)>.json`, one entry per key:

```json
{ "stored_at": 1762560000, "data": ["GHSA-...", "CVE-..."] }
```

* Keys are namespaced (`v1:batch:<eco>:<name>@<version>`, `v1:vuln:<id>`) and
  hashed, so untrusted package names never become file names.
* Writes go through `fsutil::atomic_write` (temp file, fsync, rename) inside a
  private directory; a crash leaves the old or the new file.
* `ttl_secs` decides freshness. A fresh entry answers without touching the
  network.
* `cache_max_bytes` caps the whole directory: entries larger than the budget are
  not written, and the oldest modification times are evicted until the directory
  fits. A pathological `cache_max_bytes` therefore degrades to "no cache", not to
  unbounded growth.
* Cache content is untrusted: malformed JSON, a wrong shape or an oversized file
  is a cache miss.

### Offline and failure semantics

| Situation | Result |
|---|---|
| Fresh cache entry | Used, no network, `complete = true`. |
| `offline = true`, fresh entry | Used, no network, `complete = true`. |
| `offline = true`, entry past TTL | Used plus `stale_data`, `complete = false`. |
| Network failure, entry past TTL | Used plus `stale_data`, `complete = false`. |
| `offline = true`, no entry | `incomplete_scan`, `complete = false`. |
| Unusable endpoint, no entry | `incomplete_scan`, `complete = false`. |
| Batch ok, detail fetch failed | Advisory still reported (id-only evidence), plus `incomplete_scan`. |

A report with `complete = false` must never be presented as "no known
advisories".

## Script rules

Matched force forms after a `git` invocation whose subcommand is `push`:

`--force`, `--force-with-lease[=ref]`, `--force-if-includes`, `-f`, `--mirror`,
`--delete`, `-d`, a `+refspec` argument, and a `:refspec` deletion.

Details that make the rules usable on real scripts:

* Shell separators (`;`, `&&`, `||`, `|`) end a command, so
  `git push origin main || echo --force` is not a hit.
* Quoted and wrapped forms are covered because the text still tokenizes into
  `git`, `push`, `<form>`: `sh -c "git push --force"`, `bash -lc 'git push -f'`,
  `npx ... git push --force`, and `node -e "...('git push -f')"`.
* `git -C <dir> push --force` (and other value-taking global options) are
  skipped up to the subcommand.
* `\`-continued lines are joined (at most 8 physical lines) and reported at the
  first physical line number.
* Lines are bounded to 4096 characters, files to 1 MiB, findings per package to
  256 (an `incomplete_scan` marker with `deny` follows), and a binary file (a NUL
  in the first 8 KiB) or a file past the 1 MiB prefix yields an `incomplete_scan`
  `deny` naming the file; a clean result is never reported for content that was
  not read.
* Every finding carries `<script>:<line>` or `<file>:<line>` as `location` and
  the redacted command text as `evidence`.

### These checks are evidence, not an execution boundary

A pattern match can be evaded: computed command strings, base64 or downloaded
helpers, a `git` wrapper on `PATH`, aliases, or reading the flag from the
environment. The rules therefore only ever *add* a denial; they never grant
permission. Two enforcement points still apply:

* the Git shim and hooks reject an actual forced push (FR-001/FR-003), and
* package code that must run executes only in the sandbox (FR-007).

Optional scanner integrations (for example a third-party CLI scanner) stay out
of this path: the default scan performs no process spawning at all.

## `--dir` inspection

`--dir <path>` reads `<path>/package.json` (bounded to 1 MiB) and:

1. inspects up to 64 `scripts` entries (each bounded to 8192 characters),
2. extracts tokens that look like local files (`.js`, `.cjs`, `.mjs`, `.ts`,
   `.sh`, `.bash`, `.zsh`, `.py`, `.ps1`, `.cmd`, `.bat`),
3. resolves each candidate **inside** the directory only: relative paths without
   `..`, canonicalized, re-checked against the package root so a symlink cannot
   escape, then read bounded to 1 MiB (at most 64 files).

Untrusted metadata (`name`, `version`, script names) is stripped of control
characters and length-capped before it appears in a finding.

## Library API

```rust
use fail2commit_core::scan::{check_advisories, inspect_scripts, PackageId, Ecosystem, ScriptFile};

let report = check_advisories(&paths, &settings.advisories, &[pkg]);
let findings = inspect_scripts(&pkg, &lifecycle_entries, &referenced_files);
```

`check_advisories` returns `AdvisoryReport { findings, complete }`;
`inspect_scripts` returns `Vec<Finding>`. Callers (npm T-004, pip T-005) treat
`complete = false` as "needs approval or refusal", never as success.

## Tests

| Test file | Covers |
|---|---|
| `crates/fail2commit/tests/scan_advisories.rs` | Dedupe across pages and batch, malware classification, cache hit, offline, stale, refused network, unusable endpoint, timeout, cache bounds, clean version, `#[ignore]` live smoke. |
| `crates/fail2commit/tests/scan_scripts.rs` | Every force form, wrapped aliases, benign hooks, credential redaction, file paths and line numbers, binary and oversized files, fixture package. |
| `crates/fail2commit/tests/scan_cli.rs` | The real binary: JSON `Response`, exit codes, `--offline` never opening a socket, `--dir` denial and clean package, invalid input. |
| core unit tests in `scan/{mod,cache,osv,rules}.rs` | Rule and cache invariants. |

All default tests use a loopback `TcpListener` and a `FAIL2COMMIT_HOME` tempdir;
the only internet-dependent test is `live_osv_smoke` and is `#[ignore]`.