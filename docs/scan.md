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
| `suspicious_code` | `approve` | `npm:name@ver` | Package code matched a malicious-code rule (CR-017). `location` is `<file>:<line>`; `evidence` says what the code does and whether it runs at install or when your project loads the package. |
| `stale_data` | `approve` | `npm:name@ver` | Cached answer past its TTL was used. |
| `incomplete_scan` | `approve` | `npm:name@ver` | No usable answer, or more than 128 advisory ids (the count of ordinary advisories dropped is in `evidence`). Every id up to 512 still has its record classified, so a malware record is never dropped, whatever its id case or prefix; treat the version as unreviewed. |
| `incomplete_scan` | `deny` | `npm:name@ver` | More than 512 advisory ids: malware cannot be ruled out. |
| `incomplete_scan` | `deny` | `npm:name@ver` | Referenced script content was not fully inspected: binary content, longer than the 1 MiB prefix, or dropped by the npm archive caps (CR-004). `location` and `evidence` name the file. |

Malware is deliberately a separate kind, and a hard denial: an operator may
approve a vulnerability, but a known-malicious package cannot be approved away. Every `evidence` string is redacted (`redact::redact_url_credentials`) and
length-bounded before it leaves the module.

## Malicious-code checks (CR-017)

When you run `npm install` or `npm ci` through fail2commit, every package in the install plan is also read as text and checked for code that behaves like known supply-chain attacks. Nothing is executed. Each match becomes a `suspicious_code` warning in the approval prompt: **approve** to continue the install, or **cancel** to install nothing. `fail2commit scan --dir <package>` runs the same checks on any package folder.

| Rule | What it looks for |
|---|---|
| Hidden code | A decoded string being executed (`eval(Buffer.from(…,'base64'))`, `new Function(atob(…))`, long encoded `eval` literals). Base64 blobs are decoded and scanned again, two levels deep. |
| Credential harvest | One file that names two or more credential stores: `.npmrc`, `.ssh`, `.aws`, `.git-credentials`, the GitHub CLI token, Docker or Kubernetes config, cloud credentials, browser logins, crypto wallets, `.pypirc`. |
| Environment harvest | `JSON.stringify(process.env)`, or a search of the environment for `TOKEN`, `SECRET`, `PASSW`, `AWS_`, `GITHUB_` or `NPM_TOKEN`. |
| Download and run | `curl`/`wget` piped to a shell or saved to a file, PowerShell `iwr`/`irm`/`DownloadString`, encoded PowerShell, `certutil`/`bitsadmin`/`mshta` downloads. |
| Data-drop address | Discord webhooks, webhook.site, Pipedream, RequestBin, ngrok, interactsh/OAST, Burp Collaborator, transfer.sh and similar, or an `http(s)://` URL to a public IP address. |
| Persistence | A file write next to a shell or startup file (`.bashrc`, `.zshrc`, LaunchAgents, the Windows Startup folder, autostart), a `Run` registry key, `crontab -`, `schtasks /create`, `systemctl --user enable`. |
| CI backdoor | Writing files into `.github/workflows`. |

**Install time or load time.** Lifecycle scripts and the files they run are *install-time* code: they run in the sandbox, and every rule applies. Other files are *runtime* code that runs when your project loads the package, outside the sandbox. In runtime code, download and persistence commands count only inside an `exec`/`spawn` call or next to a file write, and the package's own test files are skipped. Help text and helper scripts often mention these commands without running them.

**Warnings, not blocks.** Heuristics have false positives, so a match always needs your approval and is never a hard denial. Known malware from OSV and OpenSSF stays a hard denial.

**Limits.** Files over 16 MiB are skipped, reading stops at 64 MiB per package, and each package shows at most 8 warnings plus a count of the rest. A determined attacker can write code that none of these rules recognise. This check adds evidence to your decision; it does not make package code safe. Use `fail2commit run` for code you don't trust.

## Advisory evidence

Advisory findings lead with the severity and the versions that fix the problem, for example `GHSA-xxxx [high], fixed in 4.17.21: Prototype pollution in lodash`. Severity comes from the advisory's `database_specific.severity`. Fixed versions come from the `affected` ranges for exactly this package.

## Offline malware list (CR-020)

Known malware stays blocked when OSV cannot be reached. fail2commit can keep a local copy of the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) list and check it whenever an OSV lookup fails.

```text
fail2commit malware-list update                  # download the pinned archive
fail2commit malware-list update --file mp.tar.gz # import a copy (air-gapped machines)
fail2commit malware-list status                  # commit, import date, counts, valid or not
```

**Pinned data.** The binary pins one commit of `ossf/malicious-packages` and the SHA-256 of its archive. `update` downloads `https://codeload.github.com/ossf/malicious-packages/tar.gz/<commit>`. It follows no redirects and reads at most `[advisories] malware_list_max_bytes` (default 256 MiB). With `--file` it reads a local archive instead. Either way, the archive's SHA-256 must equal the pinned value, or the update is rejected and the installed list is not replaced. A newer list needs a newer fail2commit build.

Pinned for 0.1.3: commit `445b5efdb738cc8c4ba623dc7ab7016b6d609ebc` (main on 2026-11-10). Its archive is 47,496,163 bytes with SHA-256 `4b800102edef55aff59f47cc32d5e23a753a2b07c958fd1591df1b5244d000b7`, measured from one download of the URL above. It builds an index of about 12 MB: 223,167 npm and 11,993 PyPI listings.

**GitHub archives are not guaranteed to be byte-stable.** If GitHub regenerates the archive with different compression, the download no longer matches the pin and `update` fails closed. Then fetch the archive for the pinned commit some other way, check its SHA-256 yourself, and import it with `--file`.

**Parsing.** The archive is untrusted input even after its hash matches. fail2commit streams the `tar.gz` and reads only `osv/malicious/npm/**` and `osv/malicious/pypi/**` `.json` files. Nothing is extracted to disk. Limits:

* 2,000,000 entries, 4 GiB unpacked and 2,000,000 listings. Past any of these the whole update is rejected.
* Records over 4 MiB, malformed JSON and unsafe ids are skipped and counted.
* Paths that contain `..` or are absolute never count as records.

Each record gives one listing per affected package: the MAL id, plus either its exact `affected[].versions` or "all versions". A record with any `ranges` (for example "introduced 0", no fix), with no versions, or with more than 65,536 versions counts as all versions. Withdrawn records are left out. PyPI names are normalised (lowercase, and runs of `_`, `.` and `-` become one `-`). npm names are matched exactly. Versions are compared as exact strings.

**Storage.** The index is written atomically to `<state dir>/malware-list/index.json`. Its header holds the commit, the archive SHA-256, the import time and the counts. The file starts with the SHA-256 of its body, so a damaged or edited index is detected on load and ignored. This tag is not a signature: anyone who can write your private state directory already runs as you.

**Use.** When `[advisories] offline_malware` is on (the default) and the OSV lookup for a package failed (network down, or `offline = true`) with no cached answer:

* A package and version in the index is a `malware` finding with action `deny` and source `openssf-offline`. Its evidence names the MAL id and the list's commit.
* Each failed package still gets its `incomplete_scan` finding, because CVEs were not checked. Its evidence ends with one of `offline malware list: listed as malware`, `checked, no match`, `not installed`, `invalid, ignored` or `disabled`.

When OSV answers, the list is not read. A missing or invalid list never blocks anything by itself. `status` reports an invalid list and exits with an integrity error.

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
  anywhere in the inspected prefix; `sh` skips NULs, so one past the first block still splits tokens) or a file past the 1 MiB prefix yields an `incomplete_scan`
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