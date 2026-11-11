# Package and script scanning

**Scope:** FR-006 / SPEC-006 / TC-006; 0.1.4: FR-018, FR-019, FR-025, FR-028 / SPEC-015 ·
`crates/fail2commit-core/src/scan/**`, `rules/bundled/`, `crates/fail2commit/src/cmd/{scan,rules,malware_list}.rs`.
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
| `yara_match` | `approve` | `npm:name@ver` / `PyPI:name@ver` | A package file or a file a script produced matched a YARA rule (FR-019, FR-028). `evidence` names the rule and where the file runs. |
| `risk_signal` | `approve` | `npm:name@ver` / `PyPI:name@ver` | A pre-install check hit (FR-025); `evidence` starts with `(a)`…`(e)`. |
| `incomplete_scan` | `info` | package | A pre-install check had no registry data (not checked, not clean), or a threat-data refresh failed (source `threat-data`). |
| `incomplete_scan` | `approve` | package | A file was not matched against the YARA rules because of a bound (source `yara` or `scan.output`). |

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
fail2commit malware-list update                  # download the current data (FR-018)
fail2commit malware-list update --pinned         # download this build's pinned archive
fail2commit malware-list update --file mp.tar.gz # import a copy of the pinned archive (air-gapped machines)
fail2commit malware-list status                  # source, commit, age, counts, valid or not
```

`fail2commit threat-data update|status` is the same command.

**Current data (FR-018, 0.1.4).** `update` with no flag downloads the current `main` archive of the same repository, `https://codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main` (fixed in the binary), so new malicious packages are blocked without a new fail2commit release. It is the same set of OSV `MAL-` records OSV publishes, in one ~47 MB request, parsed by the same streaming parser and limits as the pinned archive. There is no hash to pin for moving data: trust is verified TLS (rustls, bundled roots) to that host, no redirects, and the bounds below. The new index replaces the old one only when the whole archive read, parsed within every limit and held at least one npm or PyPI record; a cut-off, oversized, malformed or empty download exits non-zero, names the reason, and the old index stays in use. If the host cannot be reached, nothing changes. The index header records `source = latest` and the commit the archive names in its `pax` header.

**Age.** `fail2commit status` and `malware-list status` show the source, record count and age, and print `warning: threat data is N day(s) old (threat_data.max_age_days = 7)` once the index is older than `[threat_data] max_age_days`. With `[threat_data] auto_update = true` (default off), a guarded npm or pip install first refreshes a missing, invalid or stale index from the current data, within 120 seconds; if that fails, the install continues with the old index and shows one `incomplete_scan` `info` finding (source `threat-data`) with the reason.

**Pinned data.** The binary pins one commit of `ossf/malicious-packages` and the SHA-256 of its archive. `update --pinned` downloads `https://codeload.github.com/ossf/malicious-packages/tar.gz/<commit>`. It follows no redirects and reads at most `[advisories] malware_list_max_bytes` (default 256 MiB). With `--file` it reads a local archive instead. Either way, the archive's SHA-256 must equal the pinned value, or the update is rejected and the installed list is not replaced.

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

## YARA rules (FR-019)

Every file of every npm package and every entry of every pip wheel in an install plan is matched against YARA rules with [YARA-X](https://virustotal.github.io/yara-x) (BSD-3-Clause), built with its `hash`, `math`, `string` and `time` modules only. Nothing is executed. A match is a `yara_match` finding with action `approve`: it names the rule, the package, the file (`location`, with the line for text files) and where the file runs — in an install script (sandboxed), in package code your project loads, or in a Python startup file.

```text
fail2commit rules list    # every rule an install matches against
fail2commit rules check   # compile the bundled rules and every user file; exit 2 on any error
```

* **Bundled rules** are written for fail2commit (`rules/bundled/*.yar` in the source, built into the binary): decoded code that is executed, credential-store harvesting, environment dumps, download-and-run commands, data-drop addresses (Discord webhooks, webhook.site, OAST hosts, Telegram bots), persistence (cron, scheduled tasks, Run keys, shell startup files), GitHub workflow writes, javascript-obfuscator output, crypto-miner pools and reverse shells. No third-party rule sets are bundled.
* **Your rules**: put `*.yar` or `*.yara` files directly in the `rules` folder of the fail2commit config directory (`rules check` prints it; `%APPDATA%\fail2commit\config\rules` style on Windows, `~/.config/fail2commit/rules` on Linux, or `$FAIL2COMMIT_HOME/config/rules`). At most 256 files of 1 MiB each; `include` is disabled; each file is its own namespace (`user.<file name>`). A project or workspace can never add rules.
* **A rule file that does not compile stops every guarded install** with `invalid_input`, naming the file and line, before resolution starts and before any package code runs. Fix it or run `rules check` to see all errors.
* **Bounds**: files over 32 MiB, reading past 256 MiB per package or 2 GiB per plan, more than 20,000 files in a package, 10 s per file and 5 minutes per plan. A file a bound skipped makes one `incomplete_scan` `approve` finding per package naming the first such file and the count; it is never reported clean. At most 16 matches per package are listed.
* `[rules] enabled = false` turns matching off (and a broken user file then no longer stops installs).
* `fail2commit scan --dir <package>` runs the same rules.

## Pre-install checks (FR-025)

Before any package code runs, each package in the plan is compared with its previous release (the one published just before it). Each hit is a `risk_signal` finding with action `approve`; the evidence starts with the check letter.

| Check | Finding when |
|---|---|
| (a) new install script | npm: this version has a `preinstall`, `install` or `postinstall` script and the previous version had none. pip: this wheel installs a startup file (`*.pth`, `sitecustomize.py`, `usercustomize.py`) and the previous release's wheel did not. |
| (b) maintainers changed | npm: the maintainer list differs, or the version was published by someone who was neither a maintainer nor the publisher of the previous version. pip: the author/maintainer names and emails differ. |
| (c) very new | published less than `[checks] min_age_hours` (default 48) ago. |
| (d) look-alike name | one edit (insert, delete, change or swap) away from, or equal after homoglyph and separator folding (`0`→`o`, `1`/`i`→`l`, `rn`→`m`, `vv`→`w`, `-_.` dropped) to, a popular package, but not that package. Names under 5 characters only get the folding check. |
| (e) newly obfuscated | this version contains obfuscated or minified JavaScript or Python (javascript-obfuscator identifiers, PyArmor, `exec` of decoded data, very long lines without spaces) and the previous release contained none. |

**Data.** npm: one request for the full packument on the pinned registry. PyPI: the project JSON (`<index>/pypi/<name>/json`) plus the per-version JSON of the previous release (and of this one when it is not the latest), on the pinned index (`https` or loopback only). Each is bounded (64 MiB npm, 16 MiB PyPI, 60 s, no redirects), parsed as untrusted, and only a small summary is cached in the advisory cache (`[advisories] ttl_secs`). For (a) and (e) the previous release's tarball or wheel is downloaded only when this version has a startup file or obfuscated code to compare; it must come from the pinned registry or index file host and match its published integrity, and it is read in memory, never extracted.

**Not checked is not clean.** When the registry returns no publish time, no maintainers, no previous artifact, or no record at all, the affected checks are listed in one `incomplete_scan` `info` finding for that package. A first release has no previous version, so (a), (b) and (e) do not apply to it.

**Popular lists** (bundled, regenerated per release): npm — the first 5,000 names of `npm-high-impact` 1.13.0's download ranking (MIT); PyPI — the 5,000 most downloaded projects over the 30 days before 2026-11-11, from the public ClickPy dataset. `[checks] enabled = false` turns every check off.

## Scanning script output (FR-028)

After the sandboxed lifecycle scripts ran and before anything is moved into the project, every file they created or changed — build output and anything they downloaded — is scanned with the code rules above (as code your project loads), the YARA rules, and the offline malware data: a `package.json` or wheel `METADATA` they produced whose name and version are listed as malware is a `malware` deny. Findings use source `scan.output`. A deny stops the install; other findings ask a second approval bound to the plan and the exact produced files. Cancelling removes the scratch tree and leaves the project unchanged. pip installs only wheels and runs no package code, so it has no script output.

## OSV client

* Endpoint comes from trusted settings (`[advisories] osv_url`). It must be
  `https://` to any host, or `http://` only to a loopback host: `localhost`, an
  address in `127.0.0.0/8`, or `[::1]` (CR-019). Plain HTTP is never used for
  anything else, and nothing is upgraded or downgraded for you.
* The check refuses anything a URL parser could read as a different host:
  userinfo (`@`), `?`, `#`, `\`, `%` in the host, control characters, and
  malformed ports. Only exact loopback forms count, so
  `http://127.0.0.1.evil.example`, `http://localhost.`, `http://127.1` and
  `http://[::ffff:127.0.0.1]` are refused. The scheme may be any case.
* A refused endpoint makes every lookup incomplete; the scan never reports
  clean and never talks to another scheme (for example `file://`).
* One `ureq` agent per call carries `settings.timeout_secs` as a global timeout
  (clamped to 1..=300 s).
* TLS is rustls with the bundled webpki roots and full certificate and host
  verification; `disable_verification` is pinned to `false`. A unit test
  asserts this agent configuration so a later change cannot turn it off quietly.
* Redirects are not followed (`max_redirects = 0`). A 3xx, like any non-2xx
  status, is a failed lookup.
* Batches are chunked to 64 queries, and each query follows `next_page_token`
  for at most 32 pages; a mismatch or a runaway page loop is a failed lookup,
  never a partial "clean" answer.
* Advisory ids from the network must match `[A-Za-z0-9._-]{1,128}` because they
  become a URL path segment.
* Live-internet coverage is a single `#[ignore]` smoke test; CI uses loopback
  fixtures (`tests/fixtures/scan/osv/*.json`).

## Bounded disk cache

`<cache_dir>/osv/<sha256(key)>.json`, one entry per key: a tag line, then the
JSON envelope.

```text
f2c-hmac1:<64 hex chars>
{"stored_at":1762560000,"data":["GHSA-...","CVE-..."]}
```

* Keys are namespaced (`v1:batch:<eco>:<name>@<version>`, `v1:vuln:<id>`) and
  hashed, so untrusted package names never become file names.
* The tag is HMAC-SHA256 over the file name and the exact envelope bytes
  (CR-019). Covering the file name means a valid entry copied over another
  package's file does not verify.
* The HMAC key is 32 random bytes in `<state_dir>/osv-cache.key`, created on
  first use with the same owner-only permissions as other private state files
  (mode `0600` on Unix). It is never stored in the cache directory.
* An entry whose tag is missing or wrong is a cache miss: it is refetched when
  online and reported as an incomplete scan when offline. Entries written by
  0.1.2 and earlier have no tag, so they are refetched once. Deleting the key
  file only makes every entry refetch.
* Writes go through `fsutil::atomic_write` (temp file, fsync, rename) inside a
  private directory; a crash leaves the old or the new file.
* `ttl_secs` decides freshness. A fresh entry answers without touching the
  network.
* `cache_max_bytes` caps the whole directory, tag line included: entries larger
  than the budget are not written, and the oldest modification times are
  evicted until the directory fits. A pathological `cache_max_bytes` therefore
  degrades to "no cache", not to unbounded growth.
* Cache content is untrusted: malformed JSON, a wrong shape, an oversized file
  or a tag that does not verify is a cache miss.
* The tag proves an entry was written by this user's fail2commit. It does not
  stop someone who can write the cache from putting back an older tagged copy
  of the same entry; the TTL limits how long such a copy is used.

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
| `crates/fail2commit/tests/threat_update.rs` | FR-018: current-data update, cut-off/oversized/invalid/unreachable downloads keep the old index, status age warning, auto refresh. |
| `crates/fail2commit/tests/rules_yara.rs` | FR-019: bundled and user rules through the npm and pip guards, broken rule files, `rules check/list`, bounds, `rules.enabled`. |
| `crates/fail2commit/tests/checks_preinstall.rs` | FR-025: checks (a)–(e) for npm and PyPI fixtures, clean package, missing metadata, npm flow approval. |
| `crates/fail2commit/tests/scan_output.rs` | FR-028: `scan_tree`, script output pausing before commit, cancel and approve. |
| core unit tests in `scan/{yara,checks,malware_list}.rs` | Each bundled rule matches its sample; look-alike, obfuscation and time parsing. |

All default tests use a loopback `TcpListener` and a `FAIL2COMMIT_HOME` tempdir;
the only internet-dependent test is `live_osv_smoke` and is `#[ignore]`.