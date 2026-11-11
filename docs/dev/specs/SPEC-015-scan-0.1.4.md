# SPEC-015 — Threat data, YARA rules, pre-install checks, output scan (0.1.4)

FR-018 · FR-019 · FR-025 · FR-028 · TC-018 / TC-019 / TC-025 / TC-028 · Task W-C.
Extends SPEC-006 (scan) and CR-017 / CR-018 / CR-020. User docs: `docs/scan.md`.

Everything here only *adds* findings. Nothing from a package, a registry, the
threat-data archive or script output is executed or trusted; every input is
bounded and parsed as untrusted. Policy stays in Rust.

## Files

| Path | Role |
|---|---|
| `crates/fail2commit-core/src/scan/malware_list.rs` | FR-018: latest-data update, source/age in the header, auto refresh. |
| `crates/fail2commit-core/src/scan/yara.rs` (new) | FR-019: rule loading (bundled + user), `rules check/list`, bounded matching of package dirs, wheels and single files. |
| `rules/bundled/*.yar` (new) | FR-019: our own rules, embedded with `include_str!`. |
| `crates/fail2commit-core/src/scan/checks.rs` (new) | FR-025: registry facts, the five checks, popular-name matching, obfuscation detector. |
| `crates/fail2commit-core/src/scan/popular/{npm,pypi}.txt` (new) | FR-025 (d): bundled popular-package lists. |
| `crates/fail2commit-core/src/scan/output.rs` (new) | FR-028: `scan_tree`. |
| `crates/fail2commit-core/src/npm/mod.rs` | Integration: rules compile, auto refresh, YARA, checks, output scan + approval. |
| `crates/fail2commit-core/src/pip/mod.rs` | Integration: rules compile, auto refresh, YARA on wheels, checks. |
| `crates/fail2commit/src/cmd/rules.rs` (new) | `fail2commit rules check|list`. |
| `crates/fail2commit/src/cmd/malware_list.rs` | `update [--pinned] [--file]`, status with age warning; also reachable as `threat-data`. |
| `crates/fail2commit/src/cmd/setup.rs` (status lines only) | `status` shows threat-data source, count, age, warning. |

## FR-018 — Threat data on demand

### Source decision

`update` (no flag) downloads **the current `main` archive of
`ossf/malicious-packages`**:
`https://codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main`,
fixed in the binary (`malware_list::LATEST_URL`).

| Criterion | ossf/malicious-packages `main` (chosen) | OSV bulk export (`osv-vulnerabilities.storage.googleapis.com/{npm,PyPI}/all.zip`) |
|---|---|---|
| Content | Exactly the OSV `MAL-` records OSV itself imports (OSV's malicious-package source). | All npm/PyPI advisories (GHSA, PYSEC, MAL); MAL- filtering needed. |
| Requests | 1 | 2 (one per ecosystem) |
| Size (2026-11-11) | ~47 MB tar.gz, ~485k entries, ~760 MB unpacked | Larger: includes every CVE/GHSA record, zip needs a staged seekable copy |
| Parser | The existing CR-020 streaming tar.gz parser and its limits, unchanged | New zip parser and new limits |
| Identity | The archive's pax global header names the commit (`comment=<sha>`); recorded in the index header | Object generation only |
| Licence | Repository Apache-2.0; OSV records are data we only index | OSV data is per-source licensed |
| Stability | GitHub codeload has served this path unchanged for years; archive bytes are not stable, which only matters for the pinned (hash-checked) path | Documented OSV data dump |

Trust: verified TLS (rustls, webpki roots, `max_redirects = 0`) to the fixed
host; there is no hash pin for moving data. The pinned 0.1.3 path stays:
`update --pinned` downloads the pinned commit and checks its SHA-256 as before,
and `update --file <archive>` still imports only the pinned archive.

### Behaviour

* Download: one GET, global timeout 900 s (auto refresh: 120 s), connect
  timeout `advisories.timeout_secs`, at most `advisories.malware_list_max_bytes`
  (default 256 MiB), copied into a private temp file, then parsed with the
  CR-020 limits (2,000,000 entries, 4 GiB unpacked, 4 MiB per record,
  2,000,000 listings).
* Valid means: the gzip and tar stream end cleanly, no limit is exceeded, and
  at least one npm or PyPI listing was read. Only then is the index written
  with `fsutil::atomic_write`. Any failure leaves the previous index file
  byte-identical (the old index stays in use).
* Header gains `source` (`"pinned"` / `"latest"`; missing in 0.1.3 indexes
  means `"pinned"`, so they stay valid). For latest data `commit` is the pax
  `comment` commit id when it is 40 hex characters, else `"unknown"`, and
  `archive_sha256` is the SHA-256 of what was downloaded.
* `status` (and `malware-list status`) show source, commit, record count
  (`npm + pypi` listings) and age in days, and print
  `warning: threat data is N day(s) old (threat_data.max_age_days = M); run fail2commit malware-list update`
  when `age > max_age_days`.
* `threat_data.auto_update = true`: before a guarded npm or pip install, a
  missing, invalid or stale index is refreshed from the latest source with the
  120 s bound. Failure never stops the install: it adds one `incomplete_scan`
  `info` finding (`threat-data` source) naming the reason, and the old index
  (if any) is used.
* The command is `fail2commit malware-list update|status`, also reachable as
  `fail2commit threat-data update|status`.

### Errors

| Case | Result |
|---|---|
| Connection refused / DNS / TLS failure | `incomplete_scan` (exit 12), "malware list download failed: …", nothing written |
| Non-200 (incl. redirects) | `incomplete_scan`, names the status |
| Body cut off | `rejected`, "archive rejected: …" (gzip/tar error), index unchanged |
| Over `malware_list_max_bytes` | `rejected`, names the setting, index unchanged |
| Not gzip / not tar / no records | `rejected`, names the reason, index unchanged |

## FR-019 — YARA-X rules

* Engine: `yara-x` 1.23.0 (BSD-3-Clause), `default-features = false`,
  features `constant-folding exact-atoms fast-regexp hash-module math-module
  string-module time-module`. No `pe`/`elf`/`macho`/`dotnet` modules (they pull
  in X.509/RSA parsing); a user rule that imports one fails to compile with the
  engine's message. Cost on this host (Windows 11, `-j 2`, clean release
  build of `fail2commit`): see "Measurements" below.
* Bundled rules: `rules/bundled/*.yar`, written for this project from the
  CR-017 patterns (hidden code, credential harvest, environment harvest,
  download-and-run, drop sites, persistence, CI backdoor) plus obfuscator and
  crypto-miner/reverse-shell strings. No third-party rule sets. Embedded with
  `include_str!` and compiled at run time (≈ tens of ms); a unit test proves
  they compile and each rule matches its own sample.
* User rules: `*.yar` / `*.yara` directly in `<config dir>/rules/`
  (`TrustedPaths::config_dir`, never the workspace). At most 256 files, 1 MiB
  each; not recursive; each file is its own namespace (`user.<stem>`).
* Load errors: a user rule file that does not compile (or cannot be read, or
  is over the bounds) makes `yara::Matcher::load` fail with `invalid_input`:
  `rule file <path> does not compile: <engine error with line:column>`. The npm
  and pip flows load rules first, before resolution, so nothing runs.
* `fail2commit rules check`: compiles each file, prints `ok`/the error per
  file; exit 0 only when all compile (exit 2 otherwise). `fail2commit rules
  list`: folder path, then every rule `namespace:identifier — description`.
* `rules.enabled = false`: no matching, no load (a broken user file is then
  not an error for installs; `rules check` still reports it).
* Matching: every file of every installed npm package dir (nested
  `node_modules` excluded; they are packages of their own) and every entry of
  every wheel. Bounds: 32 MiB per file, 256 MiB per package, 2 GiB per plan,
  20,000 files per package, 10 s engine timeout per file. A file skipped by a
  bound (or an engine error) is counted; each package with skips gets one
  `incomplete_scan` `approve` finding naming the first skipped file and the
  count. At most 16 matches per package are listed, plus one summary finding.
* Finding: `yara_match`, `approve`, source `yara`, target `npm:name@ver` /
  `PyPI:name@ver`, location `<file>[:line]`, evidence
  `rule <ns>:<id> (<description>) matched <file> <when>` where when is
  "in an install script (runs in the sandbox)" for npm lifecycle files (the
  reviewed inputs), "in package code that runs when your project loads it" for
  other npm files and wheel files, and "in a startup file that runs whenever
  Python starts" for wheel `*.pth` / `sitecustomize.py` / `usercustomize.py`.

## FR-025 — Pre-install checks

Run after the files are reviewed and before advisories and approval; no
package code has run. `checks.enabled = false` skips them.

### Registry facts

| Ecosystem | Request(s) | Bound |
|---|---|---|
| npm | One GET of the full packument `<registry>/<name>` (`Accept: application/json`) on the trusted registry | 64 MiB, 60 s, no redirects |
| PyPI | `GET <index>/pypi/<name>/json` (releases, upload times, latest `info`), plus `GET <index>/pypi/<name>/<v>/json` for the previous version's `info` (and this version's when it is not the latest) | 16 MiB each, 60 s, no redirects |

`<index>` is the pinned index URL with a trailing `/simple/` removed; it must
be `https://` or loopback `http://` (CR-019 rule, `osv::normalize_base_url`).
Only a compact `Facts` record per `(ecosystem, name, version)` is kept, in the
SPEC-006 HMAC-tagged cache (`v1:facts:…`, `advisories.ttl_secs`,
`advisories.cache_max_bytes`). The "previous version" is the version with the
latest publish time before this one (npm `time`, PyPI earliest file
`upload_time_iso_8601`), yanked PyPI releases excluded.

### The checks

| Check | Hit when | Needs |
|---|---|---|
| (a) new install script | npm: this version has `preinstall`/`install`/`postinstall` (registry or reviewed `package.json`) and the previous version had none. PyPI: this version's wheel ships a startup file (`*.pth`, `sitecustomize.py`, `usercustomize.py`) and the previous version's wheel did not. | previous version's scripts / wheel |
| (b) maintainers changed | npm: `maintainers` names differ, or `_npmUser` is not among the previous version's maintainers or publisher. PyPI: the set of author/maintainer names and emails differs. | both versions' people |
| (c) very new | published less than `checks.min_age_hours` (default 48) ago, or in the future | publish time |
| (d) look-alike name | not in the popular list, and a popular name is within optimal-string-alignment distance 1 (names ≥ 5 chars), or equal after homoglyph and separator folding (`0→o`, `1`/`i`→`l`, `5→s`, `rn→m`, `vv→w`, `-_.` dropped; names ≥ 3 chars; PyPI names PEP 503-normalised first) | bundled list only |
| (e) newly obfuscated | this version has an obfuscated or minified file and the previous version had none | previous artifact |

(a)/(e) download the previous version's artifact only when this version has
something to compare (a script-less, unobfuscated version costs nothing): npm
tarball from the trusted registry origin, verified against the packument
`dist.integrity`; PyPI one wheel of the previous release (a `py3-none-any` one
first), verified against its JSON `sha256`, URL `https://` or loopback.
Bounded by `limits.artifact_max_bytes`; read in memory, never extracted.

Obfuscated / minified (`.js .cjs .mjs .py`, ≤ 4 MiB, ≤ 2,000 files, 64 MiB per
package): ≥ 20 `_0x`-hex identifiers (javascript-obfuscator), PyArmor markers,
`exec(marshal.loads|zlib.decompress|base64.b64decode(…))`, or ≥ 4 KiB with a
line over 1,000 characters and fewer than 2 % spaces in it.

Each hit: `risk_signal`, `approve`, source `checks`, evidence
`(<letter>) <check>: <evidence>`. Data the registry did not return makes that
check "not checked": one `incomplete_scan` `info` finding per package lists
the checks not run and why; it is never reported as clean. No previous
version means (a), (b), (e) do not apply (not a gap).

### Popular lists

| File | Source | Date | Size |
|---|---|---|---|
| `scan/popular/npm.txt` | `npm-high-impact` 1.13.0 (MIT, Titus Wormer), `topDownload` list, first 5,000 | 2026-11-11 | 5,000 names |
| `scan/popular/pypi.txt` | Our own query of the public ClickPy dataset (`pypi.pypi_downloads_per_day`, last 30 days, top 5,000 projects by downloads) at `sql-clickhouse.clickhouse.com` | 2026-11-11 | 5,000 names |

Generated once and committed; the file headers record source and date.

Known limits: the false-positive rate of (d) on real, less popular names was
not measured (an offline estimate was stopped as too slow); hits are
approvals, never denials. PyPI (b) compares the author/maintainer fields of
the release JSON, because PyPI does not publish uploader identity. The
"previous version" is by publish time, so a backported patch release may be
compared with a newer major line.

## FR-028 — Output scan

`scan::output::scan_tree(matcher, index, root, files) -> Vec<Finding>` scans
root-relative files (each tagged with its package) that sandboxed scripts
created or changed:

* code rules (CR-017) on text candidates, as runtime code;
* YARA rules (FR-019) on every file, same bounds;
* malware data: a produced `package.json` or `*.dist-info/METADATA` whose
  name and version are in the offline index is a `malware` `deny`.

Source `scan.output`. npm calls it after `tree::verify_after_scripts` and
before `move_tree`/commit: any `deny` stops the install (scratch tree
abandoned, project unchanged); `approve` findings ask a second approval bound
to a digest of the plan digest and every output file's SHA-256; cancel leaves
the project unchanged. pip runs no package code (wheel-only, `has_scripts =
false`), so it has no script output; the call point is documented in
`pip/mod.rs`.

## FR-013 hooks

The npm and pip flows have no progress sink yet; each new step boundary has a
`// FR-013: Step::…` comment for the progress task.

## Measurements

Windows 11 host, 12 cores, `-j 2`, rustc 1.99.1, separate empty target dirs
(2026-11-11). "Before" is `0b77fa7`; "after" is this branch with yara-x.

| Metric | Before | After | Change |
|---|---|---|---|
| `fail2commit.exe` release size | 15,810,658 B | 60,647,016 B | +44,836,358 B (×3.8) |
| Clean release build `cargo build --release -p fail2commit -j 2` | 232 s | 1,183 s | +951 s (×5.1) |
| Crates in `THIRD-PARTY-NOTICES.md` | 148 | 282 | +134 |
| YARA scan of a clean plan (TC-019-7, 200 files, 26 MB) | — | printed by the test on the VM run | — |

The "after" build time is an upper bound: a `cargo clippy -j 2` ran on the
same host for part of it. Almost all of the cost is wasmtime and cranelift,
which yara-x uses to compile rules to native code; the disabled modules
(`pe`, `elf`, `macho`, `dotnet`, `dex`, `lnk`, `crx`, `vt`, `zip`, `cuckoo`,
`console`) and their crypto dependencies are not built. The release profile
was not changed (no LTO/strip settings were added in this task).

## Test cases

| TC | Given / When / Then | Test |
|---|---|---|
| TC-018-1 | Given an index from pinned data, When the latest update serves a new record for P, Then an offline lookup of P is a `malware` deny and the header says `latest` with the pax commit. | `threat_update::latest_update_lists_new_package_as_malware_offline` |
| TC-018-2 | Given a valid index, When the download is cut off, Then the update fails naming the reason and the index file is byte-identical. | `threat_update::cut_off_download_keeps_previous_index` |
| TC-018-3 | Given a valid index, When the archive exceeds `malware_list_max_bytes`, Then it fails naming the setting and the index is unchanged. | `threat_update::oversized_download_keeps_previous_index` |
| TC-018-4 | Given a valid index, When the body is not a gzip tar or holds no records, Then it fails and the index is unchanged. | `threat_update::invalid_archive_keeps_previous_index` |
| TC-018-5 | Given no server, When updating, Then `incomplete_scan` and no index file appears. | `threat_update::unreachable_source_changes_nothing` |
| TC-018-6 | Given an index imported 30 days ago, When `fail2commit status` and `malware-list status` run, Then each warns with the age; a fresh one does not. | `threat_update::status_warns_when_index_is_old` |
| TC-018-7 | Given `auto_update` on and a stale index, When an install refreshes it from a working source, Then the index is replaced; from a failing source, Then one `info` finding and the old index stay. | `threat_update::auto_refresh_replaces_stale_index_and_failure_only_warns` |
| TC-018-8 | Given a 0.1.3 index without `source`, Then it loads as `pinned`. | `threat_update::old_index_without_source_loads_as_pinned` |
| TC-019-1 | Bundled rules compile, `rules list` names them, each matches its sample. | `rules_yara::bundled_rules_compile_and_list` + core unit test `scan::yara::tests::each_bundled_rule_matches_its_sample` |
| TC-019-2 | Given a package with a file matching a bundled rule, When installed through the npm guard, Then a `yara_match` names rule and file and the install waits for approval; cancel leaves the project unchanged. | `rules_yara::npm_install_pauses_on_bundled_rule_match` |
| TC-019-3 | Given a wheel with a file matching a bundled rule, When `pip install` runs through the guard, Then a `yara_match` names rule and file and cancel installs nothing. | `rules_yara::pip_install_pauses_on_bundled_rule_match` |
| TC-019-4 | Given a user rule matching a string in a clean package, Then the same finding appears (namespace `user.<stem>`). | `rules_yara::user_rule_matches_clean_package` |
| TC-019-5 | Given a user rule with a syntax error, When an npm install runs, Then it stops with `invalid_input` naming the file and line, before npm or any script runs. | `rules_yara::user_rule_syntax_error_stops_install_naming_file` |
| TC-019-6 | `rules check` exits 0 with valid rules and 2 naming file:line with a broken one; a workspace `rules/` folder is ignored. | `rules_yara::rules_check_cli_reports_file_and_line` |
| TC-019-7 | Given a clean package, Then no `yara_match` and the scan time is recorded (≤ 2 s for the fixture plan). | `rules_yara::clean_package_has_no_match_within_budget` |
| TC-019-8 | Given a file over the per-file bound, Then one `incomplete_scan` `approve` names it. | `rules_yara::bounds_report_incomplete_scan` |
| TC-019-9 | Given `rules.enabled = false`, Then no matching and a broken user file is not an install error. | `rules_yara::disabled_rules_skip_matching` |
| TC-025-1 | npm: previous version had no install script, this one has → (a). | `checks_preinstall::npm_new_install_script` |
| TC-025-2 | npm: maintainer set or publisher changed → (b). | `checks_preinstall::npm_maintainer_change` |
| TC-025-3 | npm/PyPI: published 1 h ago with `min_age_hours = 48` → (c). | `checks_preinstall::very_new_version` |
| TC-025-4 | npm `lodahs`, `l0dash`, `lodash_`; PyPI `reqeusts` → (d); `lodash` itself → none. | `checks_preinstall::look_alike_names` |
| TC-025-5 | npm: this version obfuscated, previous clean (verified tarball) → (e); both obfuscated → none. | `checks_preinstall::npm_newly_obfuscated` |
| TC-025-6 | PyPI: author/maintainer change → (b); new `.pth` startup file and newly obfuscated module vs previous wheel → (a), (e). | `checks_preinstall::pypi_checks_against_previous_release` |
| TC-025-7 | Clean, established package with the same people, old publish time → no finding. | `checks_preinstall::clean_established_package_has_no_signal` |
| TC-025-8 | Registry returns no `time`/`maintainers`, or 404 → `info` "not checked" naming the checks; never clean. | `checks_preinstall::missing_metadata_is_not_checked` |
| TC-025-9 | Through the npm guard, a (c) hit pauses for approval with a `risk_signal`. | `checks_preinstall::npm_flow_pauses_on_risk_signal` |
| TC-025-10 | Given checks on, When `npm ci` runs, Then the only requests besides tarballs are one packument GET per package (the existing `npm_flow::ci_installs_the_lockfile_and_keeps_project_files` turns checks off and keeps "ci resolves nothing"). | `checks_preinstall::npm_ci_checks_add_only_one_packument_request_per_package` |
| TC-028-1 | `scan_tree` over produced files flags a YARA match, a code-rule match and a produced malware `package.json` (deny). | `scan_output::scan_tree_flags_yara_code_and_malware` |
| TC-028-2 | Given a script that writes (downloads) a file matching a bundled rule, When the install runs, Then the finding appears before commit and cancelling leaves the project unchanged. | `scan_output::script_output_match_pauses_before_commit` |
| TC-028-3 | Approving the output finding commits the tree with the produced file. | `scan_output::approved_script_output_is_committed` |

Docker/Linux: the same test files run in `rust:1` as a non-root user; flow
tests that need `node`/`python3` follow the existing harness prerequisites.
