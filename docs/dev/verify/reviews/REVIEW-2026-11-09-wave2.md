# Independent security review: fail2commit integration candidate wave 2

Date: 2026-11-09
Candidate branch: `DansPK/f2c-int-wave2`
Candidate SHA reviewed: `3d924c1dfb1e8158ae44be2020811de08c7abee3`
Previously reviewed candidate: `a147c12` (wave 1)
Review diff: `git diff a147c12..HEAD`
Reviewer: independent (did not write this code). Product code was not modified.

The candidate should not be merged before W2-001 is fixed. W2-002, W2-003 and
W2-004 need an explicit decision: each is a documented design choice that
conflicts with a stated requirement, so the coordinator should either change the
behaviour or record a change request. The attached
`crates/fail2commit/tests/review_wave2_pth.rs` and
`crates/fail2commit/tests/review_wave2_scan.rs` contain intentionally failing
reproductions.

## Findings

### W2-001 — High — CONFIRMED: a guarded pip install executes wheel-supplied code on the host

**Location:** `crates/fail2commit-core/src/pip/mod.rs:306-316` (the FR-008 call is
made with `has_scripts: false`, "pip wheel install (no install-time code)"),
`crates/fail2commit-core/src/pip/apply.rs:230-238` (`verify_installed` starts a
new interpreter right after the wheels are installed),
`crates/fail2commit-core/src/pip/interp.rs:46-49`, `:81-98`, `:101-111`
(every invocation is `python -I ...`),
`crates/fail2commit-core/src/pip/wheel.rs:48-113` (wheel inspection never looks
at interpreter-startup paths), `docs/pip.md:80-81`, `docs/pip.md:103-105`.

`-I` (isolated) removes `PYTHON*` variables, the user site directory and the
script directory from `sys.path`. It does **not** disable `site`, so CPython
still processes every `*.pth` file in the environment's `purelib` and `exec()`s
each `import` line it finds. A wheel may ship a top-level `*.pth` file and the
wheel spec installs it into `purelib`; `sitecustomize.py` and `usercustomize.py`
behave the same way. Real packages do this (for example setuptools'
`distutils-precedence.pth`), so "wheels never run install-time code" is false in
general, and it is false inside this codebase's own process chain:

1. `pip::install` reviews a wheel set, asks for approval only when there is a
   finding, and calls `exec::authorize_scripts` with `has_scripts: false`, so no
   sandbox and no host-execution approval is involved (`pip/mod.rs:306-316`).
2. `apply::apply` installs wheel *n* with `python -I -m pip ...`
   (`pip/apply.rs:215-219`, `pip/interp.rs:101-111`). The next wheel's install,
   and `verify_installed` after the loop (`pip/apply.rs:230`, `:238`), start the
   target interpreter again.
3. `site` executes the `.pth` that the review just installed. Arbitrary code now
   runs with the invoking user's full privileges, outside any sandbox, in the
   same guarded command, with no prompt at all when the advisory scan is clean.

The approval details list only `name==version sha256:...` (`pip/mod.rs:271-280`),
so the reviewer is never told that a wheel carries interpreter-startup code.
`wheel::inspect` accepts any entry name (it rejects only path escapes, symlinks,
size, and a name/version mismatch), so nothing in the pipeline notices.

**Reproduction:** `cargo test -j 2 -p fail2commit --test review_wave2_pth` runs a
real `pip::install` against the offline loopback index with a wheel carrying
`f2c_review_marker.pth`. The install returns `Ok`, `approved == false`, the
package is installed, and the marker file that only the `.pth` can create
exists.

**Why High under the SPEC-005 threat model.** SPEC-005 requires apply to run
offline from the reviewed wheel set "with no dependency re-resolution, and
reject substitutions", and SPEC-007 requires that any untrusted code that must
execute runs only after policy approval under a verified sandbox. A `*.pth` is
not a substitution — the bytes are exactly the reviewed ones — but it is
package-controlled code, and it runs unsandboxed inside the guarded command with
no approval, so the only premise holding the boundary up is FR-005's claim that
"wheels execute no code at install time" (`docs/pip.md:103-105`); that claim is
what makes the guard pass `has_scripts: false` instead of asking. The threat is
the one this guard exists for: one compromised or malicious *transitive* wheel
(supply-chain compromise, typo-squat) is approved as an opaque hash, and the
advisory scan is then the only remaining barrier — which is exactly the case
where no advisory exists yet. Not Critical only because it needs that one
approved wheel; not lower because nothing else in the command notices.

**Suggested fix:** treat import-bearing `*.pth`, `sitecustomize.py` and
`usercustomize.py` in the reviewed wheel set as package-controlled code: deny by
default, or pass `has_scripts: true` to `exec::authorize_scripts` and run the
apply (or at least every interpreter start after the first install) inside the
SPEC-007 sandbox. At minimum set `has_scripts` truthfully and name the file in
the approval details.

### W2-002 — Medium — CONFIRMED: cancelling a pip apply does not stop it; the next unrelated install finishes it without asking

**Location:** `crates/fail2commit-core/src/pip/mod.rs:148` (`apply::recover` runs
at the top of every guarded install, before the current request is looked at),
`crates/fail2commit-core/src/pip/apply.rs:181-191` (`recover` replays the journal
with no approval check), `:203-208` (cancel returns `Rejected` but leaves the
journal in place), `crates/fail2commit-core/src/pip/mod.rs:226-232`.

Scenario: the user approves a 12-wheel plan, then cancels (or the CLI is
interrupted) after 3 wheels. The venv is already modified, the journal records
`done: 3`, and `Error::rejected` is returned. The user later runs an unrelated
`pip install -r other.txt`; step 2 of that command silently installs the
remaining 9 wheels of the *old* plan — re-verified against the journal's own
hashes, so it does install exactly what was approved then — and reports only
`"recovered": true`. The one-shot approval is effectively replayed, and a
cancelled operation does apply changes.

This contradicts AGENTS.md ("A cancelled operation cannot apply changes") and the
FR-005 cancellation wording, but `docs/pip.md:90-99` describes roll-forward as
intended, so it needs an explicit decision rather than a silent fix.

**Suggested fix:** record the cancellation in the journal and require a fresh
approval — or drop the journal — before rolling forward; do not apply a
previously cancelled plan implicitly inside a different command.

### W2-003 — Medium — CONFIRMED: script evidence silently reports clean for non-text files

**Location:** `crates/fail2commit-core/src/scan/mod.rs:411-420`
(`script_text` returns an empty string when any byte in the first 8192 is NUL,
and only the first 1 MiB is examined), `:363-377` (an empty decode simply
`continue`s), `:36-37`.

`inspect_scripts` decodes each referenced file, and a decode that yields nothing
is indistinguishable from a clean file: no finding, and no `IncompleteScan`, so
the plan is reported complete. A package with
`"postinstall": "node ./setup.js"` whose `setup.js` starts with 8 KiB of NUL
bytes followed by `git push --force origin main` is reviewed clean, while the
text version of the exact same file is a hard `Deny`. The script still runs
(`npm/apply.rs:381-404`), so the flagged-script rule of SPEC-006 is bypassed by a
one-line change to the payload. The same applies to a force push placed after the
1 MiB inspection prefix.

**Reproduction:** `cargo test -j 2 -p fail2commit --test review_wave2_scan`
(the control case passes; the NUL-prefixed and past-the-prefix cases fail).

**Suggested fix:** emit an `IncompleteScan` (`FindingAction::Deny`) whenever a
referenced file cannot be decoded as text or is longer than the inspected
prefix, exactly as the finding-count overflow path already does at
`scan/mod.rs:397-407`.

### W2-004 — Medium — CONFIRMED (code path): the npm archive layer never reviews extension-less referenced scripts and silently drops referenced files past its caps

**Location:** `crates/fail2commit-core/src/npm/archive.rs:158-164`
(`is_script_like` is an extension allowlist), `:93-94` (only "script-like"
entries become candidates, and the 16 MiB `CANDIDATE_BUDGET` stops collecting
with no record), `:146-154` (at most 32 referenced files and 2 MiB of referenced
content, again with no record).

Two independent, trivial misses:

* `"postinstall": "sh ./run"` with a file `run` containing `git push --force`:
  `run` has no allowlisted extension, so it is never read, `out.files` is empty,
  and `scan::inspect_scripts` reports nothing. Renaming the file to `run.sh`
  produces a hard `Deny`, so the rule is bypassed by a file name.
* ~17 × 1 MiB `.js` filler entries exhaust `CANDIDATE_BUDGET` (16 MiB) before the
  hostile `postinstall`-referenced file, or 33 referenced files exhaust the
  32-file cap, and the referenced file is silently absent from `out.files`.

Both cases produce a *complete* clean report for a package that the same rules
deny outright when the payload is presented normally. Not reproduced by test
because `npm::archive` is a private module; confirmed by reading the loop.

**Suggested fix:** add every path token from the lifecycle commands to the
candidate set regardless of extension, and raise `IncompleteScan` (Deny) whenever
a referenced candidate is dropped by a size or count cap.

### W2-005 — Medium — CONFIRMED (code path): case-folding collision defeats npm script review on Windows

**Location:** `crates/fail2commit-core/src/npm/archive.rs:93-103` (candidates and
the manifest are keyed by the exact, case-sensitive archive path), `:138-154`
(the referenced file is matched by exact byte name), and
`crates/fail2commit-core/src/npm/apply.rs:185-239` (`verify_tree` re-checks only
`name`/`version`, never file contents).

A tarball containing `package/build.js` (benign) followed by `package/BUILD.js`
(hostile) is inspected as two distinct files. The lifecycle command
`node ./build.js` matches `build.js` exactly, so the reviewed bytes are the
benign ones. npm's extractor writes to a case-insensitive filesystem on Windows,
so the file that ends up on disk as `build.js` is the hostile `BUILD.js`. The
approved plan, the digest and `verify_tree` all describe the benign content, and
the script that runs is the unreviewed one. The same trick applies to
`package.json`/`PACKAGE.json`, where the `scripts` of the second entry are the
ones that end up executing, and to trailing-dot/space names that Windows folds
onto an existing file.

**Suggested fix:** reject archives whose entry set is not unique under ASCII
case folding (and under Windows trailing-dot/space folding) before anything else
happens, or key candidates through one case-folded map and `Deny` on collision.

### W2-006 — Low — CONFIRMED: `fail2commit setup` deletes a foreign `pip`/`pip3` in its own bin dir

**Location:** `crates/fail2commit-core/src/pip/shim.rs:21-30` (`place` removes
whatever exists at the shim path with no ownership check); contrast
`crates/fail2commit-core/src/npm/shim.rs:39-52`, which refuses to replace a file
that is not its own shim.

`fail2commit setup` silently deletes an existing `pip`/`pip3` file under
`<bin_dir>`, and `uninstall` cannot restore it because the `OwnedChange` records
only the target. The bin dir is private to fail2commit, so the impact is limited
to a user who put a wrapper there, but the two shims should behave the same way.

**Suggested fix:** apply the npm shim's "already exists and is not ours" check
before replacing, and record the replaced file so uninstall stays inert.

### W2-007 — Low — CONFIRMED: advisory-list truncation is not reported

**Location:** `crates/fail2commit-core/src/scan/mod.rs:31-33` (the doc comment
promises "A longer list is truncated and the report says so"), `:166` and `:237`
(`ids.truncate(MAX_IDS_PER_PACKAGE)`, no `complete = false`, no finding).

A package with more than 128 advisory ids is reported as a complete scan that
lists 128 of them, and the report does not say so. This is not a false clean —
the package is still flagged — but the documented behaviour is unimplemented.

**Suggested fix:** set `complete = false` (or push a `StaleData`/`IncompleteScan`
finding) when the per-package list is truncated.

### W2-008 — Low — PLAUSIBLE: known malware is one click away from approve

**Location:** `crates/fail2commit-core/src/scan/mod.rs:264-282`,
`crates/fail2commit-core/src/scan/osv.rs:187-207`,
`crates/fail2commit-core/src/pip/mod.rs:264-301`.

`is_malware` classifies an OSV `MAL-` id, or an OpenSSF malicious-packages
record, as `FindingKind::Malware` - which satisfies SPEC-006's "classify malware
separately from CVEs" - but the action is `FindingAction::Approve`, so installing
a package that OSV lists as known malware needs only the same single
`ApproveOnce` as an ordinary advisory. SPEC-006 does not require a hard denial
here, so this is a policy question for the coordinator rather than a
demonstrable defect.

**Suggested fix:** decide explicitly whether known malware is a hard `Deny`; if
not, at least require the configured password (or a distinct approval kind) for a
`Malware` finding.

## Checked and found sound

Each item was read end to end in the candidate, not taken from the workers'
verify reports.

**npm (T-004, FR-004)**

- Argument classification (`npm/cmdline.rs:98-232`) is deny-by-default: git,
  `github:`, `file:`, `link:`, URL, tarball, `npm:` alias, `workspace:` and
  `u/r` shorthand are rejected in arguments, in `package.json` dependency
  sections and in `overrides` (`npm/mod.rs:146-173`); unknown verbs, leading
  options, `-g`, `update`, `exec`, `rebuild`, `link` and `audit fix` are refused
  rather than passed through.
- npm is always `node <npm-cli.js>` with structured arguments and a cleared
  environment (`npm/runner.rs:155-170`, `:80-108`); no `cmd.exe`, no
  `npm.cmd`, and no `.bat`/`.cmd` on the tool search path
  (`toolpath.rs:43-49`).
- The registry is pinned from trusted state only; the project `.npmrc` is an
  allowlist and any other key is a hard stop with values never echoed
  (`npm/config.rs:15-32`, `:184-216`). `ignore-scripts=true` is forced into the
  staged userconfig and onto the command line for every npm invocation
  (`npm/config.rs:220-236`, `npm/apply.rs:34-53`), including cache seeding.
- The lockfile graph is validated before any download: name, version and
  `resolved` must be on the pinned origin and path prefix, integrity must be
  `sha512` (a weak token never rescues a strong one), and `link`, `inBundle`,
  `..`, absolute paths, backslashes, drive/stream markers and missing entries
  are denied (`npm/lockfile.rs:74-201`).
- Artifacts are downloaded by the guard itself, with redirects disabled, a byte
  cap and SRI verification against the lockfile (`npm/review.rs:37-59`,
  `:92-109`); archive bytes are validated without extraction (entry type, path,
  size, entry count) (`npm/archive.rs:58-156`).
- The approval digest covers the command, specs, save flags, project, pinned
  registry, project settings, npm version, sandbox setting, both final file
  hashes, every artifact with integrity and scripts, and the findings
  (`npm/mod.rs:300-345`); a second digest binds the exact script list (`:410`).
  Any `Deny` finding stops the command before approval (`npm/mod.rs:293-298`).
- Apply is `npm ci --offline --ignore-scripts` from a private cache seeded only
  with the reviewed bytes (`npm/apply.rs:88-121`, `npm/mod.rs:455-462`), then
  the tree is compared against the plan including npm's hidden lockfile
  (`npm/apply.rs:185-239`), then the project fingerprint is re-read
  (`npm/mod.rs:428-447`), then a journaled rename-based commit rolls back at
  every crash point (`npm/commit.rs:57-336`). Unsafe plan entries cannot reach
  `tree.join()` because lockfile keys are already validated.
- Host execution happens only for `ScriptRun::Host`, which
  `exec::authorize_scripts` returns only when the sandbox setting is off *and*
  the user answered `RunOnHostOnce` for that exact digest; flagged scripts are
  a hard denial in both modes (`policy.rs:42-59`, `exec/mod.rs:64-119`).

**pip (T-005, FR-005)**

- Input parsing regenerates the requirements text from parsed fields, so the
  resolver never sees user text; names, extras, specifiers and markers are
  character-restricted, which leaves no route to inject a new option or config
  directive (`pip/request.rs:54-75`, `:95-441`). Nested `-r`/`-c` must stay
  under the top-level file's directory, with depth, file-count and size caps
  (`pip/request.rs:16-19`).
- Ambient `PIP_*` variables and pip config files (user, global, site,
  `PIP_CONFIG_FILE`) are rejected when they name a different index, not
  honoured (`pip/interp.rs:276-331`); every pip invocation is
  `python -I -m pip --isolated --no-input` with a scrubbed environment
  (`pip/interp.rs:101-111`, `:155-158`).
- The wheel-only boundary holds: the loopback staging index is token-gated,
  lists only `.whl` files whose name parses, downloads and SHA-256-verifies
  each file itself, bounds its size, and withholds wheels whose `Requires-Dist`
  is a direct reference (`pip/proxy.rs:64-399`, `pip/index.rs`,
  `pip/wheel.rs:48-113`). sdists are never listed, so no build backend runs.
- The plan is built from pip's report mapped back to the staged, verified files,
  and a report hash that disagrees with the verified hash is `IntegrityFailure`
  (`pip/plan.rs:102-171`); user `--hash` pins are enforced
  (`pip/mod.rs:324-344`).
- Apply is one `--no-index --no-deps --require-hashes --only-binary=:all:
  --find-links <reviewed>` invocation per wheel, with the reviewed set re-hashed
  immediately before use and compared byte for byte
  (`pip/apply.rs:99-147`, `:193-233`).
- The network is closed before apply (`pip/mod.rs:204`), and the digest binds
  interpreter identity, tags, index, requested set and ordered wheel hashes
  (`pip/plan.rs:37-83`).

**Scanner (T-006, FR-006)**

- OSV batching validates that the response has exactly one result per query, so
  a short or reordered response becomes an incomplete scan rather than a panic
  or a silent clean (`scan/osv.rs:65-140`); the page loop is bounded. Advisory
  ids coming back from the network are charset-restricted before being placed
  in a URL path, and the endpoint must be `http(s)` without userinfo
  (`scan/osv.rs:44-62`, `:184-185`).
- Offline, timeout and lookup failure fall back to the cache, and a miss sets
  `complete = false` with an `IncompleteScan` finding rather than "no
  advisories" (`scan/mod.rs:139-146`, `:156-230`, `:299-315`). Stale cache data
  is reported as `StaleData` and marks the report incomplete.
- The cache is per-key hashed, atomic, TTL'd, byte-capped, evicted oldest-first,
  and a malformed entry is a miss (`scan/cache.rs`). No untrusted string reaches
  the filesystem.
- Force-push rules cover `--force`, `--force-with-lease`, `-f`, `--mirror`,
  `--delete`, `-d`, `+refspec` and `:refspec`, including `sh -c`/`node -e`
  wrappers and backslash continuations (`scan/rules.rs:66-193`); evidence is
  redacted and bounded; a hit is a `Deny`, and rule text is never executed.

**Sandbox and export (T-007a, FR-007)**

- The Linux policy unshares all namespaces, clears the environment, mounts only
  `/usr`, `/bin`, `/sbin`, `/lib*`, a curated `/etc` allowlist, a fresh `/proc`
  and a private `/dev`, and never `/run`, `/var/run`, the host home, the real
  checkout or a socket directory; `bindable` refuses `/`, `/home`, `/run`,
  `/tmp`, `/etc`, `/proc`, `/dev` and any ancestor of the home directory
  (`sandbox/linux.rs:36-59`, `:272-300`).
- The wrapper script rejects rather than degrades: a failed rlimit or `exec`
  exits 125 before the launch marker is written, and a missing marker means
  "nothing was launched". Limits are set inside the new user namespace so they
  count sandbox processes, and cgroup limits come from
  `systemd-run --user --scope` (`sandbox/linux.rs:65-84`).
- The probe verifies six namespaces, an rlimit or cgroup scope, home and `/run`
  invisibility, the root listing and a clean environment, and the backend
  refuses to launch anything when a mandatory control is missing
  (`sandbox/linux.rs:622-775`, `sandbox/mod.rs:34-48`). `bwrap` and `bash` are
  resolved from fixed trusted paths and must not be user-owned
  (`sandbox/linux.rs:31-34`).
- `JobSpec` arguments are passed as `argv` to `bwrap` after `--`, so package
  arguments cannot be read as sandbox options or as `systemd-run` properties,
  and the scope properties are built from numeric limits only; the systemd
  `--expand-environment=no` guard is present (`sandbox/linux.rs:405-425`).
  `--die-with-parent` and `--new-session` are applied, and the timeout kills the
  sandbox init PID, which takes the whole namespace with it.
- Export runs only after `Exited(0)`, canonicalises the source root, rejects
  absolute/`..`/empty export paths, `lstat`s every component, rejects symlinks,
  reparse points, sockets and devices, refuses to follow a link planted in the
  destination, caps size and entry count, opens with `create_new` and cleans up
  what it created (`sandbox/mod.rs:58-330`). `fail2commit run` requires
  isolation regardless of the toggle, stages a copy of the input without
  `.git`, copies a non-system program into a read-only tool dir, clears the
  environment and sanitises displayed output (`cmd/run.rs:33-380`).

## Not verified in this review (pending evidence)

- **Linux sandbox behaviour is reviewed statically only.** No Docker container
  and no WSL `bwrap` run was executed for this review, so the probe, the
  namespace and cgroup controls, the timeout kill of grandchildren and the
  export step are unexercised here.
  `docs/dev/verify/VERIFY-2026-11-08-sandbox-linux.md` claims they were run on the
  worker's branch (WSL Ubuntu plus a privileged `rust:1` container); that claim
  was not reproduced by this review.
- The repository's own suites (`npm_*`, `pip_*`, `scan_*`, `run_cli`,
  `sandbox_*`) were not re-run in full: the host was under load and this review
  prioritised the adversarial reproductions below. They are unverified here,
  not passed.
- The Windows AppContainer backend (T-007b) is out of scope for this candidate.
- No live registry, index or OSV endpoint was contacted; all fixture data was
  offline.
- The review finished within the usage budget; nothing was left unexamined for
  that reason.

## Verification evidence

All commands ran on Windows in this worktree
(`<workspace>\f2c-review-wave2`) with Cargo
`-j 2`, disposable temp state and no network beyond loopback fixtures.

| Command | Exit | Evidence |
|---|---:|---|
| `git rev-parse HEAD` | 0 | `3d924c1dfb1e8158ae44be2020811de08c7abee3`, the reviewed candidate. |
| `git diff --stat a147c12..HEAD` | 0 | 93 files, +15213/-94; matches the branch list in the assignment. |
| `cargo test -j 2 -p fail2commit --test review_wave2_pth` | 101 (expected) | `isolated_python_still_executes_target_pth_files` passed (the `python -I` premise holds); `reviewed_pip_install_runs_wheel_code_on_the_host` failed with "W2-001: the guarded install executed wheel code on the host". 1 passed, 1 failed. |
| `cargo test -j 2 -p fail2commit --test review_wave2_scan` | 101 (expected) | Control case passed; `nul_prefixed_referenced_script_is_reported_clean` and `script_file_beyond_the_scan_prefix_is_silently_ignored` failed with W2-003. 1 passed, 2 failed. |
| `cargo test -j 2 -p fail2commit --test review_wave2_scan --test review_wave2_pth --no-run` | 0 | Both reproduction binaries compile after formatting. |
| `rustfmt --edition 2021 --check crates/fail2commit/tests/review_wave2_pth.rs crates/fail2commit/tests/review_wave2_scan.rs` | 0 | Both reproductions are formatted. |
| `python .claude/hooks/trace_check.py` | 0 | Scaffold traceability check passed after the report was added. |

W2-002, W2-004, W2-005, W2-006, W2-007 and W2-008 are CONFIRMED or PLAUSIBLE by
code path only; each names the exact lines. The two findings that were testable
(W2-001, W2-003) have intentionally failing reproductions committed with this
report.
