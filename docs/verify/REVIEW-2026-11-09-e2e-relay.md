# Independent review: approval relay (CR-009) and e2e glue

Reviewer: independent (did not write the code). Base: `1f6861a` (diff `f240623..1f6861a`).
Scope: `approval/relay.rs`, `approval/channels.rs`, `cmd/{git,hook,run}.rs`, `npm/stage.rs`, `npm/apply.rs` (`run_scripts`, `lifecycle_env`), `npm/mod.rs` staging, e2e tests.
Product code was not changed. Reproductions: `crates/fail2commit/tests/review_e2e_relay.rs` (each test passes while the weakness is present; a fix should invert it).

## Findings

| ID | Severity | Status | Where |
|---|---|---|---|
| ER-001 | High | CONFIRMED | `cmd/git.rs:64-72`, `git/integ.rs:279-303` (hook script), `approval/relay.rs:66-100` |
| ER-002 | High | CONFIRMED | `approval/channels.rs:171-181` (`Stdio::ask`), `approval/relay.rs:21,104-125` |
| ER-003 | Low | CONFIRMED | `approval/relay.rs:36-46,66-75` |
| ER-004 | Low | CONFIRMED (read) | `cmd/git.rs:64-72`, `cmd/hook.rs:37-42` |
| ER-005 | Low | PLAUSIBLE | `npm/mod.rs:222-224`, `npm/apply.rs:437-440` |
| ER-006 | Low | PLAUSIBLE | `npm/apply.rs:404-412`, `npm/mod.rs:470-476` |
| ER-007 | Info | CONFIRMED (read) | `tests/e2e_npm_sandbox.rs:107-113`, `e2e_support/npm_world.rs:86-93` |

### ER-001 (High, CONFIRMED): chained hooks and git's other children inherit the relay token; it is a phishing channel and not single-use
`fail2commit git push` puts `FAIL2COMMIT_APPROVAL_RELAY=127.0.0.1:<port>/<token>` in git's environment (`git.rs:64-72`). The installed `pre-push` script runs the fail2commit hook and then runs the chained hook (the repository's `.git/hooks/pre-push`, or the user's prior global one) with the same environment (`integ.rs:296-300`). The repository hook is workspace content, which AGENTS.md says to treat as untrusted. The relay accepts any request from a holder of the token, does not check `kind`, `session`, `digest` or `password_required`, and forwards it to the user's approval client. The client's reply, including a typed password, goes back to the caller. The relay is not single-use: it keeps serving until `fail2commit git push` returns.

Scenario: a cloned repo has `.git/hooks/pre-push` (or the hook directory the user pointed at). The user force-pushes with VS Code. The user approves the real prompt. The chained hook reads the variable and sends a request with `password_required: true` and the summary "session expired, re-enter your password". The VS Code client shows it, the user types the force-push password, and the hook gets it. The same value serves any number of requests.

Reproduction: `er001_chained_hook_can_phish_through_the_relay`. The chained hook records the variable. The test then plays the attacker twice, the client shows both forgeries, and the typed password is returned both times. The legitimate force push still succeeds.

The hook-side checks (nonce, digest, expiry, password verification) do hold, so the relay cannot approve the hook's own operation. The harm is the forged prompt and password disclosure.

Fix:
1. Do not pass the capability through the environment to everything. Hand it to the hook over an inherited pipe or handle, or at least make the token single-use. Serve exactly one request and then close and unlink the listener, so a later holder gets nothing. The fail2commit hook runs first in the chain.
2. Have the hook script and `hook pre-push` run `unset FAIL2COMMIT_APPROVAL_RELAY` before chaining.
3. Relay-side, require the forwarded request to carry the digest the hook will expect, for example by binding the token to the request digest with an HMAC. Also reject `password_required` unless the relay was started for a push that needs it.

### ER-002 (High, CONFIRMED): any `--approver stdio` process honors the relay variable; the env var diverts approvals away from the client
`Stdio::ask` reads `FAIL2COMMIT_APPROVAL_RELAY` unconditionally (`channels.rs:171-181`). It is not limited to the Git hook. `git.rs` removes the variable only for the git child. `api.rs` and the npm, pip and run paths do not. If the variable is in the environment of `fail2commit api` (a shell, direnv or `.envrc`, `terminal.integrated.env`, an editor launched from such a shell), every approval request (npm advisory, `RunOnHostOnce`, pip, push) goes to whatever listens on that loopback port, which then answers with a valid nonce and digest. The api client never sees the request, and the hook-side validation passes because the attacker is the "client". Only password-gated requests are protected, by the password.

Reproduction: `er002_relay_env_diverts_an_npm_approval_away_from_the_api_client`. A listener on a loopback port approves an npm advisory install. The `api` client is never asked (`finish()` panics on any approval request) and the install completes.

The same applies to the hook. A plain `git push` through the global hook with the variable set sends the prompt to the listener instead of the terminal or tray, because `hook.rs:40-42` forces `ApproverChoice::Stdio` whenever the variable is non-empty.

Fix: read the relay target only in `hook pre-push` and only when the process is a hook child. Pass it as an inherited fd or handle, or validate a per-push secret that the parent also holds. Do not read it in `Stdio::ask`. Remove the variable in `api::route` and for every non-hook command.

### ER-003 (Low, CONFIRMED): the relay serves one connection at a time with a 10 s read timeout, so any local peer can stall it
The accept loop calls `serve` inline (`relay.rs:39`), and `serve` waits up to 10 s on a silent peer (`:68`). Any process on loopback, including another user's, can keep the hook's request waiting. The hook waits for `left + 5` s and then cancels, so this fails closed (a denial of service on the push, not a bypass). Loopback ports are reachable by other local users on a multi-user host.

Reproduction: `er003_a_silent_loopback_peer_stalls_the_relay`. Control: a bad request is dropped in under 2 s; behind a silent peer it waits more than 8 s.

Fix: handle each connection on its own thread with a short pre-auth timeout (about 1 s for the token line). Accept at most one authenticated forward.

### ER-004 (Low, CONFIRMED by reading): the caller's approver choice reaches the hook only for `none` and `stdio`
`git.rs:64-72` propagates `none` (fail closed) and `stdio` (relay). With `--approver terminal` or `--approver tray`, the hook process starts with the default `Auto`. It picks the tray before the console, so `--approver terminal git push` can pop a tray prompt. This is not a downgrade to a non-interactive channel, but it is not the caller's choice either. The `--approver none` path itself is sound: `FAIL_CLOSED_ENV` is checked first in `hook.rs:37`, it is set whenever the CLI says `none`, it can only tighten, and the relay variable is removed (`git.rs:35`). If `relay::start()` fails, the push is aborted before git runs.

Fix: propagate `terminal` and `tray` too, for example through a `FAIL2COMMIT_HOOK_APPROVER` value that only tightens.

### ER-005 (Low, PLAUSIBLE): npm job stages leak on abnormal exit or failed cleanup
The npm stage is a `tempfile::TempDir` (`npm/mod.rs:222-224`) that is removed on drop. A kill or crash during a lifecycle script skips the drop. A failed removal after sandbox code left read-only entries or AppContainer-owned files is silently ignored. `cmd/run.rs` has `make_writable` fallback code and `npm` does not. Each stage holds a copy of node and the npm tree, so tens to hundreds of MB. I found no sweeper of stale `sandbox-stage/*`. Not run, because forcing it needs a kill at a precise point.

Also, `Tools::create` copies node and npm every time `run_scripts` is called with `Sandboxed`, even when `lifecycle()` is empty (`apply.rs:437-440`). That is wasted I/O under NFR-012.

Fix: sweep `sandbox-stage/npm-*` and `run-*` older than a day under the sandbox-job lock; create `Tools` lazily when the first script runs; reuse `make_writable` on drop.

### ER-006 (Low, PLAUSIBLE): the `--preserve-symlinks` comment is too strong; no re-check of links after scripts
`NODE_OPTIONS=--preserve-symlinks --preserve-symlinks-main` (Windows lifecycle jobs only) changes how node resolves modules (by the path as written, not the realpath). It does not widen what a package can read: the AppContainer ACL, not node, bounds reads, and the grants are limited to the staged read-only roots plus `proj`. At review time the tree has no links (`deny_links`, `workspaces` and `link: true` are refused), so resolution matches the reviewed files. The comment "npm on Windows creates no symlinks" is true only because of those refusals. A lifecycle script can create a junction in its writable tree. There is no link check between `run_scripts` and `move_tree`/`commit` (`mod.rs:470-476`), so such a link would be moved into the project's `node_modules`. With `--preserve-symlinks`, a junction-loaded module is also loaded under a second identity inside the stage. This is not reachable outside the stage by ACL, and a package can already write arbitrary JS into `node_modules`, so the added risk is low. Not reproduced (an AppContainer may be unable to create junctions).

Fix: run `deny_links` (junction-aware) on `proj/node_modules` after the scripts, before `move_tree`. Correct the comment.

### ER-007 (Info, CONFIRMED by reading): weak negatives in the e2e tests
In `hostile_script_cannot_reach_network_home_or_checkout`, "blocked" means any error text starting with `blocked:`. `ENOENT` or a bad path would pass. There is no control showing the same script reads the canary, lists the checkout and connects when unsandboxed, and the TCP "blocked:timeout" also counts. Positives that do exist: the script ran (it wrote `report.json` in a `sandbox-stage` cwd) and `scripts == "Sandboxed"`. `stage_leftovers()` returns an empty list if `read_dir` fails (`unwrap_or_default`), though the first test shows the directory exists. `e2e_push` has no test that the relay token is required, that the relay is closed after the push, or that the variable does not reach chained hooks; ER-001 and ER-002 are those gaps.

Fix: require `blocked:EACCES|EPERM|ENOENT-with-existing-path` via an existence check, add a host-side control run of the same script, and add tests that invert ER-001 to ER-003.

## Checked and sound

- **Hook-side validation.** `approve_with` checks version, session, expiry, replay file, password generation, per-process "asked once", then `validate_response` (request id, nonce, digest, expiry, offered decision, non-empty password) and `verify_for_request`. A relay client cannot make the hook approve a different operation or skip the password. The relay path goes through the same function as every other channel.
- **Fail closed.** `relay::ask` returns `None` (Cancel) for a bad address, a non-loopback address, connect error, EOF, malformed or oversized reply, and timeout. The relay `serve` drops on bad JSON, bad token or an oversized line. `Stdio::ask` maps all of that to Cancel. The api client being gone is `approval_unavailable`.
- **Bounds.** Both directions use `MAX_MESSAGE_BYTES + 1` line limits; the hook waits no longer than `expires_at - now + 5`; the connect timeout is 5 s; the token comparison is constant time and 128-bit.
- **Binding.** `127.0.0.1` only, ephemeral port, non-blocking accept; the hook side refuses a non-loopback or IPv6 target. The thread stops within about 10 ms of drop. The zombie stdin reader noted in the `until_expiry` comment is harmless here because `fail2commit api` serves one request per process.
- **`--approver none`.** See ER-004. `FAIL2COMMIT_HOOK_FAIL_CLOSED` is evaluated before the relay variable.
- **CR-007 stages.** Both the npm stage (`sandbox-stage/npm-*`, random name) and the `run` stage (`run-<pid>-<nanos>-<n>`) are direct children of the root. The Windows backend requires `work_dir` and every `read_only` root to be under one first-level stage, walks the whole stage for reparse points and multi-link files before any grant, and grants only the read-only roots and `proj` (not `home`, `cache`, `tarballs` or the staged npmrc). Names are unique per job, so concurrent jobs do not reuse a stage. `run_job` takes the per-user `sandbox-job` lock for each job, the npm lock is taken outside it, and no path takes them in the other order. Windows revoke state lives in the stage root under that lock. Cleanup runs on every error path through `TempDir`/`Stage` drop (see ER-005 for abnormal exit). `run` on Windows now copies `cmd.exe` into the stage and grants nothing in place.
- **`Tools::create` copy.** Symlink-aware (`symlink_metadata`), refuses special files and (on Windows) any link or junction, and refuses an npm-cli outside the npm root.
- **NODE_OPTIONS scope.** `#[cfg(windows)]`, set in the explicit job environment only, not for host runs or Linux.

## Commands

| Command | Exit |
|---|---|
| `git diff --stat f240623..1f6861a` | 0 |
| `cargo test -j 2 -p fail2commit --test review_e2e_relay` (Windows, 3 tests, all passed, 20.4 s) at the tested SHA below | 0 |

Linux (`f2c-linux-test:1`, `scripts/linux/test.ps1`) was not run. ER-001 to ER-003 are platform independent logic, but the Linux run is pending evidence. ER-005 and ER-006 were not run.

Tested SHA: the commit that adds this report on top of `1f6861a` (`git rev-parse HEAD` after the commit).
