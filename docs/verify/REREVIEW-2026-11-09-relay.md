# Re-review: authenticated single-use approval relay (CR-010)

Reviewer: independent (did not write the code). Base `8a05b17`; fix diff `3d3bdad..ee49077`.
Scope: `approval/{relay,mod,channels}.rs`, `cmd/{git,hook}.rs`, hook script in `git/integ.rs`.
Product code unchanged. Reproductions: `crates/fail2commit/tests/rereview_relay.rs` (each test passes while the weakness is present; a fix should invert it). Synthetic values only; no push or publish.

## Verdict: CR-010 fixes ER-001 and ER-002 as written, but the relay is not yet a safe boundary. NOT APPROVED until RR-001 is fixed.

The password-harvest hole is closed: no password or password-derived value crosses the relay. But the token is both the bearer capability and the HMAC key, and git hands it to every child. The single-use design then closes the listener, which lets a token holder take the port and answer the real hook with a valid MAC. That is a force-push approval and password bypass, not only a phishing prompt.

## Per-area status

| # | Area | Status |
|---|---|---|
| 1 | No password crosses the relay | PASS. The request carries no password. The reply is `{request_id, nonce, digest, decision, mac}`. The host runs the whole `approve_relayed`, including `verify_for_request`. The hook compares id, nonce, digest and MAC with `ct_eq`, joined by non-short-circuit `&` (`relay.rs:238-244`). The token is never sent. A wrong password only becomes Cancel (`relay.rs:194-199`). |
| 2 | Forged requests | FAIL (RR-001, RR-003). Requests are unbound to the push. |
| 3 | Single use, deadlines, caps | PARTIAL. One authenticated request, 2 s pre-auth, and close on drop all hold. Silent peers no longer block the real hook (one thread each). The 16-accept cap is a token-free kill switch (RR-002), and the listener close enables RR-001. |
| 4 | Token scoping | FAIL (RR-004). The hook binary and the script unset it correctly. Other git children still see it. |
| 5 | Only the hook is a client | PASS. The variable is read only at `cmd/hook.rs:38`. `Stdio::ask` no longer reads it (`channels.rs:173`). `git.rs:35` strips it for every git invocation. |
| 6 | Regressions | PASS (see commands). |

## Findings

| ID | Sev | Status | Where |
|---|---|---|---|
| RR-001 | High | CONFIRMED | `relay.rs:135,148,188-193` |
| RR-002 | Low | CONFIRMED | `relay.rs:33,135,138` |
| RR-003 | Medium | CONFIRMED | `approval/mod.rs:100-108`, `cmd/git.rs:74-84`, `relay.rs:184` |
| RR-004 | Medium | CONFIRMED | `cmd/git.rs:84` (env on the git child) |
| RR-005 | Info | CONFIRMED (read) | `docs/approval.md` |

### RR-001 (High, CONFIRMED): a token holder burns the slot, rebinds the port and impersonates the host
Scenario: a git sibling that inherited the variable (see RR-004: `core.sshCommand`, credential helper, `remote.<n>.receivepack` or a remote helper; all run before pre-push) sends one authenticated request that ends fast. Examples are `allowed: []`, which returns Cancel before any prompt (`mod.rs:121-125`), or a non-`Operation` kind (`mod.rs:100-104`). `used` becomes true, the accept loop exits and the listener drops (`relay.rs:135,148`). The attacker binds `127.0.0.1:<port>` (std sets no exclusive bind; on Unix it also sets SO_REUSEADDR) and waits. The real hook connects, sends its request, and gets a valid-MAC `ApproveOnce` from the impostor, who holds the key. No user prompt and no password check run. The hook trusts the reply because the MAC is the only thing it verifies.

Test: `rr001_token_holder_burns_the_slot_then_impersonates_the_host`. The host's decision function ran once, for the burn only, and the hook got `ApproveOnce` for a password-gated force push.

Fix:
- (a) Keep the listener bound until the `Relay` drops. After the slot is used, accept and close without serving, so the port cannot be rebound. On Windows set `SO_EXCLUSIVEADDRUSE`.
- (b) Bind the first request to the push (RR-003), so a sibling's request does not win the slot.
- (c) Stop treating an inherited string as proof of being the hook (RR-004). Use an inherited pipe or fd to the hook only, or a named pipe whose DACL and peer-pid check admit only the hook.

### RR-002 (Low, CONFIRMED): 16 connections without a token kill the relay
Any local process finds the ephemeral port and opens 16 connections. The loop exits after the 16th accept (`relay.rs:135-141`) and drops the listener. The real hook then gets connection refused and the push fails closed. This is a durable, token-free denial, and it also frees the port for RR-001. Test: `rr002_sixteen_tokenless_connections_kill_the_relay`.

Fix: do not count unauthenticated accepts toward a stop condition. Bound the concurrent pre-auth threads (for example 8, 1 s each), drop extras, and keep listening until the push ends or the slot is used.

### RR-003 (Medium, CONFIRMED): the host does not bind the request to the push it runs
`git.rs:74-84` knows the remote, refspecs and force reasons, but the closure passes any `Operation` request on. `approve_relayed` checks kind, expiry, replay and password enablement. It does not check the summary, details, remote, whether `password_required` is needed, `allowed`, or an upper bound on `expires_at`.

A token holder gets a prompt with attacker text in the user's client, for example "Session expired: re-enter your force-push password". The typed password is checked on the host and not returned, so nothing is harvested. The user is still phished, and wrong guesses may count against password limits. A far-future `expires_at` (`until_expiry`) holds the host's stdio reader and prompt open. The slot is lost, so the real push is cancelled. Test: `rr003_relay_forwards_any_operation_text_and_expiry_to_the_host`.

Fix: the host computes the expected context from its own argv (remote name and URL, force reasons). It rejects a request whose summary or details do not name that remote, or whose kind is not `git.push`. It clamps `expires_at` to now plus the default TTL. It rejects `password_required` unless the password is enabled and a force reason exists. It requires `allowed` to hold exactly the push decisions. A mismatch must not use the slot.

### RR-004 (Medium, CONFIRMED): the token reaches every git child, not only the hook
`cmd.env(relay::ENV, ..)` (`git.rs:84`) puts it in git's environment. Credential helpers, `core.sshCommand`, `remote.<n>.receivepack` and `uploadpack`, remote helpers, askpass, proxy commands and transport children all inherit it, and several run before the hook. Repository config and workspace files are untrusted per AGENTS.md.

The chained hook is covered by the script `unset` (`integ.rs:291`), and the ER-001 test passes. Test for the rest: `rr004_receive_pack_child_inherits_the_relay_token`. The wrapper recorded `127.0.0.1:<port>/<token>` and the push still succeeded.

`core.hooksPath` is forced to the fail2commit directory, which holds only `pre-push` (`integ.rs:347,396`). Git therefore runs no `reference-transaction` or `post-update` hook from there, and those are not leak paths. This script never runs a chained repo hook of those names.

Decision on whether the host should put the token only in the `git` child: it already does, and that is not sufficient, because git forwards it to all its children and env inheritance cannot tell the hook from them. Move the capability off the environment (inherited pipe or fd, or a per-push file with an ACL and a peer check). Or make a stolen token worthless through the RR-001(a) and RR-003 fixes.

### RR-005 (Info): doc says 128-bit token
`docs/approval.md` says the token is 128-bit. `random_hex32` gives 32 random bytes (256 bits). No security issue; fix the doc.

## Checked and sound
- HMAC matches RFC 4231 (unit test). The request and reply MACs cover different inputs, and the request MAC has a label.
- `serve` verifies the MAC before it parses the request or uses the slot. Bad JSON, a bad MAC or an oversized line never use the slot. `compare_exchange` makes the service exactly once.
- The hook rejects a non-loopback or IPv6 target, a reply with other fields, a wrong MAC, and a decision not in `allowed`. Everything else is Cancel.
- `Stdio::ask` ignores the variable; the `er002_*` npm approval test passes.
- `--approver none` is checked first in the hook and never reaches the relay.
- `password_required()` is called before git runs (`git.rs:71`), so the host records the password generation.

## Not covered / limits
- Linux was not run (Windows only). RR-001 and RR-002 are platform-independent logic. On Windows the port rebind after drop worked without retries.
- A Windows `SO_REUSEADDR` hijack of a live listener (binding the same port without closing it) was not tested. PLAUSIBLE; `SO_EXCLUSIVEADDRUSE` fixes it.
- Same-user environment reads (`/proc/<pid>/environ`) are out of scope.

## Commands

| Command | Exit |
|---|---|
| `git diff 3d3bdad..ee49077 --stat` | 0 |
| `cargo test -j 2 -p fail2commit --test review_e2e_relay --test e2e_push --test e2e_npm_approval --test approval_cli --test approval_stdio --test git_push` with empty stdin (7 + 5 + 4 + 5 + 8 + 13 tests, all passed) | 0 |
| `cargo test -j 2 -p fail2commit --test rereview_relay` with empty stdin (4 passed, 69.6 s) | 0 |

Tested SHA: the commit that adds this report on top of `8a05b17` (`git rev-parse HEAD`).
