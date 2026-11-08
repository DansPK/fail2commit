# Approval and force-push password (FR-002, SPEC-002)

Code: `crates/fail2commit-core/src/approval/`, CLI `crates/fail2commit/src/cmd/password.rs`.
Tests: `approval/tests.rs` (unit), `crates/fail2commit/tests/approval_*.rs` (child-process, stdio and pty).

## What approval protects

A guarded command (git push, npm/pip install, host execution) that finds something needing consent builds an `ApprovalRequest` with `approver::new_request`. The request is bound to:

- the operation **digest**: canonical SHA-256 of every security-relevant input, e.g. all ref tuples `(ref, old, new)` of a multi-ref push;
- a 256-bit **nonce** and a request id;
- the originating **session** (random per CLI process);
- an **expiry** (`[approval] request_ttl_secs`, default 300 s);
- the **decisions offered** (`allowed`). Cancel is always the default.

`approval::approve(ctx, req)` is the only way to get a decision. It returns `Cancel` or an offered decision. When no channel can be reached it returns `ApprovalUnavailable` (exit 11). It never assumes approval.

## Policy order in `approve`

1. Refuse if a `FAIL2COMMIT_*PASSWORD*`, `*RECOVERY*`, `*PASSPHRASE*` or `*SECRET*` variable is set. The value is never read.
2. Reject a request with an unknown version, from another session, already expired, or with a nonce already consumed. A request with no non-cancel decision returns Cancel without prompting.
3. If `req.password_required`, a password must be set. The password-state **generation** is captured. If this process observed an older generation when it called `password_required()` (that is, when the request was built), the request is rejected.
4. A request id is presented at most once per process.
5. Ask the channel. `ApprovalUnavailable` propagates. Any other channel failure, EOF, empty or unknown input, an oversized line or a timeout at `expires_at` is Cancel.
6. `approver::validate_response` checks version, request id, nonce, digest (so a changed operation is "operation changed"), expiry, that the decision was offered, and that a password is present when one is required. Any mismatch is `Rejected`.
7. The nonce is recorded as consumed (also for Cancel), under a lock, in `state_dir/approvals/consumed.json` until expiry. A second reply, including from another process such as a tray answering twice, is rejected.
8. For a non-cancel decision with `password_required`, the password is verified with rate limiting, and the state generation must still equal the captured one. A reset or change while the prompt is open invalidates it.

## Channels (`--approver`)

| Choice | Behaviour |
|---|---|
| `auto` (default) | `ipc::tray_approver()` if a tray answers (T-009); else the terminal if an interactive console exists; else `ApprovalUnavailable`. |
| `terminal` | Renders summary, details and findings on `/dev/tty` or `CONOUT$`, and reads the decision and the hidden password from `/dev/tty` or `CONIN$`. It never reads stdin, which carries Git hook tuples. Without a console: `ApprovalUnavailable`. |
| `tray` | `ApprovalUnavailable` when no tray is running. |
| `stdio` | Used by `fail2commit api` (VS Code). It writes one `ServerMessage::ApprovalRequest` JSON line to stdout and flushes, then reads one `ClientMessage` line from stdin, bounded by `MAX_MESSAGE_BYTES`. `cancel` or EOF means Cancel. An API request cannot choose its approver. |
| `none` | Unattended. Anything needing approval fails closed. |

The terminal prompt accepts only the exact keyword: `approve` for ApproveOnce, `run-on-host` for RunOnHostOnce. Anything else, including `y` or an empty line, cancels. All untrusted text (ref names, package names, evidence) passes through `console::sanitize`. Control and bidi characters are escaped so a ref name cannot repaint the prompt with terminal escapes, and URL credentials are stripped.


## Git hook relay under `api` (CR-010)

Git gives the pre-push hook its own stdin and moves its stdout, so the hook cannot speak the stdio protocol. When `fail2commit --approver stdio git push` runs (the `api` path), that process, the relay host, listens on `127.0.0.1:<ephemeral>` and puts `FAIL2COMMIT_APPROVAL_RELAY=127.0.0.1:<port>/<token>` in git's environment. The 128-bit token is the HMAC key and is never sent on the wire.

- **Host approves, not the hook.** The hook sends its `ApprovalRequest` and an HMAC-SHA-256 of it. The host runs the whole `approval::approve` itself (`approve_relayed`): stdio round trip to the api client, reply validation, replay, rate limits and the password check against trusted state. The session id is the hook's, and only `Operation` requests are relayed. A typed password therefore never crosses the relay.
- **The reply** is only `{request_id, nonce, digest, decision}` plus `HMAC-SHA-256(token, request_id || nonce || digest || decision)`. The hook compares with constant-time equality, requires the fields to equal its own request and the decision to be offered, and treats everything else (no relay, bad MAC, timeout, EOF) as Cancel. The host prints the reason for a refusal (wrong password, changed operation) on its stderr.
- **Single use, bounded.** The relay accepts exactly one authenticated request, then stops listening. A connection gets 2 s to send an authenticated line; an unauthenticated or malformed one is dropped without using the slot. After 16 accepted connections the relay stops. It also stops when the push ends.
- **Token scope.** Only `fail2commit hook pre-push` reads the variable and it removes it from its own environment at once. The installed hook script runs `unset FAIL2COMMIT_APPROVAL_RELAY` before it chains the prior hook, so the repository's or the user's earlier hook and any other child see nothing.
- **Only the hook is a relay client.** The generic `stdio` approver used by `api` for npm, pip, sandbox and the rest ignores the variable.

## Force-push password

`fail2commit password set|change|reset|disable|status|verify`

- **Input.** Passwords and recovery codes come only from hidden console input (`rpassword` on the console device). Any extra argument is refused with a usage error that does not echo it, as is a secret-looking environment variable. `set`, `change`, `reset` and `disable` without a console fail with `ApprovalUnavailable`.
- **Set.** Asks for the new password twice (at least 8 characters, at most 1024 bytes, no control characters). Generates a recovery code and shows it **once on the console only**, never on stdout, stderr or `--json`.
- **Change / disable.** Require the current password. Change keeps the recovery code. Disable removes both verifiers.
- **Reset.** Requires the recovery code. Sets a new password and **rotates** the recovery code, so the old one stops working.
- **Generation.** Every set, change, reset and disable bumps it, which invalidates pending and earlier-minted password approvals.
- **Status.** Shows enabled, generation, failed attempts, remaining lockout and KDF parameters. It never shows secrets.
- **Verify.** Runs a password-protected self-test approval through the selected channel. It is useful for checking the password and the approver, and the tests use it.

### Storage: `state_dir/password.json`

- Argon2id (RustCrypto `argon2` 0.6), version 0x13, **m = 19456 KiB, t = 2, p = 1, 32-byte output**. These are the OWASP minimum recommendation for Argon2id, and they are recorded per verifier in the file. Recorded parameters are bounds-checked on load, so a damaged file fails closed instead of allocating unbounded memory.
- A random 16-byte salt per verifier. The comparison is constant time (`digest::ct_eq`).
- The recovery code has 160 bits from the OS CSPRNG, as 32 Crockford base32 characters in 8 dash-separated groups of 4. Only an Argon2id verifier of the normalized code is stored. Input is case-insensitive, separators are ignored, and `O`→`0` and `I`/`L`→`1`.
- Writes use `fsutil::atomic_write` (temp file, fsync, rename) under `fsutil::with_lock`, so concurrent processes serialize. A malformed or unknown-version file fails closed (`InvalidInput`).
- On Unix the directory is 0700 and the file is 0600. On Windows the file inherits the per-user `%LOCALAPPDATA%` DACL.
- Secrets in memory are wrapped in `Zeroizing`. `ApprovalResponse` zeroizes its password on drop, and stdio input buffers are zeroized.

### Rate limiting

The failure counter and lockout deadline are stored in `password.json` and updated under the lock **before** the error is returned, so killing the process cannot reset them and parallel attempts cannot lose updates. Approval, change, disable and reset share the counter.

| Setting | Value |
|---|---|
| Free attempts | 3 |
| Lockout after the 3rd failure | 30 s |
| Each further failure | doubles the lockout, capped at 1 h |
| A success | clears the counter |
| While locked | even the correct secret is refused |

Cancels never count as failures.

## Threat model

| Threat | Mitigation |
|---|---|
| Repo content, ref names or package metadata trick the prompt | Sanitized rendering. Policy decisions are in Rust. The prompt shows only redacted evidence. |
| An approval meant for operation A is used for B, or for a changed ref set | Digest binding through `validate_response`. Different tuples give a different digest. |
| Replayed reply (second tray answer, captured line) | Per-process "asked once" set, plus a persisted consumed-nonce store with expiry under a lock. |
| Stale approval after password reset or change | The generation is captured when the request is built (`password_required`) and checked again at verification. |
| Online guessing of the password or recovery code | Argon2id cost, persisted exponential backoff, serialized attempts, and a 160-bit recovery code. |
| Offline cracking of a stolen state file | Argon2id memory-hard hash with a per-verifier salt. No plaintext is stored. |
| Secrets in argv, env, logs or `--json` | They are hidden-input only. Argument and environment attempts are refused without echo. The recovery code goes to the console device only. Debug output of secret types is redacted. |
| Unattended or headless runs | `none`, non-TTY, closed tray and a gone stdio client are all `ApprovalUnavailable` or Cancel, never approval. |
| Hook stdin confusion | The terminal channel reads the console device, not stdin. |

Out of scope: a process already running as the same user can read the user's console and state, or set `FAIL2COMMIT_HOME`. The password raises the bar for accidental or agent-driven force pushes. It does not stop a same-user attacker. Protected refs across clients are enforced remotely (FR-003).

## Known limits

- A timed-out prompt leaves its reader thread blocked until the process exits. The CLI is short-lived. On Unix, a password prompt that times out may leave the terminal with echo off until the shell resets it.
- `password` takes its action as the only argument, so global flags must come before it: `fail2commit --json password status`.
- On Windows there is no explicit DACL tightening beyond what `%LOCALAPPDATA%` inherits. A `FAIL2COMMIT_HOME` in a shared directory is the operator's choice.
