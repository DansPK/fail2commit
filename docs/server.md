# Protected remote updates (FR-003, SPEC-003)

`fail2commit server` protects selected refs of a self-hosted Git repository.
The client-side guard can be skipped (`--no-verify`, a different Git, another
machine), so enforcement lives in the server's `pre-receive` hook.

## Components

| Command | Runs as | Purpose |
|---|---|---|
| `fail2commit server install <bare repo> --state <dir> [--protect <ref>]...` | maintainer | Writes `hooks/pre-receive`, creates `server.toml` if missing, sets `receive.advertisePushOptions=true`. Refuses to overwrite a foreign hook. |
| `fail2commit server pre-receive [--state <dir>]` | Git (hook) | Reads every `<old> <new> <ref>` tuple (max 1 MiB / 4096 updates) and allows or denies the whole push. |
| `fail2commit server approve --repo <bare> --actor <name> --update REF:OLD:NEW... [--ttl s]` | maintainer | Mints a one-time token and prints it once on stdout (`--json`: `data.token`). |

`--state <dir>` selects the server home; otherwise `FAIL2COMMIT_SERVER_HOME`.
The path must be absolute, outside the repository, and (Unix) not group- or
world-writable.

## Server home (trusted state)

```
<state>/server.toml     policy, written by the maintainer
<state>/approvals.json  token verifiers (SHA-256) with expiry, rewritten atomically
<state>/approvals.json.lock
```

`server.toml`:

```toml
protected_refs = ["refs/heads/main", "refs/heads/release/*"]  # exact, or prefix ending in *
secret_policy = false        # true: protected-ref pushes must pass the outgoing secret scan
max_token_ttl_secs = 900     # upper bound for `approve --ttl`
```

**Permissions.** Create the directory as the Git service account with mode
`0700` (the hook runs as that account and must write `approvals.json`).
Developers must have no shell, file or `sudo` access as that account, only
Git over SSH/HTTP (for SSH use `git-shell` or a forced command). Maintainers
run `approve` as the same account (`sudo -u git fail2commit server approve ...`)
or share it through a restricted group with a `0770` directory; the group must
contain no developers. Never place the state under the repository or under any
path a push can write to. A missing or malformed `server.toml` denies every
push (fail closed).

## Decision rules

For updates to protected refs only (other refs always pass):

- Creation and fast-forward pass without approval.
- Non-fast-forward updates, deletions and moves of an existing tag need
  approval. Ancestry is `git merge-base --is-ancestor old new` run in the
  hook's environment, so objects still in Git's quarantine
  (`GIT_QUARANTINE_PATH`, alternate object dirs) are visible. Missing objects
  or a non-commit target cannot be classified and are denied outright.
- With `secret_policy = true` every non-deletion update runs through
  `git::scan_outgoing`. Any finding, or a scan that fails or is unavailable,
  denies; this is never approvable. Messages carry redacted evidence only.

## Approval tokens

1. The maintainer runs `approve` with the exact update set the developer will
   push: `--update refs/heads/main:<old full oid>:<new full oid>` (repeat for
   multi-ref pushes). The token is opaque, 256-bit random, bound to the
   repository ID, the authenticated actor and the SHA-256 `Digest` over the
   sorted `(ref, old, new)` set. Only its SHA-256 verifier is stored.
2. The developer pushes with the token as a push option:
   `git push --force -o f2c-approval=<token> origin main`.
3. The hook consumes the token under an exclusive lock with an atomic
   rewrite, so two concurrent pushes cannot both use it. A token that is
   presented is burned even when its binding does not match, and consumption
   happens before Git applies the update: a push that then fails needs fresh
   approval. Expired tokens are purged.

Missing push options, an unadvertised option, more than one
`f2c-approval=` option, no actor, or any mismatch deny the rewrite.

Repository ID: first 32 hex characters of `Digest("server.repo", canonical git dir path)`.
Moving the repository requires re-issuing approvals.

## Actor mapping

The hook trusts `FAIL2COMMIT_ACTOR` from its environment (letters, digits,
`._@+-`, up to 128 chars); the transport must set it from the authenticated
identity and developers must not be able to choose it:

- SSH: a per-key forced command in `authorized_keys`,
  `command="env FAIL2COMMIT_ACTOR=alice git-shell -c \"$SSH_ORIGINAL_COMMAND\"",restrict ssh-ed25519 ...`
  (or a wrapper script doing the same).
- HTTP (`git http-backend`): set it from `REMOTE_USER` in the web server
  configuration (e.g. `SetEnv`/`fastcgi_param FAIL2COMMIT_ACTOR $remote_user`),
  never from a client header.
- Tests: the Rust tests set `FAIL2COMMIT_ACTOR` on the `git push` process; a
  `file://` push passes its environment to `git receive-pack` and the hook.

## Installing on a server

```sh
git init --bare /srv/git/app.git
fail2commit server install /srv/git/app.git --state /var/lib/fail2commit-server --protect refs/heads/main
```

The installed hook is a two-line `sh` script that sets `FAIL2COMMIT_HOME`
below the state directory (so the hook never reads a real user home) and
`exec`s the absolute path of the `fail2commit` binary that ran `install`.

## GitHub (hosted alternative)

GitHub-hosted repositories cannot run this hook. Use repository rulesets (or
branch protection) on the selected refs: block force pushes and deletions,
require pull requests, and restrict the bypass list to maintainers. A GitHub
App or automated hosted approval service is outside this MVP.
