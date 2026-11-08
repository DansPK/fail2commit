# End-to-end tests

`crates/fail2commit/tests/e2e_*.rs` run the built `fail2commit` binary (path `F2C_BIN`, else the cargo-built one) in disposable worlds: a temp `HOME`/`USERPROFILE`, `FAIL2COMMIT_HOME`, global Git config and PATH target (`FAIL2COMMIT_PATH_TARGET`), disposable bare remotes, an offline loopback npm registry and an offline OSV stub (the trusted `advisories.osv_url` setting). Passwords and secrets are built at runtime and never printed. Helpers: `tests/e2e_support/`.

| File | Proves |
|---|---|
| `e2e_npm_sandbox.rs` | `npm install` runs a lifecycle script in the real sandbox (AppContainer / bubblewrap) from a CR-007 job stage; the build artifact lands in `node_modules`; a hostile script cannot read a home canary, list the checkout, write outside, or reach a loopback listener; sandbox off: a required script (`node-gyp`) fails closed without an approver (exit 11, nothing changed), a cancelled host approval changes nothing, an approved one runs once; an optional script is skipped. Linux only: a C compile with the system `cc`. |
| `e2e_npm_approval.rs` | An advisory finding asks on the `api` stdio channel; approve installs exactly the approved digest; cancel and a changed digest change nothing; `--approver none` exits 11. |
| `e2e_push.rs` | `api` plus a forced push to a bare remote with a configured password: approve, wrong password, cancel, changed tuple, unattended (CR-009 relay). |
| `e2e_setup.rs` | `setup` (twice) over a third-party global `core.hooksPath`; a push runs the installed hook and chains the prior hook; a secret push is blocked; `uninstall-integrations` restores git config, hook and profile byte for byte. |
| `extensions/vscode/test/real-cli.test.ts` | `runApi` against the real CLI (`F2C_BIN`; skipped when absent): `status`, and one `approval_request` answered with cancel on a real forced push. |

## Staged toolchain

Sandboxed lifecycle jobs get, read-only, inside the npm stage: the host `node` binary, a copy of the npm tree and, on Windows, `cmd.exe`. The "native build" is a staged node script writing a build artifact (Windows and Linux); Linux also compiles C with the system `cc` when `/usr/bin/cc` exists (otherwise the test prints SKIPPED, which is pending evidence; `F2C_REQUIRE_NATIVE_BUILD=1` makes it fail instead). No MinGW toolchain is staged on Windows.

## Running

```
cargo test -j 2 -p fail2commit --test e2e_npm_sandbox --test e2e_npm_approval --test e2e_push --test e2e_setup
F2C_BIN=<path to fail2commit> npm test      # in extensions/vscode
powershell -File scripts/linux/test.ps1 -Stage container,wsl -Filter '^e2e_'   # Linux, needs node in WSL
```

`fail2commit setup` takes about 10 s per call (pip/npm integration probing), so setup-based tests are slow.
