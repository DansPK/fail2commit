# Architecture

## Stack and ownership

| Area | Implementation |
|---|---|
| Shared logic | `crates/fail2commit-core` with Rust types, policy and decision contracts. Use clap in the CLI, serde and serde_json for messages, TOML for trusted user settings, and ureq with rustls for HTTPS. |
| CLI and adapters | `crates/fail2commit` with Git, npm, pip, setup, secret scan, hook and server subcommands. Invoke installed tools with structured arguments and bounded I/O. Resolve real executables outside shims to avoid recursion. |
| Sandbox | Windows `sandboxrs-windows` AppContainer backend, reviewed and pinned to an exact revision if unavailable from crates.io. Linux Bubblewrap. See SPEC-007. |
| Windows UI | `crates/fail2commit-tray` using windows-sys, native Win32 notifications and dialogs, local named pipe and NSIS packaging. |
| VS Code | TypeScript extension using the workspace-side CLI, @vscode/vsce packaging, JSON protocol. |
| Delivery | GitHub Actions, NSIS, cargo-deb, source tarball and VSIX. Apache-2.0 for new product code, inherited template notices retained. |

## Contract to freeze in CHORE-001

Version the JSON request and result. A finding includes kind, action, source, redacted evidence, affected ref or package, and optional advisory ID. Use stable machine-readable codes for success, rejected/canceled, approval unavailable, incomplete scan, integrity failure, isolation unavailable, invalid input, and internal error. Carry operation digest and a nonce through approvals. Canonicalize consistently before hashing. Include effective config, target and ordered immutable inputs in install identity. Windows and VS Code use the same policy engine as the terminal. Expose commands for setup, status, uninstall-integrations, sandbox on/off/status, password set/change/reset, guarded package commands, explicit isolated run, and private hook entry points.

## Trust boundaries

- Trusted policy, credential hashes, setup state and approval decisions live under per-user OS data directories with private permissions. Repository data can provide input and stricter restrictions. It cannot authorize an override.
- The resolver, scanner and apply phases keep package code separate. Any untrusted code that must execute runs only after policy approval under a verified sandbox, or after explicit host consent with sandboxing disabled. Repo-defined tool paths, npm config and pip index/requirement directives are untrusted.
- The Windows tray is per-user and event-driven. It presents prompts. The CLI owns decisions and revalidation. Sandbox processes cannot access approval IPC.
- Local hooks and shims cover participating clients. The remote receive policy is the authority for protected refs across clients. Self-hosted remote approval uses a separate trusted issuer. GitHub uses configured rulesets.
- Exported build files remain untrusted. Subsequent execution is isolated only through `fail2commit run` or other explicitly integrated flows.
