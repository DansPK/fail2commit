# fail2commit on macOS

fail2commit is available on macOS Apple Silicon (`aarch64-apple-darwin`).

## Capabilities

On macOS, fail2commit provides:
- **Git push guard**: Outgoing commits are scanned for secrets, and forced pushes, history rewrites, and tag replacements require explicit approval.
- **Dependency & code scanning**: Scans dependencies against OSV and runs static heuristic scans on package code without executing it.
- **Approval workflows**: Interactive approval prompts on the terminal.
- **Package manager shims**: `npm` and `pip` shims that inspect plans and run installs offline without install scripts.

## Limitations & Fail-Closed Behavior

> [!IMPORTANT]
> **No Sandbox Backend on macOS Yet**
> macOS does not yet have an active sandbox backend implementation. A Seatbelt-based sandbox backend is planned under roadmap item **P-211**.
> 
> Because fail2commit adheres strictly to a **fail-closed** security model:
> - Fail-closed holds while `sandbox.enabled = true` (the default). With the sandbox enabled, any package that has install/lifecycle scripts is denied (refused rather than running untrusted code unsandboxed), as is `fail2commit run`.
> - Running `fail2commit sandbox status` reports the backend as `unavailable` with the reason: `no sandbox backend on macOS yet`.
> - Turning the sandbox off (`sandbox.enabled = false` in settings) allows "Run on host once" approvals that run approved scripts on the host with full user access, while optional scripts are skipped without asking.

## Installation

Download `fail2commit-<version>-aarch64-apple-darwin.tar.gz` and `fail2commit-<version>-aarch64-apple-darwin.tar.gz.sha256` from GitHub Releases.

1. Verify checksum:
   ```sh
   shasum -a 256 -c fail2commit-<version>-aarch64-apple-darwin.tar.gz.sha256
   ```

2. Extract the archive:
   ```sh
   tar -xzf fail2commit-<version>-aarch64-apple-darwin.tar.gz
   cd fail2commit-<version>-aarch64-apple-darwin
   ```

3. Remove quarantine attribute (if downloaded via browser):
   This build is currently unsigned (pending Apple Developer ID code signing). If macOS Gatekeeper blocks execution, clear the quarantine attribute:
   ```sh
   xattr -d com.apple.quarantine fail2commit*
   ```

4. Install to your PATH:
   ```sh
   install -m 0755 fail2commit "$HOME/.local/bin/fail2commit"
   ```

5. Enable guards:
   ```sh
   fail2commit status
   fail2commit setup
   ```
