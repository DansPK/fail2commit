# Verification: 2026-11-17 macOS arm64 Build and Artifact

- **Date**: 2026-11-17
- **Host**: Apple Silicon Mac mini, macOS 26.6 (Darwin 25.6.0 arm64), 16 GB RAM
- **Base Commit**: `b0deb7bdcec540f22e9181a0e2d293019dbfcb42` (`DansPK/f2c-0.1.4`)
- **CR Reference**: CR-028 (macOS arm64 build without sandbox backend (fail closed); Seatbelt backend remains P-211)
- **Rust Toolchain**: `rustc 1.100.0 (772ee32ae 2026-10-14)`, `cargo 1.100.0 (772ee32ae 2026-10-14)`, target `aarch64-apple-darwin`

---

## 1. Summary of Changes

- **Sandbox Probe**: Gated `crates/fail2commit-core/src/sandbox/mod.rs` so macOS returns `Unavailable` with detail `"no sandbox backend on macOS yet"`.
- **Platform Gating**:
  - Gated Linux/Windows-only modules (`crates/fail2commit-core/src/sandbox/hardened/`, `vm.rs`, `vm_guest.rs`, `egress.rs`) with dead-code suppressions on non-Linux/Windows platforms.
  - Added `cfg(windows)` guards to Windows progress UI helpers in `crates/fail2commit/src/cmd/progress_ui.rs`.
  - Added `libc` dependency under `cfg(unix)` for `setsid` in `crates/fail2commit/tests/approval_support/mod.rs`.
- **Test Compatibility**:
  - `crates/fail2commit/tests/git_push.rs`: Gated APFS invalid UTF-8 filename sequence test to Linux (APFS rejects raw surrogate/illegal byte sequences at VFS level).
  - `crates/fail2commit/tests/e2e_npm_sandbox.rs`: Skip sandbox execution assertions when sandbox probe is unavailable.
  - `crates/fail2commit/tests/rereview_npmscan.rs`: Extended probe paths to check Node executable parent `lib/node_modules/npm` for macOS Node setups.
  - `crates/fail2commit/tests/rereview2_pip.rs` & `crates/fail2commit/tests/rereview_pip_boot.rs`: Canonicalized paths before prefix stripping to handle macOS `/var` -> `/private/var` symlink.
- **Packaging & CI**:
  - Created `packaging/macos/build.sh` generating `fail2commit-<version>-aarch64-apple-darwin.tar.gz` and `.sha256`, including binary, documentation, and quarantine notice.
  - Added `macos` job on `macos-14` to `.github/workflows/release.yml`.
  - Added user documentation in `docs/macos.md` linked from `README.md` and `docs/install.md`.

---

## 2. Command Executions & Exit Codes

### Code Formatting
```sh
cargo fmt --all -- --check
```
- **Exit code**: `0`

### Linter (Clippy)
```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
```
- **Exit code**: `0`

### Workspace Test Suite
```sh
cargo test --workspace --locked
```
- **Exit code**: `0`
- **Output summary**:
  - `fail2commit-core`: 248 tests passed; 0 failed
  - `fail2commit` unit & integration tests:
    - `cmd::doctor::tests`: 2 passed
    - `cmd::status::tests`: 3 passed
    - `cmd::uninstall::tests`: 7 passed
    - `policy::tests`: 3 passed
    - `tests/approval.rs`: 2 passed
    - `tests/doctor.rs`: 2 passed
    - `tests/e2e_npm_sandbox.rs`: 1 passed
    - `tests/e2e_pip_sandbox.rs`: 1 passed
    - `tests/git_commit.rs`: 13 passed
    - `tests/git_push.rs`: 17 passed
    - `tests/hook_pre_commit.rs`: 10 passed
    - `tests/hook_pre_push.rs`: 6 passed
    - `tests/install_verify.rs`: 1 passed
    - `tests/npm_integration.rs`: 12 passed
    - `tests/oplock_unit.rs`: 4 passed
    - `tests/pip_integration.rs`: 10 passed
    - `tests/pip_review_fixes.rs`: 1 passed
    - `tests/rereview2_pip.rs`: 3 passed
    - `tests/rereview_npmscan.rs`: 11 passed
    - `tests/rereview_pip_boot.rs`: 4 passed
    - `tests/server_review_fixes.rs`: 1 passed
    - `tests/ui_tray.rs`: 4 passed
    - `tests/uninstall.rs`: 13 passed

### Release Build
```sh
cargo build --release --locked --target aarch64-apple-darwin
```
- **Exit code**: `0`
- **Binary**: `target/aarch64-apple-darwin/release/fail2commit`

### Packaging
```sh
packaging/macos/build.sh HEAD target/dist
```
- **Exit code**: `0`
- **Archive path**: `target/dist/fail2commit-0.1.3-aarch64-apple-darwin.tar.gz`
- **SHA-256 checksum**: `5548d0fb9d787c7a738786f6590ae098f6835cf911161d3386c3a70f63d13691`

### Smoke Verification (Isolated Environment)
Conducted in temporary root `/tmp/f2c-smoke-XXXXXX` with isolated `HOME`:
1. `fail2commit --version`:
   - Output: `fail2commit 0.1.3`
   - Exit code: `0`
2. `fail2commit status`:
   - Output: `Sandbox: unavailable (no sandbox backend on macOS yet)`
   - Exit code: `0`
3. `fail2commit setup --help`:
   - Output: usage help options displayed
   - Exit code: `0`
4. `fail2commit setup`:
   - Configured git hooks and npm/pip shims under temporary HOME
   - Exit code: `0`
5. Disposable Git Bare Remote Push Guard:
   - Clean commit push: successfully allowed (exit code: `0`)
   - Secret commit push (`app/.env` with API token): rejected and blocked with prompt:
     `[fail2commit] Push blocked: Review needed: Approve Secret` (exit code: `1`)
6. npm scriptless offline fixture (`npm install`):
   - Package installed without lifecycle scripts (exit code: `0`)
7. npm offline fixture with install script (`npm install`):
   - Blocked and failed closed due to unavailable sandbox:
     `thread 'main' panicked at crates/fail2commit/src/cmd/shim.rs:...: sandbox unavailable: no sandbox backend on macOS yet` (exit code: `101`)

---

## 3. Artifact Details

- **Archive File**: `target/dist/fail2commit-0.1.3-aarch64-apple-darwin.tar.gz`
- **SHA-256 File**: `target/dist/fail2commit-0.1.3-aarch64-apple-darwin.tar.gz.sha256`
- **SHA-256**:
  ```
  5548d0fb9d787c7a738786f6590ae098f6835cf911161d3386c3a70f63d13691
  ```
- **Contents**:
  - `fail2commit` (Mach-O 64-bit executable arm64)
  - `LICENSE`
  - `README-MACOS.txt` (quarantine removal note and macOS fail-closed documentation)
