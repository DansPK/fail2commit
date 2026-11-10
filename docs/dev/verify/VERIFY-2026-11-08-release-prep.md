# Verify Report: release preparation (2026-11-09)

> **Requirements covered:** FR-011
> **Commit / branch:** release artifacts `4d70c9275360211a9da4a0b1ccf5fa04a4667369`; final release-script checks `0ba81f517a3d20fb45e6d7b1f8f049566b378097` / `DansPK/f2c-t011-release`
> **Verified by:** Codex worker `task_b352602a61b5`

---

## 1. Environment

- Windows 11 x86_64 host; Rust `1.99.1`, Cargo `1.99.1`, target `x86_64-pc-windows-gnu`.
- Docker Engine `29.8.2`.
- `rust:1`: `sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07`, `linux/amd64`.
- `ubuntu:24.04`: `sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`, `linux/amd64`.
- Git for Windows `2.56.0.windows.2`; Python `3.12.10`.

## 2. Commands Run

Commands below ran from the repository root. `C:\Program Files\Git\bin\bash.exe` is written as `git-bash` for readability; it is the exact executable used.

| Command | Platform / tested SHA | Exit | Result |
|---|---|---:|---|
| `git merge-base --is-ancestor fe411ba HEAD` | Windows / initial branch | 0 | Required baseline is an ancestor. |
| `git-bash -n scripts/release/*.sh` | Windows Git Bash / `4d70c9275360211a9da4a0b1ccf5fa04a4667369` | 0 | Shell syntax passed. |
| `python -m py_compile scripts/release/notices.py` | Windows / `dd997c22680c3a2ac366ad32f22e201bcafb5fdb` | 0 | Python syntax passed. |
| `python scripts/release/notices.py` | Windows / `dd997c22680c3a2ac366ad32f22e201bcafb5fdb` | 0 | Notice file regenerated; review flags recorded below. |
| `git diff --exit-code -- THIRD-PARTY-NOTICES.md` | Windows / `dd997c22680c3a2ac366ad32f22e201bcafb5fdb` | 0 | Generated notice is deterministic and committed. |
| `cargo fmt --all -- --check` | Windows / `0ba81f517a3d20fb45e6d7b1f8f049566b378097` | 0 | Pass. |
| `cargo clippy --workspace --all-targets --locked -j 2 -- -D warnings` | Windows / same | 0 | Pass. |
| `cargo test --workspace --locked -j 2` | Windows / same | 0 | Pass: 17 unit tests, 0 failures. |
| `docker run --rm -v "${PWD}:/src" -v f2c-t011-linux-check-target:/target -e CARGO_TARGET_DIR=/target -w /src rust:1 bash -euc 'rustup component add rustfmt clippy; cargo fmt --all -- --check; cargo clippy --workspace --all-targets --locked -j 2 -- -D warnings; cargo test --workspace --locked -j 2'` | Linux container / same | 101 | Format and clippy pass; one frozen CLI unit test fails on Linux (Issue 1). |
| `git-bash scripts/release/build-deb.sh HEAD target/dist` | Docker Linux / `4d70c9275360211a9da4a0b1ccf5fa04a4667369` | 0 | Built binary and `.deb`; Cargo build jobs limited to 2. |
| `git-bash scripts/release/verify-deb.sh target/dist/fail2commit_0.1.0_amd64.deb` | Ubuntu 24.04 container / same | 0 | Install, version, status, remove/purge, and unrelated Git files passed. |
| `git-bash scripts/release/reproducible-linux.sh HEAD` | Two independent `rust:1` containers and target volumes / same | 0 | Binary and `.deb` were byte-identical across builds. |
| `git-bash scripts/release/source-tarball.sh HEAD target/dist` | Windows Git Bash / same | 0 | Built archive from `git archive` with locked vendored crates. |
| `git-bash scripts/release/verify-source-tarball.sh target/dist/fail2commit-0.1.0-src.tar.gz` | `rust:1`, `--network none` / same | 0 | `cargo build --release --locked --offline -p fail2commit -j 2` and version check passed. |
| `scripts/release/build-windows.ps1 -OutDir target/dist` | Windows / `0ba81f517a3d20fb45e6d7b1f8f049566b378097` | 0 | Remapped, optimized Windows release binary built. |
| `git-bash scripts/release/hashes.sh target/dist` | Windows Git Bash / same | 0 | SHA256SUMS generated. |
| `scripts/release/hashes.ps1 -Dist target/dist` | Windows PowerShell / same | 0 | SHA256SUMS generated; byte-identical to shell output. |
| `python .claude/hooks/trace_check.py` | Windows / same | 0 | `[guard:trace_check] OK`. |

An initial `bash scripts/release/source-tarball.sh HEAD target/dist` used the host's WSL launcher rather than Git Bash and exited 128 because this Windows worktree's `.git` file contains a Windows `D:/...` gitdir. Re-running through the explicitly required Git for Windows Bash passed; WSL invocation of Windows worktree release scripts is not claimed as supported.

## 3. Artifact Hashes

The Linux artifacts were built from `4d70c9275360211a9da4a0b1ccf5fa04a4667369`. The later `0ba81f5` commit changes only `scripts/release/hashes.ps1`; the Windows binary was built from that later commit.

| Artifact | SHA-256 |
|---|---|
| `fail2commit-0.1.0-linux-amd64` | `42c0249778e81755fe08a383198e4576f8e0dd7d8ae1b3ab8ecd9844b355f4c2` |
| `fail2commit_0.1.0_amd64.deb` | `176189aaa87103c95fa5513bb0b2e752dd011c001b5463ccb859015d8dab383d` |
| `fail2commit-0.1.0-src.tar.gz` | `deca8789f76575c6739e5dc50d19b92bc51f7fc2c3a26ce186f71665a930f177` |
| `fail2commit-windows-x86_64.exe` | `9501c626bab77b691bc6810cf00408d63bfa03c9ad1f86f2e8b92faef4abb489` |

Independent Linux build 1 and build 2 both produced:

- binary: `42c0249778e81755fe08a383198e4576f8e0dd7d8ae1b3ab8ecd9844b355f4c2`
- `.deb`: `176189aaa87103c95fa5513bb0b2e752dd011c001b5463ccb859015d8dab383d`

Therefore the tested Linux binary and `.deb` are bit-identical. Final hashes for the integrated release commit remain Pending.

## 4. TC-011 and Distribution Matrix

| Target | Result | Evidence / exact pending prerequisite |
|---|---|---|
| Ubuntu 24.04 amd64 `.deb` install/status/remove/purge | Pass | Clean container test preserved a pre-existing `~/.config/git/config` and `hooks/pre-push`; no fail2commit home was created. |
| Locked offline source build | Pass | Clean `rust:1` container with Docker network disabled built and ran `fail2commit --version`. |
| Two-build Linux reproducibility | Pass | Independent target volumes produced matching binary and `.deb` hashes above. |
| Windows x64 release binary build | Pass | PowerShell release build completed; this is not installer evidence. |
| Windows Setup.exe install/uninstall | Pending | `packaging/windows/build.ps1` and NSIS are not present on this branch; requires T-009 integrated tree and real Windows install test. |
| VSIX on native Windows and Linux | Pending | `extensions/vscode/package.json` is not present; requires T-010 integrated tree and VS Code on both platforms. |
| Workspace-side CLI selection in WSL | Pending | Requires integrated T-010 extension and a real WSL workspace test. |
| Paths with spaces; Git Bash and PowerShell product flows | Pending | Release scripts passed in both shells, but the checkout path had no spaces and no final installers were available. |
| Disposable protected remote receive | Pending | Requires integrated T-003 server implementation and its disposable remote harness. |
| Platform-gated Windows/Linux integration jobs | Pending | Neither `packaging/windows/integration.ps1` nor `scripts/integration/linux.sh` is present on this branch. |
| Final TC-011 on integrated release commit | Pending | Coordinator must build all artifacts from one integrated SHA and record final install/uninstall evidence and hashes. |

TC-011 remains **Pending**, despite the passing `.deb` and source subtests, because every supported artifact and integration path has not yet been tested from the integrated commit.

## 5. Issues and Review Flags

1. Linux workspace tests fail in coordinator-owned frozen `crates/fail2commit/src/main.rs:176`: `shims_route_to_subcommands` supplies `C:\\b\\NPM.exe` on Linux, where `std::path` does not treat backslashes as separators. Expected prerequisite: coordinator makes the Windows-only assertion platform-gated or makes shim-name parsing platform-neutral, then reruns Linux tests.
2. Dependency notice review flags are intentionally emitted:
   - `flatbuffers 24.12.23`: no license text found in the resolved crate source.
   - `r-efi 6.0.0`: copyleft alternative in the declared expression and no license text found in the resolved crate source.
3. `cargo-deb` warns that the package `description` field is missing. Adding it would require a coordinator-owned manifest change outside the permitted `[package.metadata.deb]` exception; packaging still succeeds.

Change request `CR-T011-001`: normalize PowerShell `SHA256SUMS` to ordinal path order and LF so it is byte-identical to the shell generator. Implemented in `0ba81f517a3d20fb45e6d7b1f8f049566b378097`.

No dependency was added and no frozen contract change was requested. No root `Cargo.toml` release-profile change is requested: the release scripts' environment overrides achieved bit-identical Linux outputs without editing the shared manifest.

## 6. Verdict

- [ ] **Verified:** all linked TCs pass; requirement status set to `Verified`
- [x] **Not verified:** release preparation passes for `.deb`, offline source, hashes, and reproducibility, but integrated Windows installer, VSIX, WSL, server, and final-SHA evidence are Pending; the Linux workspace test issue must also be resolved.
