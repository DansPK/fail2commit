# Verify Report: MVP release candidate (2026-11-09)

> **Requirements covered:** FR-001 to FR-011, NFR-012
> **Commit / branch:** release commit `4559bab` (`DansPK/f2c-release-a026090`) = integration commit `a026090` plus regenerated notices and docs. Product code is unchanged since the gated commit `d15f559`; the only later changes are two test files and documentation, each re-run.
> **Verified by:** Orca coordinator (gates, release builds, VM run); independent reviewers per area (see section 4)

---

## 1. Hosts and tools

| Platform | Details |
|---|---|
| Windows | Windows 11 Pro 10.0.26200, Rust 1.99.1 (`x86_64-pc-windows-gnu`), Git 2.56.0.windows.2, Node 24.22, Python 3.12.10 |
| Linux (container) | `f2c-linux-test:1` = `rust:1` (Debian) + python3-venv, pip 25.1, Node 20.19, npm 9.2; Docker 29.8.2 in WSL2 capped at 4 CPUs / 16 GB |
| Linux (real sandbox) | WSL2 Ubuntu 26.04.1, kernel 6.18.54.1-microsoft-standard-WSL2, bubblewrap 0.11.1, unprivileged user namespaces |
| Clean Windows VM | VMware Workstation 17 `win11` (Windows 11 Pro 25H2), reverted to its pre-test snapshot afterwards |

## 2. Commands and results

| Gate | Command (abridged) | Exit | Result |
|---|---|---:|---|
| Format | `cargo fmt --all -- --check` | 0 | at `8f69137` and later |
| Lint | `cargo clippy -j 3 --workspace --all-targets --locked -- -D warnings` | 0 | at `8f69137` and later |
| Windows tests | `<empty stdin> cargo test -j 3 --workspace --locked --no-fail-fast` at `d15f559` | 0 | **503 passed, 0 failed** (includes real AppContainer attack suite and npm e2e through AppContainer) |
| Linux tests | `docker run ... f2c-linux-test:1 cargo test -j 3 --workspace --locked --no-fail-fast` at `d15f559` | 0 | **494 passed, 0 failed** |
| Traceability | `python .claude/hooks/trace_check.py` | 0 | OK |
| Linux real sandbox | `scripts/linux/test.ps1 -Stage container,wsl -Gcc -NoCheck -Filter '^(sandbox_linux\|run_\|e2e_\|resource_)'` with `F2C_REQUIRE_SANDBOX=1` | 1 then 0 | all sandbox, run, e2e and resource suites pass in WSL bwrap; the one failure (native C build needed the CR-012 approval) was fixed in `a026090` and `e2e_npm_sandbox` re-run **6/6** with `F2C_REQUIRE_SANDBOX=1 F2C_REQUIRE_NATIVE_BUILD=1` |
| Windows sandbox attack suite | `cargo test -p fail2commit --test sandbox_windows_matrix --test review_t007b_* -- --include-ignored` | 0 | 12/12, including live external TCP denial with a host positive control (`Test-NetConnection 1.1.1.1 -Port 443` = True) |
| Windows release build | `scripts/release/build-windows.ps1`; `packaging/windows/build.ps1 -Makensis <portable NSIS 3.11>` | 0 | CLI and Setup.exe built |
| .deb build | `scripts/release/build-deb.sh HEAD target/dist` (cargo-deb 3.8.0 in `rust:1`) | 0 | built |
| .deb verify | `scripts/release/verify-deb.sh` (clean `ubuntu:24.04`: install, `status`, remove, purge, third-party files kept) | 0 | passed |
| Source tarball | `scripts/release/source-tarball.sh`; `verify-source-tarball.sh` (`--network none`, vendored) | 0 | offline build passed |
| Reproducibility | `scripts/release/reproducible-linux.sh HEAD` (two independent target volumes) | 0 | `.deb` and Linux binary bit-identical across builds and equal to the released hashes |
| VSIX | `npm ci; npm run compile; npm test; npx @vscode/vsce package` | 0 | packaged; tests 13/13 against the Windows release CLI and 13/13 against the Linux release CLI (`F2C_BIN`) |
| Clean Windows 11 install/uninstall | `C:\f2c\f2c-vm-test.ps1` in the `win11` VM | see section 5 | see section 5 |

## 3. Artifacts (`target/dist/SHA256SUMS`)

```text
f19ad03b254ff5dcd2f3ce27a2f0b19882e592ffca548f525da525ca6ac64218  fail2commit-0.1.0-setup.exe
816e25a23e3adb31289443f0bce1eeca62aa031e13a2c42cfbd6d09d404f958c  fail2commit-windows-x86_64.exe
f52ddf7638c40894595d1c38a84dfd4ebc24fea0afbc179daaaba1ee23ee0815  fail2commit_0.1.0_amd64.deb
e2be5a408d5d1f42846c05b430cca39162a53dc0bbbc38ce9aeb49e61a694cd7  fail2commit-0.1.0-linux-amd64
4496e68130607e665b47db5007f338032c4d327703b992ea4d34d386ead5f4fa  fail2commit-0.1.0-src.tar.gz
1d9473c5b20b449074ede3dd1cf638fff535590e269ece429f27612c852a2814  fail2commit-0.1.0.vsix
```

Nothing was published or pushed.

## 4. Security review trail

Every security-sensitive area was reviewed by an agent that did not write it, and fixed until a narrow re-review closed the finding class:

| Area | Reviews | Outcome |
|---|---|---|
| Git guard, approval, server, tray, VS Code (wave 1) | review, re-review, re-review 2 | closed (`REVIEW/REREVIEW/REREVIEW2-2026-11-09-*`) |
| npm, pip, scanner, Linux sandbox (wave 2) | review, then per-area re-reviews (npm 3 rounds, pip 2 rounds) | closed; structural fixes CR-005, CR-008 |
| Windows AppContainer | review, fix, coordinator re-run of the attack suite | closed (CR-006, CR-007) |
| Approval relay | review, re-review, fix | closed (CR-010; CR-011 residual risk accepted) |
| Coordinator's own last fixes | independent review | closed (CF-001..003 fixed) |

All reviewer reproductions are permanent regression tests. Change requests CR-001 to CR-012 are in `docs/change-requests.md`.

## 5. Clean Windows 11 install and uninstall

VMware `win11` (Windows 11 Pro 25H2, NT 10.0.26200), snapshot `pre-f2c-test` taken first and reverted afterwards. Script `f2c-vm-test.ps1` (run through VMware Tools as the normal user). MinGit 2.47.1 was unpacked inside the VM for the Git integration. A third-party global `core.hooksPath` with its own pre-push hook was planted before install.

| Check | Result |
|---|---|
| `fail2commit-0.1.0-setup.exe /S` | exit 0; CLI, tray, uninstaller and HKCU uninstall entry present |
| `fail2commit --json status` | `ok`; integrations `git:True,npm:True,pip:True,tray-startup:False` |
| Global hooks and PATH | `core.hooksPath` = fail2commit's hooks dir; shim dir on the user PATH |
| Normal push to a local bare remote | exit 0; **the third-party pre-push hook was chained and ran** |
| Unattended `git push --force` | exit 1, `Approve ForceIntent: explicit force intent: --force`; remote unchanged (fails closed) |
| `uninstall.exe /S _?=<dir>` | exit 0; CLI, tray, uninstall entry and Run value removed |
| Third-party state after uninstall | `core.hooksPath` restored to the third-party value; its hook file intact; user PATH identical to before |
| Leftover | `uninstall.exe` only, because `_?=` keeps the uninstaller in place for a waitable silent run |

Finding: `fail2commit sandbox status` in this session reported the AppContainer backend unavailable: `CreateAppContainerProfile failed: HRESULT 0x80070002`. The session was a VMware Tools guest operation: `NT AUTHORITY\BATCH` logon, session 0, with the user's registry hives (including `_Classes`) not loaded. `CreateAppContainerProfile` needs that profile. The backend failed closed as designed. In an interactive session on the development host the same backend passes 12/12 attack tests. Documented as a known limitation in docs/sandbox-windows.md: batch or service logons without a loaded profile report the sandbox unavailable and fail closed.

## 6. Pending gates (missing prerequisite)

| Gate | Status | Missing prerequisite |
|---|---|---|
| GitHub Actions `ci.yml` / `release.yml` runs | Pending | Running them needs a push to GitHub, which this implementation run must not do |
| GitHub repository rulesets (SPEC-003 hosted path) | Pending | A hosted GitHub repository with admin access |
| VS Code GUI click-through (modal approval, picker) and a real Remote-WSL session | Pending | An interactive desktop session; the extension and protocol are covered against both real CLIs headless |
| Tray GUI click-through (dialog, menu) | Pending | An interactive desktop session; pipe, ACL and rendering are covered by tests |
| Interactive terminal approval prompt on Windows | Pending | A ConPTY harness; terminal approval is covered on Linux with a real pty and by the stdio channel |
| Windows full staged-gcc native build in AppContainer | Pending | The MinGW closure is 961 MB / 11,871 files to stage; a staged native workload and the npm node build pass instead |
| LPAC (less-privileged AppContainer) | Not claimed | Runtime verification of LPAC capability with this backend |
| Live internet tests (OSV live smoke, Linux external TCP control) | Pending (ignored tests) | Explicit authorization to contact live endpoints from tests |
| Windows editions other than Windows 11 Pro 26200 / 25H2 | Pending | Additional Windows hosts |
| Windows sandbox on the clean VM in an interactive sign-in | Pending | A console sign-in on the VM (the guest-operations session is a BATCH logon without the user profile; see section 5) |
