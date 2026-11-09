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

## 5b. Windows 10 and interactive-session runs (same release artifacts)

VMware `win10` (Windows 10 IoT Enterprise LTSC 2021, 21H2, NT 10.0.19044.7725) and `win11` again, each from a fresh `pre-f2c-test` snapshot and reverted afterwards. MinGit 2.47.1 was downloaded on the host (SHA-256 `50b04b55425b5c465d076cdb184f63a0cd0f86f6ec8bb4d5860114a713d2c29a`, equal to the release notes) and copied in. Interactive probes ran as a scheduled task with `LogonType Interactive` in the signed-in console session (`NT AUTHORITY\INTERACTIVE`, session 1): on win10 as a new standard user `f2cuser` signed in by auto-logon, on win11 as the VM's own console user.

| Check | Windows 10 LTSC 21H2 | Windows 11 25H2 |
|---|---|---|
| `f2c-vm-test.ps1` install, guard, uninstall (section 5 checks) | all pass: install exit 0; normal push exit 0 with the third-party hook chained; unattended `--force` exit 1 `Approve ForceIntent`, remote unchanged; uninstall exit 0; hooksPath, hook file and user PATH restored | passed earlier (section 5) |
| `sandbox status` in the interactive session | available; all 9 AppContainer controls `ok` | available; all 9 controls `ok` |
| `run -- cmd /d /c ...` reading `C:\f2c\secret.txt` (synthetic) outside the input | `Access is denied.`; secret not exported | `Access is denied.`; secret not exported |
| Network from inside the sandbox (`curl http://1.1.1.1/`) with host control | inconclusive (curl ran silent; see Defender finding) | denied: `curl: (7) Failed to connect`; host control `http=301` |
| Benign workload x4 (`status` + `run`), Defender detections | 0 | 0 |
| Re-export onto an existing file | refused: `cannot create destination: The file exists` (by design) | same |

Findings:

1. **`run -- cmd.exe` failed** with `cmd.exe was not found on PATH`, because `toolpath::find_real` appended `.exe` to a name that already had it (`cmd` worked). Fixed after the release candidate in `11be0a6` (FR-007) with a regression test; `.bat`/`.cmd` stay unresolvable. Host re-run: core lib 151/151, `run_cli` 3/3, `sandbox_windows_matrix` 7/7 including ignored. The 0.1.0 artifacts above predate this fix.
2. **Microsoft Defender quarantined the unsigned `fail2commit.exe`** on win10 (`Behavior:Win32/DefenseEvasion.A!ml`, severity 5, signatures 1.463.203.0) during the third run of the adversarial probe, whose sandboxed `cmd` reads a file named `secret.txt` and connects to a bare IP. Afterwards the same hash was blocked as soon as it was written to disk. From a fresh snapshot, the benign workload produced no detection on win10 or win11, and on win11 the adversarial probe ran without detection. The machine-learning verdict therefore depends on what the sandboxed child does, which for fail2commit is untrusted package code. Release prerequisite: Authenticode signing and a Microsoft false-positive submission (section 6).

## 5c. Linux full user flow with real bubblewrap (released `.deb`)

A disposable WSL distro `f2c-e2e` imported from the official Ubuntu 24.04 WSL rootfs (SHA-256 `8251e27f...15ea`, equal to Canonical's `SHA256SUMS`); kernel 6.18.54.1-microsoft-standard-WSL2, bubblewrap 0.9.0 (Ubuntu package), Node 18.19.1, npm 9.2.0, Python 3.12.3, Git 2.43.0. The released `fail2commit_0.1.0_amd64.deb` (`f52ddf76...0815`) was installed with `dpkg -i`; the flow ran as a new normal user `dev` under `setsid` (no controlling terminal, so unattended paths fail closed), against a loopback npm registry, PyPI index and OSV stub serving synthetic packages, with approvals given through `fail2commit api` exactly as the VS Code client does. Scripts: `setup_root.sh`, `flow.sh`, `secret_probe.sh`, `uninstall_root.sh`, `servers.py`, `approve.py`.

| Step | Result |
|---|---|
| `fail2commit setup`, `status` | exit 0; integrations `git, npm, pip`; sandbox `bubblewrap available=True`; 12 of 13 controls ok, `cgroup_v2_limits` not verified because `wsl --exec` processes are outside a systemd session (`0::/non-systemd`), so limits fell back to rlimits as designed |
| Normal push | exit 0; the third-party `core.hooksPath` pre-push hook ran |
| Unattended `git push --force` | exit 1 `Approve RefRewrite`; remote unchanged |
| Same push, approved once over `api` | asked once with findings `force_intent`, `ref_rewrite`; exit 0; remote updated |
| Secret pushes, unattended | GitHub token, AWS access key, private key and `password = "..."` each exit 1 with the value redacted (`[redacted N chars]`) |
| npm `plain` (no scripts) | exit 0 |
| npm `hello-build` (install script) | exit 0, `scripts: Sandboxed`; artifact `built-in-sandbox:1,4,9` built inside a `sandbox-stage` job and merged into `node_modules` |
| npm `hostile` | exit 0; inside the sandbox: home secret, `~/.ssh` key and the user's repo `ENOENT`; loopback canary `ECONNREFUSED` (0 connections seen by the listener); external TCP `ENETUNREACH`; child environment only npm lifecycle keys; nothing written to the real home |
| npm `advised` (synthetic OSV advisory) | unattended exit 11 `approval_unavailable`, nothing changed; cancel over `api` exit 10, nothing changed; approve once exit 0, installed |
| Sandbox off, npm package with a required install script | exit 11: a host-run approval is required and unattended fails closed; no script ran |
| pip `cleanpkg` wheel into a venv | exit 0, importable |
| pip `pyadvised` (advisory) | unattended exit 11, not installed; approved once over `api` exit 0, installed |
| `fail2commit run` | exit 0; output exported; the home secret, `~/.ssh` key and repo were not visible (`No such file or directory`) |
| `uninstall-integrations`, `dpkg --purge` | exit 0 / 0; binary gone; `core.hooksPath` restored to the third-party directory with its hook intact |

Findings:

1. **Generic secret detector missed quoted values containing `#`, `,` or `;`**: `db_password = "Zq8#vT2kPw9xLmR4sQ7"` was pushed unattended without a finding, because the value pattern stopped at `#`. Fixed (FR-001): a quoted value now runs to its closing quote; unquoted values still treat `#` as a comment. Regression test `quoted_password_with_hash_or_comma_is_flagged`.
2. In a session with a terminal the guard prompts on the terminal and waits, as specified; the first flow attempt (run from a backgrounded console) stopped there.

## 5d. GitHub Actions (PR #1, private repository)

| Run | Commit | scaffold | rust (ubuntu-latest) | rust (windows-latest) |
|---|---|---|---|---|
| 42584670597 | `02fd51f` | pass | pass (494) | fail: `e2e_npm_approval` 4 tests, `EISDIR lstat 'C:'` under the runner's Node 22.23.4 |
| 42592243721 | `7046e37` | pass | pass | fail: `e2e_npm_sandbox` 4 tests |

- `7046e37` (FR-004): npm-cli.js was passed to node in the `\\?\` form; Node 22 cannot resolve it. Reproduced locally with the official Node 22.23.4 zip (old code fails identically, fix passes 3 runs in a row).
- The second run's failures: three came from the test fixture embedding the runner's 8.3 `TEMP` (`RUNNER~1`), which the npm guard correctly refuses; reproduced locally with an 8.3 alias and fixed in the test support (long form). One was a leftover `probe-*` stage: the AppContainer probe stage is now removed with a short retry, and stale `probe-*` stages are swept like `npm-*` and `run-*`.
- The Linux job does not install bubblewrap, so the hostile-sandbox suites skip there; real-sandbox evidence is section 5c and the WSL runs in section 2.

## 6. Pending gates (missing prerequisite)

| Gate | Status | Missing prerequisite |
|---|---|---|
| GitHub Actions `ci.yml` runs | In progress (section 5d) | - |
| GitHub `release.yml` run | Pending | `workflow_dispatch` needs the workflow on the default branch, i.e. merging PR #1 |
| Linux CI exercising the real sandbox | Pending | Install bubblewrap in the CI job and require the sandbox; on stock Ubuntu 24.04 runners AppArmor may need a bwrap userns profile |
| Stock Ubuntu desktop with AppArmor userns restriction | Pending | A non-WSL Ubuntu 24.04+ host (WSL does not enforce the restriction) |
| GitHub repository rulesets (SPEC-003 hosted path) | Pending | A hosted GitHub repository with admin access |
| VS Code GUI click-through (modal approval, picker) and a real Remote-WSL session | Pending | An interactive desktop session; the extension and protocol are covered against both real CLIs headless |
| Tray GUI click-through (dialog, menu) | Pending | An interactive desktop session; pipe, ACL and rendering are covered by tests |
| Interactive terminal approval prompt on Windows | Pending | A ConPTY harness; terminal approval is covered on Linux with a real pty and by the stdio channel |
| Windows full staged-gcc native build in AppContainer | Pending | The MinGW closure is 961 MB / 11,871 files to stage; a staged native workload and the npm node build pass instead |
| LPAC (less-privileged AppContainer) | Not claimed | Runtime verification of LPAC capability with this backend |
| Live internet tests (OSV live smoke, Linux external TCP control) | Pending (ignored tests) | Explicit authorization to contact live endpoints from tests |
| Windows editions other than Windows 11 Pro 25H2 and Windows 10 IoT Enterprise LTSC 2021 | Pending | Additional Windows hosts (Windows 10 LTSC 21H2 passed in section 5b) |
| Windows sandbox on a clean VM in an interactive sign-in | **Passed** (section 5b) | - |
| Microsoft Defender false positive on the unsigned CLI (`Behavior:Win32/DefenseEvasion.A!ml`) | **Open, release blocker for Windows** | An Authenticode code-signing certificate and a Microsoft false-positive submission; both are outward-facing and need the owner |
| Release artifacts including `11be0a6` (`run -- cmd.exe` fix) | Pending | A rebuild of the Windows CLI, Setup.exe and the Linux artifacts from the new commit |
