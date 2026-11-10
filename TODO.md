# fail2commit task board and roadmap
The MVP tasks below are done. The roadmap after them lists what is planned for 0.2 and later.

Integration branch: `main` (one PR per change). Latest release `v0.1.2` (pre-release; `v0.1.0` was built from `a9afcdf`) by the GitHub `release-candidate` workflow; evidence in `docs/dev/verify/VERIFY-2026-11-09-release.md`. Change requests CR-001 to CR-012 are in `docs/dev/change-requests.md`.

"Done" means implemented, independently security-reviewed until closed, merged, and passing the gate on both platforms. Requirement status stays `Approved` (not `Verified`) until the pending platform gates in the release report have evidence.

| ID | Task | Req IDs | Owner | Status | Depends on |
|---|---|---|---|---|---|
| CHORE-001 | Finalize workspace contracts, CLI routing and CI entry points | - | coordinator | done | - |
| T-001 | Guard Git pushes | FR-001, SPEC-001 | orca:claude-sonnet | done; GitHub-hosted CI run pending | CHORE-001 |
| T-002 | Approve exact operations | FR-002, SPEC-002 | orca:claude-opus | done; Windows interactive terminal prompt pending | CHORE-001 |
| T-003 | Enforce protected remote updates | FR-003, SPEC-003 | orca:claude-sonnet | done; GitHub rulesets pending | T-001, T-002 |
| T-004 | Guard npm installs | FR-004, SPEC-004 | orca:claude-sonnet | done | T-006, T-007 |
| T-005 | Guard pip installs | FR-005, SPEC-005 | orca:claude-sonnet | done | T-006, T-007 |
| T-006 | Scan packages and scripts | FR-006, SPEC-006 | orca:cline-deepseek | done; malicious-code warnings and advisory severity/fix added (CR-017, 0.1.2); live OSV smoke pending | CHORE-001 |
| T-007 | Isolate build scripts: T-007a Linux Bubblewrap, export, `run`, Linux test harness | FR-007, SPEC-007 | orca:claude-opus | done | CHORE-001 |
| T-007 | Isolate build scripts: T-007b Windows AppContainer | FR-007, SPEC-007 | orca:codex, cline-deepseek | done; clean-VM interactive run passed on Windows 10 and 11; Defender false positive needs code signing; LPAC and staged MinGW build pending | CHORE-001 |
| T-008 | Manage sandbox policy | FR-008, SPEC-008 | orca:claude-sonnet | done | T-007 |
| T-009 | Ship Windows desktop integration | FR-009, SPEC-009 | orca:claude-sonnet | done; tray GUI click-through pending | T-002, T-008 |
| T-010 | Integrate VS Code | FR-010, SPEC-010 | orca:claude-sonnet | done; GUI and Remote-WSL session pending | T-002, T-004, T-005, T-008 |
| T-011 | Ship reproducible releases | FR-011, SPEC-011 | orca:codex + coordinator | done; Arch pacman package added (CR-016); GitHub release-candidate run passed on `2888aec`; Windows code signing pending (P-101) | T-003–T-010 |
| T-012 | Keep resource use bounded | NFR-012, SPEC-012 | orca:claude-sonnet | done | T-004, T-005, T-007, T-009 |

## Production roadmap (proposed, not yet approved)

The MVP stops install-time attacks for npm and pip when the install goes through the guard (verify report sections 5f and 5g). Production grade means three more things: the guard is hard to bypass by accident, it costs a developer little time and few prompts, and the OS trusts the releases. Each row below needs its requirement written with `/write-requirements` and approved before code starts. "Exit" is the check that closes the row.

### Phase 1: close the gaps (v0.2)

| ID | Task | Why | Exit | Depends on |
|---|---|---|---|---|
| P-101 | Code-sign the Windows binaries and installer; submit the CLI to Microsoft as a false positive | Defender quarantined the unsigned CLI (`Behavior:Win32/DefenseEvasion.A!ml`), which blocks the Windows release | Signed installer passes SmartScreen and Defender on clean Windows 10 and 11 VMs, including the attack simulation | owner: certificate |
| P-108 | Verify npm registry signatures (ECDSA keys from the registry) and Sigstore provenance for every package in the plan, as `npm audit signatures` does; PyPI attestations (PEP 740) next | A hijacked maintainer account or a tampered mirror ships bytes the registry never signed, or drops the provenance an earlier version had | An invalid or missing registry signature is a deny; provenance that disappeared since the previous version is a warning; tests with a tampered fixture registry | in progress: orca worker (claude), branch DansPK/f2c-0.1.3; CR-018 |
| P-109 | Harden the advisory connection: HTTPS-only OSV by default (HTTP only to loopback), strict TLS, and a tamper-evident advisory cache | Advisory data decides what gets blocked; it must not be swappable in transit or on disk | A non-HTTPS OSV URL is refused; an edited cache entry is detected and refetched | in progress: orca worker (claude), branch DansPK/f2c-0.1.3; CR-019 |
| P-110 | Offline malware list: the OpenSSF malicious-packages data, pinned to a verified GitHub commit and checked by hash, used when OSV is unreachable | Known malware should stay blocked without network | With the network off, a package from the list is denied; a modified list is rejected | in progress: orca worker (claude), branch DansPK/f2c-0.1.3; CR-020 |
| P-102 | Low-friction defaults that every launcher reads: `setup` sets npm `script-shell` to a fail2commit wrapper that runs dependency install scripts in the sandbox and passes the project's own scripts through; and pip `only-binary = :all:` in the user pip config (release age is P-105). Each is recorded and undone by uninstall; `status` warns when one is removed or the package manager is too old | `npm.cmd`, nvm, IDEs and CI scripts read the user config but skip the shims. `ignore-scripts=true` was considered and rejected: it breaks native modules and npm `pre`/`post` hooks | Attack simulation run with bare `npm.cmd`, nvm's npm and `python -m pip` runs no package code outside the sandbox; `npm test` and `npm run` behave unchanged | - |
| P-103 | cmd.exe `doskey` macros through the per-user cmd AutoRun key | cmd has no shell functions, so a venv in cmd bypasses the guard (CR-015) | `venv\Scripts\activate.bat`, then `pip install`, is guarded | - |
| P-104 | Registry gate: the user's npm `registry=` and pip `index-url` point at a fail2commit loopback service that reviews before serving; grows from the existing wheel-only pip proxy (`pip/proxy.rs`) | Closes `python -m pip`, IDEs and every other launcher that reads the standard config files | Attack simulation through `python -m pip` and `npm.cmd` is blocked; with the service stopped, installs fail closed | P-102 |
| P-105 | Minimum release age: versions published less than N hours ago (default 72) need approval | Most malicious versions are found and pulled within days; this also catches new malware that has no findings | A freshly published simulation package prompts; a pinned year-old lockfile installs with no prompt | - |
| P-106 | Linux CI with real bubblewrap; AppArmor userns check on stock Ubuntu 24.04 | Open gates in the verify report, section 6 | CI fails if any sandbox control fails | - |
| P-107 | Fuzz the untrusted parsers (tar/gzip, wheel ZIP, lockfiles, pre-push input, IPC) with `cargo fuzz` in CI | They parse attacker-controlled bytes | 1 h per target without a crash; corpus committed | - |

### Phase 2: user experience (v0.3)

| ID | Task | Why | Exit | Depends on |
|---|---|---|---|---|
| P-201 | False-positive benchmark: install the top 500 npm and top 500 PyPI packages through the guard and record every prompt and deny | People switch off a guard that prompts on normal work; this is the number to drive down | Prompt rate and false-deny rate recorded in `docs/dev/verify/`; 0 false denies on the corpus | - |
| P-202 | Overhead budget: time the same installs with and without the guard (guarded esbuild took 26 s on Arch and 32 s on Windows; unguarded not yet measured) | Install speed decides adoption | Median overhead recorded, a target set in NFR-012 and met | P-201 |
| P-203 | Review cache keyed by package integrity hash | Re-installs, CI runs and fresh clones rescan the same tarballs | A second install of an unchanged lockfile does no rescan and shows no prompt | - |
| P-204 | Project approval file: approvals bound to the lockfile digest, which a team commits and reviews in a PR | One-time approvals repeat on every machine for every teammate (approval fatigue) | A teammate with the same lockfile gets no prompt; any lockfile change invalidates the approval | P-203 |
| P-205 | Plain-language prompts and errors: what was found, why it matters and the next command, with no internal names (`RefRewrite`, `IncompleteScan`) | Testers had to read the docs to act on a prompt | Every finding kind has a reviewed message and a "what to do" line, covered by snapshot tests | - |
| P-206 | `fail2commit doctor`: checks PATH order, shims, shell functions, npmrc, sandbox controls and the Linux user manager, then prints the fix | Most issues found in testing were setup issues: PATH order, visible consoles, cgroups without a login session | Each check has a test that breaks the setup and confirms `doctor` names the fix | - |
| P-207 | Tray and dialog polish: test the menu items, add screen-reader labels and a high-DPI icon, show decision history | The tray menu was never clicked through; accessibility is untested | Narrator reads every control; menu click-through recorded | - |
| P-208 | Document and test `fail2commit run -- npm test` / `npm start` as the way to run untrusted code at use time | Malicious code that runs on `require()` is outside install-time isolation | A simulation package with a require-time payload is contained when run through `fail2commit run` | - |
| P-209 | Distribution through winget, Scoop, a signed apt repository and the AUR | Download-and-run installs are hard to keep updated | Each channel installs, upgrades and removes cleanly on a clean VM | P-101 |
| P-210 | Signed releases with an SBOM and GitHub build provenance; an update check with no telemetry | Users need to verify what they install | `gh attestation verify` passes for every artifact | P-101 |
| P-211 | macOS support: Seatbelt sandbox backend (no network, writes only to staging, no home), rlimits and timeouts, universal binary, notarisation, Homebrew tap | Requested; macOS developers are a large share of npm and pip users. macOS has no enforced memory rlimit, which is a known gap | The attack simulation is blocked on a real Apple Silicon Mac; the notarised build passes Gatekeeper | owner: Apple Developer ID, a Mac |

### Phase 3: more package managers (v0.4 and later)

First, split the npm and pip code into one ecosystem adapter trait. Its steps:

1. Plan: resolve without running package code.
2. Fetch the packages and verify their integrity.
3. Review: scan them.
4. Stage: install offline with scripts off.
5. Run the approved build steps in the sandbox.
6. Commit the result into the project.

Shims, shell functions and the registry gate (P-104) then come from the trait. The order below is install-time code-execution risk multiplied by usage.

| ID | Package manager | Registry and scan | Where package code runs | Approach |
|---|---|---|---|---|
| P-300 | Adapter refactor, no behaviour change | - | - | npm and pip move onto the trait; every existing test passes unchanged |
| P-301 | pnpm | npm registry; reuse the npm scan | Lifecycle scripts (pnpm 10 gates them with `onlyBuiltDependencies`) | Install with `--ignore-scripts`, then run approved builds with `pnpm rebuild` in the sandbox; parse `pnpm-lock.yaml` |
| P-302 | Yarn classic and Yarn Berry | npm registry | Lifecycle scripts; Berry plugins | As pnpm; Berry with `enableScripts: false`, then `yarn rebuild`; parse `yarn.lock` |
| P-303 | Bun | npm registry | Lifecycle scripts of `trustedDependencies` | Install with `--ignore-scripts`; sandboxed build step |
| P-304 | uv and pipx | PyPI; reuse the pip scan | sdist builds | Point `UV_INDEX_URL` at the wheel-only gate; `--no-build` unless the build is approved and sandboxed |
| P-305 | Poetry | PyPI | sdist builds, plugins | Gate as the package source; `poetry install` under the guard |
| P-306 | Cargo | crates.io; OSV and RustSec | `build.rs` and proc macros at build time | Sandbox `cargo build` through `fail2commit run`; scan `Cargo.lock` |
| P-307 | RubyGems/Bundler, Composer, NuGet | Each registry; OSV | Native extensions, Composer scripts, MSBuild targets | Same adapter steps, one ecosystem at a time |
| P-308 | Go modules | proxy.golang.org; OSV and `sum.golang.org` | None at install | Advisory scan only |
| Later | VS Code extensions, GitHub Actions, container images | - | - | Different install shape; needs its own requirement |

A package manager is done when it passes the same gate as npm and pip:
- the attack simulation, ported to that ecosystem, is blocked at every step on the Windows, Debian and Arch VMs;
- the false-positive benchmark (P-201) runs on its top 200 packages;
- uninstall leaves the host unchanged.
