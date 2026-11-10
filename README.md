<p align="center"><img src="asset/logo.png" alt="fail2commit logo" width="128"></p>

# fail2commit

fail2commit stops supply-chain attacks and leaked secrets at the developer's machine. It checks the code you push and the packages you install, and runs package build scripts in a sandbox.

- **Git pushes:** scans outgoing commits for secrets and asks before a force push, a history rewrite or a tag replacement. Rewrites can require a password. A self-hosted server hook enforces the same rules for pushes that skip local hooks.
- **npm and pip installs:** resolves the exact packages first, checks them against OSV (known vulnerabilities and the OpenSSF malicious-packages list) and scans their install scripts. Nothing from the package runs until you approve the plan. A changed plan cancels the approval.
- **Sandboxed build scripts:** approved install scripts and `fail2commit run --input <dir> -- <command>` run in an AppContainer on Windows, or in bubblewrap with cgroup v2 limits on Linux. They get no network access, no access to your home directory and no access to your credentials.
- **Desktop and editor:** approval dialogs come from a Windows tray app or the terminal. A VS Code extension adds guarded push and install commands.

It is free, open source (Apache-2.0), written in Rust, and needs no account or cloud service.

## Status: 0.1.0 preview

0.1.0 is for technical users and testers. It is not yet a general release.

**What has been tested:**
- Windows 10 and 11, Debian, and Arch Linux VMs.
- An attack simulation (credential theft, persistence and lockfile tampering) was fully blocked, and the host stayed unchanged.
- 516 tests on Windows and 502 on Linux pass.

Evidence: [docs/verify/VERIFY-2026-11-09-release.md](docs/verify/VERIFY-2026-11-09-release.md).

**Known limits:**
- **The Windows binaries are not code-signed.** SmartScreen warns, and Defender has quarantined the CLI once as a false positive. You may need to allow it.
- **Some launchers bypass the guard.** `python -m pip`, a program that runs `npm.cmd` by full path, and `pip` in an activated venv in cmd.exe are not guarded. `fail2commit status` warns about the cases it can detect. Use `fail2commit npm ...` and `fail2commit pip ...` there.
- **Only install time is protected.** Code that runs when you `require`/`import` a package is not stopped. Run untrusted projects with `fail2commit run --input . -- npm test`.
- **Two package managers.** Only npm and pip are guarded for now. pnpm, Yarn, Bun, uv, Poetry and Cargo are planned.
- **Not tested yet:** the tray menu, the VS Code GUI, Ubuntu with AppArmor, Manjaro and EndeavourOS.

The [roadmap in TODO.md](TODO.md#production-roadmap-proposed-not-yet-approved) lists what is planned for 0.2 and later.

## Install

Download the file for your platform and `SHA256SUMS` from [GitHub Releases](https://github.com/DansPK/fail2commit/releases), and check the hash first (`sha256sum -c SHA256SUMS --ignore-missing`, or `Get-FileHash` on Windows). Full instructions, including removal, are in [docs/install.md](docs/install.md).

| Platform | File | Install |
|---|---|---|
| Windows 10/11 x64 | `fail2commit-0.1.0-setup.exe` | Run it as your normal user; it asks for administrator rights to guard the machine-wide npm and pip |
| Debian / Ubuntu amd64 | `fail2commit_0.1.0_amd64.deb` | `sudo dpkg -i fail2commit_0.1.0_amd64.deb` |
| Arch and Arch-based x86_64 | `fail2commit-0.1.0-1-x86_64.pkg.tar.zst` | `sudo pacman -U fail2commit-0.1.0-1-x86_64.pkg.tar.zst`, or `makepkg -si` with [packaging/arch/PKGBUILD](packaging/arch/PKGBUILD) |
| Other Linux x86_64 | `fail2commit-0.1.0-linux-amd64` or `fail2commit-0.1.0-src.tar.gz` | Copy the binary onto your PATH, or build offline from the source archive |
| VS Code | `fail2commit-0.1.0.vsix` | `code --install-extension fail2commit-0.1.0.vsix` |

On Linux the sandbox needs `bubblewrap`. Node.js/npm and Python are needed only for their guards.

## Quick start

Installing the package changes nothing in your home directory. Turn on the guards yourself:

```sh
fail2commit setup      # Git hooks, npm/pip shims and shell functions for this user
fail2commit status     # check what is guarded and whether the sandbox works
```

After setup, the usual commands are guarded:

```sh
git push               # outgoing commits are scanned; force pushes ask first
npm ci                 # packages are reviewed; approved install scripts run in the sandbox
pip install requests   # wheels are checked; source builds run in the sandbox
```

Other useful commands:

```sh
fail2commit secret-scan                  # scan unpushed commits without pushing
fail2commit scan npm:left-pad@1.3.0      # check exact packages without installing
fail2commit run --input . -- npm test    # run a command in the sandbox
fail2commit sandbox status               # show the sandbox controls and whether each works
fail2commit password set                 # require a password for force pushes and rewrites
fail2commit uninstall-integrations       # remove everything setup added, and nothing else
```

Run `fail2commit help <command>` for the options.

## Documentation

The full index is [docs/README.md](docs/README.md). The most used guides:

| Topic | Document |
|---|---|
| Installing and removing | [docs/install.md](docs/install.md) |
| Git push guard and its limits | [docs/git-integration.md](docs/git-integration.md) |
| Approvals and the force-push password | [docs/approval.md](docs/approval.md) |
| npm guard | [docs/npm.md](docs/npm.md) |
| pip guard | [docs/pip.md](docs/pip.md) |
| Package and script scanning | [docs/scan.md](docs/scan.md) |
| Sandbox on Linux / Windows | [docs/sandbox-linux.md](docs/sandbox-linux.md), [docs/sandbox-windows.md](docs/sandbox-windows.md) |
| Sandbox policy | [docs/sandbox-policy.md](docs/sandbox-policy.md) |
| Windows PATH, machine shims and tray | [docs/windows.md](docs/windows.md) |
| VS Code extension | [docs/vscode.md](docs/vscode.md) |
| Self-hosted protected remote | [docs/server.md](docs/server.md) |
| Architecture and trust boundaries | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Building a release | [docs/release.md](docs/release.md) |

## Build from source

Use Rust stable. On Linux you also need a C toolchain.

```sh
cargo build --release --locked -p fail2commit
cargo test --workspace --locked
```

The Windows tray app is `-p fail2commit-tray`. The release scripts are in `scripts/release/`.

## Contributing

Requirements, specs and tests are in [docs/requirements](docs/requirements/FRD.md), [docs/specs](docs/specs/) and [docs/tests](docs/tests/TEST-PLAN.md). The task board is [TODO.md](TODO.md).
- Agents and contributors: start with [AGENTS.md](AGENTS.md).
- Status rules: [docs/WORKFLOW.md](docs/WORKFLOW.md).
- Fresh repository setup: [SETUP.md](SETUP.md).

Use synthetic secrets and disposable repositories in tests, never real ones.

## License

Copyright 2026 Nut Youlong. fail2commit is licensed under the [Apache License 2.0](LICENSE); see [NOTICE](NOTICE).
Development files inherited from the project template stay under their [MIT license](LICENSE.template-MIT).
Third-party notices for everything compiled into the release binaries are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
