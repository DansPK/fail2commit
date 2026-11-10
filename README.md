<p align="center"><img src="asset/logo.png" alt="fail2commit logo" width="128"></p>

<h1 align="center">fail2commit</h1>

<p align="center">
  <b>Stop supply-chain attacks and leaked secrets on the developer's machine.</b><br>
  fail2commit checks the code you push and the packages you install, and runs package build scripts in a sandbox.
</p>

<p align="center">
  <a href="https://github.com/DansPK/fail2commit/actions/workflows/ci.yml"><img src="https://github.com/DansPK/fail2commit/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/DansPK/fail2commit/releases"><img src="https://img.shields.io/github/v/release/DansPK/fail2commit?include_prereleases&label=release" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey" alt="Platforms: Windows, Linux">
</p>

---

## Why

A malicious package runs its install script the moment you type `npm install` or `pip install`. Within seconds it can read your SSH keys, cloud credentials and tokens, send them out, and plant persistence. A leaked secret in a pushed commit is just as quick to exploit. fail2commit puts a check in front of both, on your own machine, before anything leaves it or runs.

It is free, written in Rust, and needs no account or cloud service.

## Features

- **Git push guard**
  - Scans outgoing commits for secrets before they leave.
  - Asks before a force push, a history rewrite or a tag replacement, and can require a password for them.
  - A self-hosted server hook enforces the same rules for pushes that skip local hooks.
- **npm and pip install guard**
  - Resolves the exact packages first, and checks them against [OSV](https://osv.dev) (known vulnerabilities and the OpenSSF malicious-packages list).
  - Scans their install scripts.
  - Nothing from a package runs until you approve the plan, and a changed plan cancels the approval.
- **Sandboxed build scripts**
  - Approved install scripts, and anything you run with `fail2commit run`, get no network, no access to your home directory and no access to your credentials.
  - On Windows this uses an AppContainer. On Linux it uses bubblewrap with cgroup v2 limits.
- **Fails closed.** If the sandbox can't start, package code does not run. A cancelled operation changes nothing.
- **Desktop and editor**
  - Approvals come from the terminal or a Windows tray app.
  - A VS Code extension adds guarded push and install commands.
- **Clean removal.** `fail2commit uninstall-integrations` removes exactly what `setup` added, and nothing else.

## How it works

```text
 git push ──► pre-push hook ──► secret scan, rewrite check ──► approve? ──► push
 npm ci   ──► shim ──► resolve exact plan ──► OSV + script scan ──► approve? ──┐
 pip install                                                                     │
          ┌──────────────────────────────────────────────────────────────────────┘
          └─► install with scripts off ──► approved build scripts in the sandbox
                                            (no network, no home, no secrets)
```

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) covers the components and trust boundaries.

## Project status

**0.1.1 is a preview** for technical users and testers.

**What has been tested:**
- Clean Windows 10 and 11, Debian, and Arch Linux VMs.
- A realistic attack simulation (credential theft, persistence, lockfile tampering) was fully blocked, the host stayed unchanged, and nothing was sent out. Without the guard, the same attack stole everything.
- 516 tests pass on Windows and 502 on Linux. Evidence: [release report](docs/dev/verify/VERIFY-2026-11-09-release.md).

**Known limits** (being worked on, see the [roadmap](#roadmap)):
- **The Windows binaries are not code-signed yet.** SmartScreen warns, and Defender may flag the CLI as a false positive.
- **Some launchers bypass the guard:** `python -m pip`, programs that run `npm.cmd` by full path, and `pip` in a venv activated in cmd.exe. `fail2commit status` warns about the cases it can detect. Use `fail2commit npm ...` and `fail2commit pip ...` there.
- **Only install time is protected.** Code that runs when a package is imported is not stopped. Run untrusted projects with `fail2commit run --input . -- npm test`.
- **Only npm and pip are guarded**, on Windows and Linux.

## Installation

Download the file for your platform and `SHA256SUMS` from [GitHub Releases](https://github.com/DansPK/fail2commit/releases). Check the download first:
- Linux: `sha256sum -c SHA256SUMS --ignore-missing`
- Windows: `Get-FileHash`
- Any platform: `gh attestation verify <file> -R DansPK/fail2commit`

| Platform | File | Install |
|---|---|---|
| Windows 10/11 x64 | `fail2commit-0.1.1-setup.exe` | Run it as your normal user. It asks for administrator rights to guard the machine-wide npm and pip |
| Debian / Ubuntu amd64 | `fail2commit_0.1.1_amd64.deb` | `sudo dpkg -i fail2commit_0.1.1_amd64.deb` |
| Arch and Arch-based x86_64 | `fail2commit-0.1.1-1-x86_64.pkg.tar.zst` | `sudo pacman -U fail2commit-0.1.1-1-x86_64.pkg.tar.zst`, or `makepkg -si` with [packaging/arch/PKGBUILD](packaging/arch/PKGBUILD) |
| Other Linux x86_64 | `fail2commit-0.1.1-linux-amd64` | Copy it onto your PATH |
| From source | `fail2commit-0.1.1-src.tar.gz` | Offline build, with the crates vendored. See [docs/install.md](docs/install.md) |
| VS Code | `fail2commit-0.1.1.vsix` | `code --install-extension fail2commit-0.1.1.vsix` |

On Linux the sandbox needs `bubblewrap`. Node.js/npm and Python are needed only for their own guards. Full instructions, including removal, are in [docs/install.md](docs/install.md).

## Quick start

Installing the package changes nothing in your home directory. Turn on the guards yourself:

```sh
fail2commit setup      # Git hooks, npm/pip shims and shell functions for this user
fail2commit status     # check what is guarded and whether the sandbox works
```

After that, your usual commands are guarded:

```sh
git push               # outgoing commits are scanned; force pushes ask first
npm ci                 # packages are reviewed; approved install scripts run in the sandbox
pip install requests   # packages are checked; source builds run in the sandbox
```

## Usage

```sh
fail2commit secret-scan                  # scan unpushed commits without pushing
fail2commit scan npm:left-pad@1.3.0      # check exact packages without installing
fail2commit run --input . -- npm test    # run a command in the sandbox
fail2commit sandbox status               # show each sandbox control and whether it works
fail2commit password set                 # require a password for force pushes and rewrites
fail2commit uninstall-integrations       # remove everything setup added, and nothing else
```

Run `fail2commit help <command>` for all options. The guides are listed in the [documentation index](docs/README.md). The main ones:
- the [Git guard](docs/git-integration.md)
- [approvals](docs/approval.md)
- the [npm guard](docs/npm.md) and the [pip guard](docs/pip.md)
- [scanning](docs/scan.md)
- the sandbox on [Linux](docs/sandbox-linux.md) and [Windows](docs/sandbox-windows.md)
- [Windows setup](docs/windows.md)
- [VS Code](docs/vscode.md)
- the [server hook](docs/server.md)

## Roadmap

These items are planned, not promised, and each one starts with an approved requirement. The detailed plan, with the exit check for each item, is in [TODO.md](TODO.md#production-roadmap-proposed-not-yet-approved).

### 0.2: close the gaps
- [ ] Code-sign the Windows binaries and installer.
- [ ] Close the known bypasses with low-friction defaults that every launcher respects:
  - npm install scripts always run in the sandbox (through npm's `script-shell`);
  - pip only installs prebuilt wheels when the guard is bypassed;
  - cmd.exe macros for venvs;
  - a minimum release age for brand-new versions.
- [ ] A local registry gate, so `python -m pip`, IDEs and CI scripts are reviewed too.
- [ ] Linux CI with the real sandbox, and fuzzing of every parser that reads untrusted input.

### 0.3: user experience
- [ ] Measure false positives on the top 500 npm and PyPI packages, and drive them down.
- [ ] Cache reviews by package hash, and let a team share approvals through a file bound to the lockfile.
- [ ] Plain-language prompts and errors, and a `fail2commit doctor` command that finds and explains setup problems.
- [ ] Install through winget, Scoop, apt, the AUR and Homebrew. Signed releases with an SBOM.
- [ ] macOS support: a Seatbelt sandbox, notarised builds and a Homebrew tap.

### 0.4 and later: more package managers
- [ ] One adapter for every ecosystem, so each new package manager gets the same review, sandbox and approvals.
- [ ] pnpm, Yarn, Bun, then uv and pipx, Poetry, Cargo, RubyGems, Composer, NuGet, and Go (advisories only).
- [ ] Later: VS Code extensions, GitHub Actions and container images.

Feature requests and votes are welcome in [issues](https://github.com/DansPK/fail2commit/issues).

## Contributing

Contributions are welcome. Test results on platforms we haven't covered are especially useful. Start with [CONTRIBUTING.md](CONTRIBUTING.md). To build and run the tests, see [docs/dev/setup.md](docs/dev/setup.md):

```sh
cargo build --release --locked -p fail2commit
cargo test --workspace --locked
```

Requirements, specs, the test plan and the test evidence are under [docs/dev/](docs/dev/setup.md#project-records). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Acknowledgements

fail2commit builds on:
- [OSV](https://osv.dev) and the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) data
- [bubblewrap](https://github.com/containers/bubblewrap)
- Windows AppContainer isolation
- [NSIS](https://nsis.sourceforge.io)
- the Rust crates listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)

## License

Copyright 2026 Nut Youlong. Licensed under the [Apache License 2.0](LICENSE); see [NOTICE](NOTICE).
