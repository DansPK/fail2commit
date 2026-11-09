# Install fail2commit

Release artifacts are accompanied by `SHA256SUMS`. Verify the checksum before
installing and retain both the artifact SHA-256 and the tested Git commit in
your deployment record. Installing a package does not install user hooks or
shims; run `fail2commit setup` explicitly when you are ready to enable them.

## Windows x64 Setup.exe

Run the signed `fail2commit-<version>-windows-x64-setup.exe` as the intended
desktop user, then run `fail2commit setup`. Use **Apps > Installed apps >
fail2commit > Uninstall** to remove the application. Before removing the
application, `fail2commit uninstall-integrations` removes only integration
changes recorded as owned by fail2commit; unrelated Git hooks and settings are
left intact.

Windows on Arm, system-wide unattended installation, and non-x64 Windows are
not supported by the initial release. Git Bash and PowerShell behavior must be
verified separately for each release.

## Debian/Ubuntu amd64

```sh
sha256sum -c SHA256SUMS --ignore-missing
sudo dpkg -i fail2commit_<version>_amd64.deb
fail2commit --version
fail2commit status
fail2commit setup
```

Remove owned integrations before removing the binary, if setup was used:

```sh
fail2commit uninstall-integrations
sudo dpkg -r fail2commit
sudo dpkg --purge fail2commit
```

The package contains no maintainer scripts and never edits a home directory.
It installs `/usr/bin/fail2commit` and documentation under
`/usr/share/doc/fail2commit`. Debian/Ubuntu architectures other than amd64 are
not supplied as binary packages.

## Arch Linux and Arch-based x86_64 (pacman)

For Arch, Manjaro, EndeavourOS and other pacman-based distributions. Install
the release package:

```sh
sha256sum -c SHA256SUMS --ignore-missing
sudo pacman -U fail2commit-<version>-1-x86_64.pkg.tar.zst
fail2commit status
fail2commit setup
```

Or build it yourself from the source archive (offline; the crates are
vendored). Put the PKGBUILD from `packaging/arch/` and the source archive in
one directory, then:

```sh
sudo pacman -S --needed base-devel rust
makepkg -si
```

The package depends on `git` and `bubblewrap`; `nodejs`/`npm` and `python`
are optional and only needed for the matching guards. It has no install
scriptlet and never edits a home directory: it installs
`/usr/bin/fail2commit`, licenses under `/usr/share/licenses/fail2commit` and
documentation under `/usr/share/doc/fail2commit`. Run `fail2commit sandbox
status` from a normal login session: the cgroup v2 job limits need your
systemd user manager.

To remove:

```sh
fail2commit uninstall-integrations
sudo pacman -R fail2commit
```

## Linux source archive

The source archive contains `Cargo.lock`, vendored crates, and Cargo source
replacement configuration. A Rust 1.x toolchain and native C build tools are
required; no network access is needed:

```sh
tar -xzf fail2commit-<version>-src.tar.gz
cd fail2commit-<version>-src
cargo build --release --locked --offline -p fail2commit
install -m 0755 target/release/fail2commit "$HOME/.local/bin/fail2commit"
fail2commit setup
```

To uninstall, run `fail2commit uninstall-integrations`, then remove the binary
you installed and the extracted source directory. Building on macOS, non-amd64
Linux, musl, or non-GNU userlands is not a release-tested path.

## VS Code VSIX

In VS Code, choose **Extensions: Install from VSIX...** and select
`fail2commit-<version>.vsix`, or use:

```text
code --install-extension fail2commit-<version>.vsix
```

Uninstall it from the Extensions view or with `code --uninstall-extension`
using the extension identifier shown by `code --list-extensions`. Native VS
Code on Windows and Linux and a workspace-side Linux CLI in WSL are separate
release verification targets. Web VS Code, remote hosts other than the tested
WSL path, and editor forks are not initially supported.
