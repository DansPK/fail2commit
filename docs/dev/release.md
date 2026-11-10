# Release process

The release workflow is intentionally manual and non-publishing. Start
`.github/workflows/release.yml` with **Run workflow** for the commit to test.
It has read-only repository permissions and uploads workflow artifacts only;
it never creates a release, pushes a ref, or publishes a package.

## Build inputs and outputs

- `Cargo.lock` is committed and every Cargo command uses `--locked`.
- `cargo-deb` 3.8.0 is installed with `--locked` inside `rust:1`, never on the
  host.
- `SOURCE_DATE_EPOCH` is the tested commit time. Release builds use one
  codegen unit, LTO, no incremental state, stripped symbols, and remapped
  checkout/target paths from `scripts/release/release-env.sh` or
  `scripts/release/build-windows.ps1`.
- `source-tarball.sh` uses `git archive`, vendors dependencies, normalizes
  timestamps and ownership, and emits a gzip stream without a timestamp.
- `notices.py` regenerates `THIRD-PARTY-NOTICES.md` from locked Cargo metadata
  and crate license files. Any copyleft, unknown, or missing license is a
  release-review flag.
- `hashes.sh` and `hashes.ps1` write deterministic `SHA256SUMS` entries for
  every file below `target/dist`.

Linux package builds and their cargo-deb installation occur in the official
Rust container. The `.deb` is tested in a clean Ubuntu 24.04 container. The
vendored source archive is rebuilt with `--network none`, `--locked`, and
`--offline`. `reproducible-linux.sh` uses two independent target volumes and
compares the Linux binary and `.deb` SHA-256 values.

The Arch package (CR-016) is built from that same source archive with
`makepkg` in a clean `archlinux` container as an unprivileged user
(`build-arch.sh`, which runs the core unit tests in `check()`). `verify-arch.sh`
then installs it with `pacman -U` in another clean container, runs `status` as
a normal user with that user's Git configuration hashed before and after, and
removes it. Arch's rolling toolchain means this package is not byte-for-byte
reproducible across days; the `.deb` and the Linux binary remain the
reproducibility references.

## Evidence required for release approval

Create a report under `docs/dev/verify/`. For every
artifact and tested platform record:

```text
tested commit: <40-character Git SHA>
artifact: <release filename>
sha256: <64 lowercase hex characters>
command: <exact command>
exit code: <integer>
platform: <OS/version/architecture or container image>
result: Pass | Fail | Pending
```

Evidence must cover clean install, `fail2commit --version`, `fail2commit
status`, uninstall/purge, preservation of a pre-existing third-party Git
configuration and hook, an offline source build, VSIX installation on each
supported editor platform, Windows Setup.exe install/uninstall, WSL CLI
selection, and a disposable protected remote. A skipped or simulated check is
Pending, not Pass. Final hashes must be generated from artifacts built at the
reported integrated commit.

Known unsupported paths are listed in [install.md](../install.md) and must be
copied into release notes. NSIS, native desktop, WSL, VS Code, and server
integration evidence remains platform-gated and must not be inferred from a
successful unit-test job.

## Licensing

fail2commit is Copyright 2026 Nut Youlong under Apache-2.0 (`LICENSE`, `NOTICE`).

Every binary artifact ships `LICENSE`, `NOTICE` and the generated `THIRD-PARTY-NOTICES.md` (`.txt` inside the Windows installer; beside the standalone binaries in `target/dist`; under `/usr/share/doc/fail2commit` in the `.deb`). Besides the Cargo crates it covers code the toolchain links in, from texts vendored in `packaging/licenses/`:

- the Rust standard library (all binaries), from the toolchain's `COPYRIGHT-library.html`;
- the MinGW-w64 runtime (Windows, `x86_64-pc-windows-gnu`), whose license requires its notice in binary distributions;
- libgcc (Windows), under the GCC Runtime Library Exception, which imposes no conditions;
- the LLVM exception and Unicode-3.0 texts referenced by dependency expressions.

The Linux binary links glibc and libgcc_s dynamically (system libraries, no notice obligation). The VSIX contains only fail2commit code and its license. When the toolchain or target changes, refresh `packaging/licenses/` and rerun `scripts/release/notices.py`.

## License elections

- `r-efi` (`MIT OR Apache-2.0 OR LGPL-2.1-or-later`): used under MIT or Apache-2.0; it is only compiled for UEFI targets (getrandom's UEFI backend) and is not part of the Windows or Linux artifacts. `notices.py` still flags it because the expression contains a copyleft alternative.
- `flatbuffers` is no longer a dependency: `sandboxrs-windows` was dropped (CR-006).

