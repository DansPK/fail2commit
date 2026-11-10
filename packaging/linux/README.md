# Linux package

The Debian/Ubuntu amd64 package is described by `[package.metadata.deb]` in
`crates/fail2commit/Cargo.toml` and built only in the official Rust container:

```sh
python3 scripts/release/notices.py
scripts/release/build-deb.sh HEAD target/dist
scripts/release/verify-deb.sh target/dist/fail2commit_0.1.3_amd64.deb
```

The package has no maintainer scripts. It installs the CLI and documentation
only; `fail2commit setup` is the explicit, per-user integration step.
