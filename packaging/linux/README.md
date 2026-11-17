# Linux package

The Debian/Ubuntu amd64 package is described by `[package.metadata.deb]` in
`crates/fail2commit/Cargo.toml` and built only in the official Rust container:

```sh
python3 scripts/release/notices.py
scripts/release/build-deb.sh HEAD target/dist
scripts/release/verify-deb.sh target/dist/fail2commit_0.1.4_amd64.deb
```

The package has no maintainer scripts and does not enable services or change
user integrations. It installs the CLI, its `f2c-sandbox-relay` sibling, and
documentation. Its systemd unit templates are stored under
`/usr/share/fail2commit/templates` and are copied with installer-specific
values only by `hardened install`; they are not loaded as incomplete system
units. `fail2commit setup` remains the explicit per-user integration
step. On a supported Linux host, `sudo fail2commit hardened install` installs
the separate root service and sandbox account; `fail2commit hardened status`
reports whether every mandatory platform and network effect probe passes, and
`sudo fail2commit hardened uninstall` removes only recorded service resources.
An installed service whose probe is unavailable remains fail-closed; do not
use hardened Internet jobs until status reports availability.

The optional disposable VM backend (FR-029, `sandbox.backend = "vm"`) bundles
nothing extra: it uses the host kernel and host binaries. Its runtime
dependencies are optional and must be installed by the operator:
`qemu-system-x86_64` (with the `microvm` machine and `virtio-9p-device` /
`virtio-net-device` MMIO devices), `busybox`, and `/dev/kvm` access for the
invoking user. `sudo fail2commit vm prepare` assembles the root-owned initramfs
once; `fail2commit vm status` reports it and `sudo fail2commit vm remove`
deletes it. Without KVM the backend falls back to the platform default; without
preparation it fails closed. See `docs/sandbox-linux.md` §5.
