# SPEC-011 — Distribution

FR-011 · TC-011 · Owner paths: packaging/linux, shared CI/release jobs, installation docs.

Ship Windows x64 NSIS installer, Debian/Ubuntu amd64 .deb via cargo-deb, Linux Cargo source build, and VSIX. The .deb installs binaries/docs and leaves per-user hook/shim setup to fail2commit setup. Provide pinned dependencies, committed lockfiles, artifact hashes and dependency/license notices. Use Windows and Linux CI for format, clippy, tests and packaging. Separate platform-gated integration checks and record real desktop, WSL, and sandbox results. Do not use live credentials, publish, or push from the implementation run. Store release verification evidence with the artifact SHA and report known unsupported paths.
