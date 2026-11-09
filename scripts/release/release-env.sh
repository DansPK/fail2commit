#!/usr/bin/env bash
# Reproducible Rust release settings. Source this file from a release shell.
set -euo pipefail

release_root="${1:-$(git rev-parse --show-toplevel)}"
release_target="${CARGO_TARGET_DIR:-${release_root}/target}"
release_sep=$'\x1f'

export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_INCREMENTAL=false
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${release_root}=/usr/src/fail2commit${release_sep}--remap-path-prefix=${release_target}=/usr/src/fail2commit-target"

unset release_root release_target release_sep
