#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
commit=${1:-HEAD}
out=${2:-target/dist}
commit=$(git -C "$repo" rev-parse --verify "${commit}^{commit}")
epoch=$(git -C "$repo" show -s --format=%ct "$commit")
version=$(git -C "$repo" show "${commit}:Cargo.toml" | sed -n 's/^version = "\([^"]*\)"/\1/p' | head -n 1)

if [[ -z "$version" ]]; then
  echo "could not determine workspace version at $commit" >&2
  exit 2
fi
if ! git -C "$repo" diff-index --quiet "$commit" --; then
  echo "tracked files differ from $commit; commit release inputs first" >&2
  exit 2
fi
if [[ ! -f "$repo/THIRD-PARTY-NOTICES.md" ]]; then
  echo "THIRD-PARTY-NOTICES.md is missing; run notices.py first" >&2
  exit 2
fi

mkdir -p "$repo/$out"
target_volume=${F2C_TARGET_VOLUME:-f2c-t011-deb-target}

docker run --rm \
  -v "$repo:/src" \
  -v "$target_volume:/target" \
  -e CARGO_TARGET_DIR=/target \
  -e SOURCE_DATE_EPOCH="$epoch" \
  -e RELEASE_VERSION="$version" \
  -e RELEASE_OUT="/src/$out" \
  -w /src \
  rust:1 \
  bash -euc '
    cargo install cargo-deb --version 3.8.0 --locked
    source scripts/release/release-env.sh /src
    cargo deb --locked --manifest-path crates/fail2commit/Cargo.toml --target x86_64-unknown-linux-gnu
    deb=$(find /target/debian -maxdepth 1 -type f -name "*.deb" -print -quit)
    test -n "$deb"
    cp "$deb" "$RELEASE_OUT/fail2commit_${RELEASE_VERSION}_amd64.deb"
    cp /target/x86_64-unknown-linux-gnu/release/fail2commit "$RELEASE_OUT/fail2commit-${RELEASE_VERSION}-linux-amd64"
  '

printf 'built %s\n' "$repo/$out/fail2commit_${version}_amd64.deb"
