#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
commit=${1:-HEAD}
out=${2:-target/dist}
commit=$(git -C "$repo" rev-parse --verify "${commit}^{commit}")
epoch=$(git -C "$repo" show -s --format=%ct "$commit")
version=$(git -C "$repo" show "${commit}:Cargo.toml" | sed -n 's/^version = "\([^"]*\)"/\1/p' | head -n 1)
name="fail2commit-${version}-src"

if [[ -z "$version" ]]; then
  echo "could not determine workspace version at $commit" >&2
  exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/$name" "$repo/$out"
git -C "$repo" archive --format=tar "$commit" | tar -xf - -C "$tmp/$name"
mkdir -p "$tmp/$name/.cargo"
(
  cd "$tmp/$name"
  cargo vendor --locked --versioned-dirs vendor > .cargo/config.toml
)
find "$tmp/$name" -exec touch -d "@$epoch" {} +
tar --sort=name --format=gnu --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
  -C "$tmp" -cf - "$name" | gzip -n > "$repo/$out/$name.tar.gz"

printf 'built %s\n' "$repo/$out/$name.tar.gz"
