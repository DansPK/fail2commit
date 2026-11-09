#!/usr/bin/env bash
set -euo pipefail

dist=${1:-target/dist}
mkdir -p "$dist"
dist=$(cd "$dist" && pwd)
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

(
  cd "$dist"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | while IFS= read -r -d '' file; do
    hash=$(sha256sum "$file" | cut -d ' ' -f 1)
    printf '%s  %s\n' "$hash" "${file#./}"
  done
) > "$tmp"
mv "$tmp" "$dist/SHA256SUMS"
