#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
commit=${1:-HEAD}
commit=$(git -C "$repo" rev-parse --verify "${commit}^{commit}")
run_id="f2c-repro-$$"
volume_one="${run_id}-one"
volume_two="${run_id}-two"
out_one="target/dist/repro-one"
out_two="target/dist/repro-two"

cleanup() {
  docker volume rm "$volume_one" "$volume_two" >/tmp/f2c-repro-volume-rm.log 2>&1 || true
}
trap cleanup EXIT
rm -rf "$repo/$out_one" "$repo/$out_two"
mkdir -p "$repo/$out_one" "$repo/$out_two"

F2C_TARGET_VOLUME="$volume_one" "$repo/scripts/release/build-deb.sh" "$commit" "$out_one"
F2C_TARGET_VOLUME="$volume_two" "$repo/scripts/release/build-deb.sh" "$commit" "$out_two"

status=0
for first in "$repo/$out_one"/*; do
  name=$(basename "$first")
  second="$repo/$out_two/$name"
  if [[ ! -f "$second" ]]; then
    echo "missing second-build artifact: $name" >&2
    status=1
    continue
  fi
  hash_one=$(sha256sum "$first" | cut -d ' ' -f 1)
  hash_two=$(sha256sum "$second" | cut -d ' ' -f 1)
  printf '%s  %s  %s\n' "$name" "$hash_one" "$hash_two"
  if [[ "$hash_one" != "$hash_two" ]]; then
    echo "not reproducible: $name" >&2
    status=1
  fi
done
exit "$status"
