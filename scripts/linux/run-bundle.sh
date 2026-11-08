#!/usr/bin/env bash
# Run a test bundle from container.sh on a Linux host with real bwrap and
# user namespaces (WSL Ubuntu, or the privileged container). T-007a, FR-007.
# Usage: run-bundle.sh <bundle-dir> [name-regex]
# Sets F2C_REQUIRE_SANDBOX=1 so a missing sandbox fails instead of skipping.
set -uo pipefail
SRC=${1:?usage: run-bundle.sh <bundle-dir> [name-regex]}
FILTER=${2:-}
DEST=$(mktemp -d "${TMPDIR:-/tmp}/f2c-bundle.XXXXXX")
cp -r "$SRC"/. "$DEST"/
chmod -R u+rwX,go-rwx "$DEST"
if [ -f "$DEST/gcc-root.tar.gz" ]; then
  mkdir "$DEST/gcc-root"
  tar -xzf "$DEST/gcc-root.tar.gz" -C "$DEST/gcc-root"
  export F2C_TEST_GCC_ROOT="$DEST/gcc-root" F2C_REQUIRE_NATIVE_BUILD=1
fi
export F2C_BIN="$DEST/bin/fail2commit" F2C_REQUIRE_SANDBOX=1
echo "host: $(uname -sr) uid=$(id -u) bwrap: $(bwrap --version 2>&1)"
echo "tracers: $(command -v strace ltrace || echo none)"
fail=0
for t in "$DEST"/tests/*; do
  name=$(basename "$t")
  if [ -n "$FILTER" ] && ! [[ $name =~ $FILTER ]]; then continue; fi
  echo "=== $name"
  (cd "$DEST" && "$t")
  rc=$?
  echo "=== $name exit=$rc"
  [ $rc -eq 0 ] || fail=1
done
rm -rf "$DEST"
echo "bundle result: $([ $fail -eq 0 ] && echo PASS || echo FAIL)"
exit $fail
