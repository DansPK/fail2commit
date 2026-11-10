#!/usr/bin/env bash
# Linux build/test inside the rust:1 container (T-007a, FR-007).
# Usage: container.sh <out-dir> [--no-check] [--gcc]
#   Runs fmt, clippy and the workspace tests (unless --no-check), then
#   bundles every test binary plus the fail2commit CLI into <out-dir>/bundle
#   for run-bundle.sh on a host with real bwrap. --gcc also stages a
#   relocatable gcc sysroot for the native build test.
set -euo pipefail
OUT=${1:?usage: container.sh <out-dir> [--no-check] [--gcc]}
shift
CHECK=1 GCC=0
for a in "$@"; do
  case $a in
    --no-check) CHECK=0 ;;
    --gcc) GCC=1 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
cd "$(dirname "$0")/../.."
echo "rustc: $(rustc --version)"

if [ "$CHECK" = 1 ]; then
  # The npm and pip tests need node/npm and python3 with venv; rust:1 has neither.
  if ! command -v npm >/dev/null 2>&1 || ! python3 -c 'import ensurepip, venv' >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nodejs npm python3 python3-venv python3-pip >/dev/null
  fi
  echo "node: $(node --version) npm: $(npm --version) python: $(python3 --version)"
  rustup component add rustfmt clippy
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace --no-fail-fast
fi

B="$OUT/bundle"
rm -rf "$B"
mkdir -p "$B/tests" "$B/bin"
cargo test --workspace --no-run --message-format=json |
  sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | sort -u |
  while read -r exe; do
    case $exe in
      */deps/*) cp "$exe" "$B/tests/" ;;
      *) cp "$exe" "$B/bin/" ;;
    esac
  done
cargo build -p fail2commit --bin fail2commit
cp "${CARGO_TARGET_DIR:-target}/debug/fail2commit" "$B/bin/"
if [ "$GCC" = 1 ]; then
  bash scripts/linux/stage-gcc.sh "$B/gcc-root.tar.gz"
fi
echo "bundle: $(ls "$B/tests" | wc -l) test binaries in $B"
