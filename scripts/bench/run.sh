#!/usr/bin/env bash
# Linux resource benchmarks for fail2commit (T-012, NFR-012, SPEC-012, TC-012).
#
#   run.sh build <out-dir>           in the rust:1 container: release build
#       (cargo -j 2) of fail2commit into <out-dir>/bin.
#   run.sh measure <out-dir> [runs]  on a host with python3 (and bwrap for the
#       sandbox build, e.g. WSL Ubuntu): measures <out-dir>/bin/fail2commit.
#       Results: <out-dir>/linux.json. The sandbox native build needs a
#       root-owned /usr/bin/gcc, so it is Pending on WSL;
#       scripts/bench/privileged.sh (rust:1 --privileged + bwrap) measures it.
#
# Example (from Windows): docker run --rm -v "$PWD:/src" -v f2c-bench-target:/target \
#   -v "$PWD/target/bench-linux:/out" -e CARGO_TARGET_DIR=/target -w /src rust:1 \
#   bash scripts/bench/run.sh build /out ; then in WSL: bash scripts/bench/run.sh measure <path> 20
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MODE=${1:?usage: run.sh build|measure <out-dir> [runs]}
OUT=${2:?out dir}
case $MODE in
  build)
    cd "$HERE/../.."
    echo "tested sha: $(git rev-parse HEAD 2>&1 || echo unknown)"
    echo "rustc: $(rustc --version)"
    CARGO_BUILD_JOBS=2 cargo build --release -j 2 -p fail2commit
    mkdir -p "$OUT/bin"
    cp "${CARGO_TARGET_DIR:-target}/release/fail2commit" "$OUT/bin/"
    ;;
  measure)
    RUNS=${3:-20}
    # Copy out of /mnt/c: DrvFs would dominate the startup numbers.
    W=$(mktemp -d "${TMPDIR:-/tmp}/f2c-bench-bin.XXXXXX")
    cp -r "$OUT/bin" "$W/bin"
    echo "host: $(uname -sr); bwrap: $(bwrap --version 2>&1 || echo missing)"
    python3 -I "$HERE/bench.py" measure --bin-dir "$W/bin" --out "$OUT/linux.json" --runs "$RUNS"
    rm -rf "$W"
    ;;
  *) echo "unknown mode $MODE" >&2; exit 2 ;;
esac
