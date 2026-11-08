#!/usr/bin/env bash
# Inside `docker run --privileged rust:1` (image's real /usr/bin/gcc): install
# bubblewrap, then run `run.sh measure` as an unprivileged user so the native
# build goes through the real bwrap sandbox (T-012, NFR-012). The CLI's `run`
# cannot bind a staged gcc sysroot, so hosts without a root-owned gcc (WSL)
# report the native build as unmeasurable; this container covers it.
# Usage: privileged.sh <out-dir> [runs]   (<out-dir>/bin/fail2commit exists;
# result: <out-dir>/linux-privileged.json). No systemd: rlimit-only limits.
set -euo pipefail
OUT=${1:?out dir}
RUNS=${2:-20}
apt-get update -qq
apt-get install -y -qq bubblewrap
id f2c 2>&1 | grep -q uid || useradd -m -u 1000 f2c
W=/tmp/f2c-bench-priv
rm -rf "$W"; mkdir -p "$W"; cp -r "$OUT/bin" "$W/bin"
R=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$W/src/scripts" "$W/src/tests/fixtures"
cp -r "$R/scripts/bench" "$W/src/scripts/"
cp -r "$R/tests/fixtures/sandbox" "$W/src/tests/fixtures/"
chown -R f2c:f2c "$W"
setpriv --reuid=f2c --regid=f2c --init-groups \
  env -i HOME=/home/f2c PATH=/usr/local/bin:/usr/bin:/bin TMPDIR=/tmp \
  bash "$W/src/scripts/bench/run.sh" measure "$W" "$RUNS"
cp "$W/linux.json" "$OUT/linux-privileged.json"
