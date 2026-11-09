#!/usr/bin/env bash
# Pack the container's gcc, binutils and libc headers as a relocatable
# sysroot (T-007a, FR-007), so the native build test can run on hosts with
# bwrap but no compiler (WSL Ubuntu). Usage: stage-gcc.sh <out.tar.gz>
set -euo pipefail
OUT=${1:?usage: stage-gcc.sh <out.tar.gz>}
S=$(mktemp -d)
pkgs=$(dpkg-query -W -f='${binary:Package}\n' |
  grep -E '^(gcc|cpp|binutils|libbinutils|libc6|libc6-dev|libc-dev-bin|linux-libc-dev|libgcc|libcrypt|libisl|libmpc|libmpfr|libgmp|libzstd|libjansson|libsframe|libctf|libgprofng|zlib1g|libz|libasan|libubsan|libtsan|liblsan|libhwasan|libitm|libatomic|libquadmath|libcc1|libgomp|libstdc)')
# Resolve the directory part only (merged /usr), keep file symlinks.
dpkg -L $pkgs | sort -u | while read -r f; do
  if [ -f "$f" ] || [ -L "$f" ]; then
    d="$(realpath "$(dirname "$f")")/$(basename "$f")"
    mkdir -p "$S$(dirname "$d")"
    cp -a "$f" "$S$d"
  fi
done
# Toolchain libraries for LD_LIBRARY_PATH, minus the libc6 runtime: the
# host's own glibc must stay in charge (mixing loaders segfaults).
mkdir "$S/f2c-libs"
libc=$(dpkg -L libc6 | xargs -n1 basename | sort -u)
for f in "$S"/usr/lib/x86_64-linux-gnu/*.so*; do
  b=$(basename "$f")
  grep -qxF "$b" <<<"$libc" || ln -s "../usr/lib/x86_64-linux-gnu/$b" "$S/f2c-libs/$b"
done
ln -s usr/lib "$S/lib"
ln -s usr/lib64 "$S/lib64"
ln -s usr/bin "$S/bin"
tar -C "$S" -czf "$OUT" .
rm -rf "$S"
echo "gcc sysroot: $(du -h "$OUT" | cut -f1) at $OUT"
