#!/usr/bin/env bash
# Build the Arch Linux package (FR-011; CR-016) from the release source
# tarball with makepkg in a clean archlinux container, as an unprivileged
# build user. usage: build-arch.sh path/to/fail2commit-<ver>-src.tar.gz [out]
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
src=${1:?usage: build-arch.sh path/to/fail2commit-<ver>-src.tar.gz [out]}
out=${2:-target/dist}
src=$(cd "$(dirname "$src")" && pwd)/$(basename "$src")
test -f "$src"
mkdir -p "$repo/$out"
docker_repo=$repo
docker_src=$src
if [[ $(uname -s) == MINGW* || $(uname -s) == MSYS* ]]; then
  docker_repo=$(cygpath -w "$repo")
  docker_src=$(cygpath -w "$src")
fi

MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$docker_repo/packaging/arch/PKGBUILD:/input/PKGBUILD:ro" \
  -v "$docker_src:/input/$(basename "$src"):ro" \
  -v "$docker_repo/$out:/out" \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  archlinux:latest \
  bash -euc '
    pacman -Syu --noconfirm --needed base-devel rust git bubblewrap > /tmp/pacman.log
    useradd --create-home builder
    install -d -o builder -g builder /home/builder/pkg
    cp /input/PKGBUILD /input/*.tar.gz /home/builder/pkg/
    chown -R builder:builder /home/builder/pkg
    su builder -c "cd /home/builder/pkg && MAKEFLAGS=-j\${CARGO_BUILD_JOBS:-2} makepkg --force --noconfirm --cleanbuild"
    cp /home/builder/pkg/*.pkg.tar.zst /out/
    ls -l /out/*.pkg.tar.zst
  '
