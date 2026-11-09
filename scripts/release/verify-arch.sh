#!/usr/bin/env bash
# Install, check and remove the Arch package in a clean archlinux container.
# The user's own Git configuration and hooks must be untouched throughout.
# usage: verify-arch.sh path/to/fail2commit-<ver>-1-x86_64.pkg.tar.zst
set -euo pipefail

pkg=${1:?usage: verify-arch.sh path/to/fail2commit.pkg.tar.zst}
pkg=$(cd "$(dirname "$pkg")" && pwd)/$(basename "$pkg")
test -f "$pkg"
docker_pkg=$pkg
if [[ $(uname -s) == MINGW* || $(uname -s) == MSYS* ]]; then
  docker_pkg=$(cygpath -w "$pkg")
fi

MSYS_NO_PATHCONV=1 docker run --rm -v "$docker_pkg:/input/fail2commit.pkg.tar.zst:ro" archlinux:latest bash -euc '
  pacman -Sy --noconfirm > /tmp/sync.log
  useradd --create-home f2ctest
  install -d -o f2ctest -g f2ctest /home/f2ctest/.config/git/hooks
  printf "%s\n" "[user]" "  name = unrelated" > /home/f2ctest/.config/git/config
  printf "%s\n" "#!/bin/sh" "exit 0" > /home/f2ctest/.config/git/hooks/pre-push
  chown -R f2ctest:f2ctest /home/f2ctest/.config
  before=$(find /home/f2ctest/.config/git -type f -print0 | sort -z | xargs -0 sha256sum)

  pacman -U --noconfirm /input/fail2commit.pkg.tar.zst > /tmp/install.log
  pacman -Qi fail2commit | grep -E "^(Name|Version|Depends On|Licenses)"
  pacman -Ql fail2commit | grep -E "/usr/bin/fail2commit$|/usr/share/licenses/fail2commit/(LICENSE|NOTICE|THIRD-PARTY-NOTICES.md)$" | wc -l | grep -qx 4
  fail2commit --version
  su -s /bin/sh f2ctest -c "HOME=/home/f2ctest FAIL2COMMIT_HOME=/home/f2ctest/f2c-home GIT_CONFIG_GLOBAL=/home/f2ctest/.config/git/config GIT_CONFIG_NOSYSTEM=1 fail2commit status"
  after_status=$(find /home/f2ctest/.config/git -type f -print0 | sort -z | xargs -0 sha256sum)
  test "$before" = "$after_status"
  test ! -e /home/f2ctest/f2c-home

  pacman -R --noconfirm fail2commit > /tmp/remove.log
  test ! -e /usr/bin/fail2commit
  test ! -e /usr/share/licenses/fail2commit
  after_remove=$(find /home/f2ctest/.config/git -type f -print0 | sort -z | xargs -0 sha256sum)
  test "$before" = "$after_remove"
  printf "%s\n" "arch package install/status/remove verification passed"
'
