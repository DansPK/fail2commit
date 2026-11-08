#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
deb=${1:?usage: verify-deb.sh path/to/fail2commit.deb}
deb=$(cd "$(dirname "$deb")" && pwd)/$(basename "$deb")
test -f "$deb"

docker run --rm -v "$deb:/input/fail2commit.deb:ro" ubuntu:24.04 bash -euc '
  useradd --create-home f2ctest
  install -d -o f2ctest -g f2ctest /home/f2ctest/.config/git/hooks
  printf "%s\n" "[user]" "  name = unrelated" > /home/f2ctest/.config/git/config
  printf "%s\n" "#!/bin/sh" "exit 0" > /home/f2ctest/.config/git/hooks/pre-push
  chown -R f2ctest:f2ctest /home/f2ctest/.config
  before=$(find /home/f2ctest/.config/git -type f -print0 | sort -z | xargs -0 sha256sum)

  dpkg -i /input/fail2commit.deb
  fail2commit --version
  su -s /bin/sh f2ctest -c "HOME=/home/f2ctest FAIL2COMMIT_HOME=/home/f2ctest/f2c-home GIT_CONFIG_GLOBAL=/home/f2ctest/.config/git/config GIT_CONFIG_NOSYSTEM=1 fail2commit status"
  after_status=$(find /home/f2ctest/.config/git -type f -print0 | sort -z | xargs -0 sha256sum)
  test "$before" = "$after_status"
  test ! -e /home/f2ctest/f2c-home

  dpkg -r fail2commit
  test ! -e /usr/bin/fail2commit
  test ! -e /usr/share/doc/fail2commit
  dpkg --purge fail2commit
  after_purge=$(find /home/f2ctest/.config/git -type f -print0 | sort -z | xargs -0 sha256sum)
  test "$before" = "$after_purge"
  test ! -e /home/f2ctest/f2c-home
  printf "%s\n" "deb install/status/remove/purge verification passed"
'
