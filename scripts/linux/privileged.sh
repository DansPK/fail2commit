#!/usr/bin/env bash
# Inside `docker run --privileged rust:1`: install bubblewrap, then run the
# bundle as an unprivileged user (real root bypasses RLIMIT_NPROC, so the
# process-limit tests must not run as root). T-007a, FR-007.
# Usage: privileged.sh <bundle-dir> [name-regex]
set -euo pipefail
apt-get update -qq
apt-get install -y -qq bubblewrap
id f2c 2>&1 | grep -q uid || useradd -m -u 1000 f2c
exec setpriv --reuid=f2c --regid=f2c --init-groups \
  env -i HOME=/home/f2c PATH=/usr/local/bin:/usr/bin:/bin TMPDIR=/tmp \
  bash "$(dirname "$0")/run-bundle.sh" "$@"
