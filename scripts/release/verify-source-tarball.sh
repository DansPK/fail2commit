#!/usr/bin/env bash
set -euo pipefail

archive=${1:?usage: verify-source-tarball.sh path/to/source.tar.gz}
archive=$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")
test -f "$archive"
docker_archive=$archive
if [[ $(uname -s) == MINGW* || $(uname -s) == MSYS* ]]; then
  docker_archive=$(cygpath -w "$archive")
fi

MSYS_NO_PATHCONV=1 docker run --rm --network none -v "$docker_archive:/input/source.tar.gz:ro" rust:1 bash -euc '
  mkdir /work
  tar -xzf /input/source.tar.gz -C /work
  source_dir=$(find /work -mindepth 1 -maxdepth 1 -type d -print -quit)
  test -n "$source_dir"
  export CARGO_HOME=/tmp/cargo-home
  export CARGO_TARGET_DIR=/tmp/target
  source "$source_dir/scripts/release/release-env.sh" "$source_dir"
  cd "$source_dir"
  cargo build --release --locked --offline -p fail2commit
  test -x /tmp/target/release/fail2commit
  /tmp/target/release/fail2commit --version
'
