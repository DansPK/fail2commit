#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
commit=${1:-HEAD}
out=${2:-target/dist}
commit=$(git -C "$repo" rev-parse --verify "${commit}^{commit}")
version=$(git -C "$repo" show "${commit}:Cargo.toml" | sed -n 's/^version = "\([^"]*\)"/\1/p' | head -n 1)

if [[ -z "$version" ]]; then
  echo "could not determine workspace version at $commit" >&2
  exit 2
fi

echo "Building fail2commit $version for aarch64-apple-darwin at $commit"

cd "$repo"
cargo build --release --locked --target aarch64-apple-darwin

dist_dir="$repo/$out"
mkdir -p "$dist_dir"

archive_name="fail2commit-${version}-aarch64-apple-darwin"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$archive_name"

# Copy release binaries
cp "$repo/target/aarch64-apple-darwin/release/fail2commit" "$stage/$archive_name/"
if [[ -f "$repo/target/aarch64-apple-darwin/release/fail2commit-tray" ]]; then
  cp "$repo/target/aarch64-apple-darwin/release/fail2commit-tray" "$stage/$archive_name/"
fi
if [[ -f "$repo/target/aarch64-apple-darwin/release/f2c-sandbox-relay" ]]; then
  cp "$repo/target/aarch64-apple-darwin/release/f2c-sandbox-relay" "$stage/$archive_name/"
fi

# Copy licenses, notices, and README
cp "$repo/LICENSE" "$stage/$archive_name/"
cp "$repo/NOTICE" "$stage/$archive_name/"
if [[ -f "$repo/THIRD-PARTY-NOTICES.md" ]]; then
  cp "$repo/THIRD-PARTY-NOTICES.md" "$stage/$archive_name/"
fi
cp "$repo/README.md" "$stage/$archive_name/"

# Unsigned build note
cat << 'NOTE' > "$stage/$archive_name/README-MACOS.txt"
fail2commit for macOS (Apple Silicon / aarch64-apple-darwin)

NOTE ON UNSIGNED BUILD & GATEKEEPER QUARANTINE:
This release is not yet signed with an Apple Developer ID certificate.
If macOS Gatekeeper prevents execution ("cannot be opened because the developer cannot be verified"),
clear the quarantine attribute from the extracted binaries using:

    xattr -d com.apple.quarantine fail2commit*

SANDBOX LIMITATION:
There is currently no sandbox backend for macOS (a Seatbelt backend is planned in P-211).
Installs or jobs requiring sandbox isolation fail closed by design ("no sandbox backend on macOS yet").
Git push protection, scan checks, and offline scriptless installs remain fully supported.
NOTE

# Package tar.gz
tar -czf "$dist_dir/${archive_name}.tar.gz" -C "$stage" "$archive_name"

# Generate sha256
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$dist_dir" && sha256sum "${archive_name}.tar.gz" > "${archive_name}.tar.gz.sha256")
else
  (cd "$dist_dir" && shasum -a 256 "${archive_name}.tar.gz" > "${archive_name}.tar.gz.sha256")
fi

echo "Created $dist_dir/${archive_name}.tar.gz"
echo "Created $dist_dir/${archive_name}.tar.gz.sha256"
