#!/usr/bin/env sh
set -eu

version=${1:-}
[ -n "$version" ] || { echo "usage: $0 vX.Y.Z" >&2; exit 2; }
release_dir="release-artifacts/$version"
[ -d "$release_dir" ] || { echo "missing release directory: $release_dir" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "missing required tool: sha256sum" >&2; exit 1; }

(
  cd "$release_dir"
  sha256sum -c SHA256SUMS.txt
)

if [ -f "$release_dir/SHA256SUMS.txt.asc" ]; then
  command -v gpg >/dev/null 2>&1 || { echo "gpg is required to verify SHA256SUMS.txt.asc" >&2; exit 1; }
  gpg --verify "$release_dir/SHA256SUMS.txt.asc" "$release_dir/SHA256SUMS.txt"
else
  echo "warning: no detached signature found at $release_dir/SHA256SUMS.txt.asc" >&2
  exit 1
fi

printf 'Release artifacts verified: %s\n' "$release_dir"
