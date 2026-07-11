#!/usr/bin/env sh
set -eu

usage() {
  echo "usage: $0 vX.Y.Z [gpg-key-id]" >&2
}

version=${1:-}
[ -n "$version" ] || { usage; exit 2; }
key=${2:-}
release_dir="release-artifacts/$version"
[ -d "$release_dir" ] || { echo "missing release directory: $release_dir" >&2; exit 1; }
command -v gpg >/dev/null 2>&1 || { echo "missing required signing tool: gpg" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "missing required tool: sha256sum" >&2; exit 1; }

(
  cd "$release_dir"
  find . -type f \
    ! -name 'SHA256SUMS.txt' \
    ! -name 'SHA256SUMS.txt.asc' \
    ! -name '*.asc' \
    -print | LC_ALL=C sort | sed 's#^./##' | xargs sha256sum > SHA256SUMS.txt
)

if [ -n "$key" ]; then
  gpg --local-user "$key" --armor --detach-sign --output "$release_dir/SHA256SUMS.txt.asc" "$release_dir/SHA256SUMS.txt"
else
  gpg --armor --detach-sign --output "$release_dir/SHA256SUMS.txt.asc" "$release_dir/SHA256SUMS.txt"
fi

printf 'Signed checksum manifest: %s/SHA256SUMS.txt.asc\n' "$release_dir"
printf 'Create a signed Git tag with:\n  scripts/release/create-signed-tag.sh %s%s\n' "$version" "${key:+ $key}"
