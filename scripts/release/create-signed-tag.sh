#!/usr/bin/env sh
set -eu

usage() {
  echo "usage: $0 vX.Y.Z [gpg-key-id]" >&2
}

version=${1:-}
[ -n "$version" ] || { usage; exit 2; }
key=${2:-}
command -v git >/dev/null 2>&1 || { echo "missing required tool: git" >&2; exit 1; }

if git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
  echo "tag already exists: $version" >&2
  exit 1
fi

msg="HYDRA-MSG $version"
if [ -n "$key" ]; then
  git tag -s "$version" -u "$key" -m "$msg"
else
  git tag -s "$version" -m "$msg"
fi

git tag -v "$version"
printf 'Signed Git tag created: %s\n' "$version"
printf 'Push after final verification with:\n  git push origin %s\n' "$version"
