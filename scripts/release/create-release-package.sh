#!/usr/bin/env sh
set -eu

usage() {
  echo "usage: $0 vX.Y.Z" >&2
  echo "example: $0 v0.1.0" >&2
}

case "${1:-}" in
  v[0-9]*.[0-9]*.[0-9]*|v[0-9]*.[0-9]*.[0-9]*-*) version=$1 ;;
  *) usage; exit 2 ;;
esac

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$repo_root"

if [ "${HYDRA_RELEASE_ALLOW_DIRTY:-0}" != "1" ] && [ -n "$(git status --porcelain)" ]; then
  echo "refusing to create release package from a dirty working tree" >&2
  echo "commit changes first, or set HYDRA_RELEASE_ALLOW_DIRTY=1 for a local dry run" >&2
  exit 1
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required release tool: $1" >&2
    exit 1
  fi
}

need cargo
need git
need python3
need sha256sum
need gzip

git_commit=$(git rev-parse HEAD)
source_epoch=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH="$source_epoch"

release_dir="release-artifacts/$version"
rm -rf "$release_dir"
mkdir -p "$release_dir/sbom" "$release_dir/crates" "$release_dir/logs"

printf '==> release package: %s\n' "$version"
printf '==> commit: %s\n' "$git_commit"

# Deterministic source archive. `git archive` uses commit metadata, and `gzip -n`
# removes gzip filename/timestamp fields.
archive_prefix="hydra-msg-${version#v}/"
git archive --format=tar --prefix="$archive_prefix" HEAD | gzip -n > "$release_dir/hydra-msg-$version-source.tar.gz"

# Rebuild the archive once and compare the hash so reproducibility is tested during packaging.
tmp_archive=$(mktemp)
git archive --format=tar --prefix="$archive_prefix" HEAD | gzip -n > "$tmp_archive"
if ! cmp -s "$release_dir/hydra-msg-$version-source.tar.gz" "$tmp_archive"; then
  rm -f "$tmp_archive"
  echo "source archive reproducibility check failed" >&2
  exit 1
fi
rm -f "$tmp_archive"

printf '==> cargo package workspace members\n'
# Let Cargo verify package manifests and collect .crate archives for maintained crates.
: > "$release_dir/logs/cargo-package.log"
for manifest in crates/*/Cargo.toml; do
  echo "==> cargo package --manifest-path $manifest" >> "$release_dir/logs/cargo-package.log"
  cargo package --manifest-path "$manifest" --locked --allow-dirty >> "$release_dir/logs/cargo-package.log" 2>&1
done
find target/package -maxdepth 1 -type f -name '*.crate' -exec cp {} "$release_dir/crates/" \;

printf '==> generate SBOM\n'
python3 scripts/release/generate-sbom.py --repo . --version "$version" --output "$release_dir/sbom/hydra-msg-$version-cyclonedx.json"
cargo metadata --locked --format-version 1 > "$release_dir/sbom/hydra-msg-$version-cargo-metadata.json"

cat > "$release_dir/RELEASE-MANIFEST.txt" <<EOF
HYDRA-MSG release manifest
version: $version
git_commit: $git_commit
source_date_epoch: $source_epoch
repository: https://github.com/peavey2787/hydra-msg
msrv: 1.88
license: GPL-2.0-or-later
security_policy: SECURITY.md
private_vulnerability_reporting: https://github.com/peavey2787/hydra-msg/security/advisories/new

Required evidence before publication:
- check-all green
- supply-chain green
- Miri evidence archived
- sanitizer evidence archived
- browser E2E evidence archived
- coverage-guided fuzz evidence archived
- coverage report archived
- mutation testing evidence archived or documented exception
- external review status documented
- artifacts hashed and signed
- signed Git tag published
EOF

printf '==> hash artifacts\n'
(
  cd "$release_dir"
  find . -type f \
    ! -name 'SHA256SUMS.txt' \
    ! -name 'SHA256SUMS.txt.asc' \
    ! -name '*.asc' \
    -print | LC_ALL=C sort | sed 's#^./##' | xargs sha256sum > SHA256SUMS.txt
)

printf '\nRelease package created: %s\n' "$release_dir"
printf 'Next:\n  scripts/release/sign-release-artifacts.sh %s\n  scripts/release/verify-release-artifacts.sh %s\n' "$version" "$version"
