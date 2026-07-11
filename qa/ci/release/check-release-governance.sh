#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

required_files="
CHANGELOG.md
SECURITY.md
docs/validation/release/release-checklist.md
docs/validation/release/release-artifacts.md
docs/validation/release/release-signing.md
docs/validation/release/sbom.md
docs/validation/release/reproducible-builds.md
docs/validation/release/supported-platforms.md
docs/validation/release/msrv-policy.md
docs/validation/release/dependency-update-policy.md
docs/validation/release/security-advisory-policy.md
docs/validation/release/responsible-disclosure.md
docs/validation/release/external-review-status.md
scripts/release/generate-sbom.py
scripts/release/create-release-package.sh
scripts/release/sign-release-artifacts.sh
scripts/release/verify-release-artifacts.sh
scripts/release/create-signed-tag.sh
"

for file in $required_files; do
  test -s "$file" || {
    echo "release-governance file missing or empty: $file" >&2
    exit 1
  }
done

require_text() {
  file=$1
  text=$2
  if ! grep -Fq "$text" "$file"; then
    echo "required text missing in $file: $text" >&2
    exit 1
  fi
}

for file in Cargo.toml crates/*/Cargo.toml examples/*/Cargo.toml qa/fuzz/*/Cargo.toml qa/tests/*/Cargo.toml qa/tools/vector-gen/Cargo.toml; do
  test -f "$file" || continue
  if ! grep -Eq 'rust-version(\.workspace)?\s*=' "$file"; then
    echo "Cargo manifest missing rust-version metadata: $file" >&2
    exit 1
  fi
  if ! grep -Eq 'repository(\.workspace)?\s*=' "$file"; then
    echo "Cargo manifest missing repository metadata: $file" >&2
    exit 1
  fi
done

require_text Cargo.toml 'repository = "https://github.com/peavey2787/hydra-msg"'
require_text Cargo.toml 'rust-version = "1.88"'
require_text SECURITY.md 'https://github.com/peavey2787/hydra-msg/security/advisories/new'
require_text docs/validation/release/release-artifacts.md 'scripts/release/create-release-package.sh'
require_text docs/validation/release/release-signing.md 'scripts/release/sign-release-artifacts.sh'
require_text docs/validation/release/sbom.md 'scripts/release/generate-sbom.py'
require_text docs/validation/release/reproducible-builds.md 'SOURCE_DATE_EPOCH'
require_text docs/validation/release/msrv-policy.md 'rust-version = "1.88"'

if grep -RInE 'example\.invalid|fake security email|Production release blocker until verified|must be verified before production release|public production release remains blocked until.*private reporting|GitHub Private Vulnerability Reporting availability is unverified' README.md SECURITY.md docs CHANGELOG.md; then
  echo "stale release-governance blocker or placeholder wording found" >&2
  exit 1
fi

if find docs/project -type f 2>/dev/null | grep .; then
  echo "long-lived docs still present under docs/project" >&2
  exit 1
fi

echo "release governance checks passed"
