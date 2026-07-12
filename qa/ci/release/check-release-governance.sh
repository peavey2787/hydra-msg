#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

required_files="
CHANGELOG.md
SECURITY.md
.github/workflows/ci.yml
.github/workflows/release-validation.yml
.github/dependabot.yml
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

require_text .github/workflows/ci.yml 'push:'
require_text .github/workflows/ci.yml 'pull_request:'
require_text .github/workflows/ci.yml 'workflow_dispatch:'
require_text .github/workflows/ci.yml './qa/ci/check-all.sh --through examples --skip-permissions'
require_text .github/workflows/ci.yml './qa/ci/check-all.sh --only browser --skip-permissions'
require_text .github/workflows/ci.yml 'target/ci-logs/rust-policy-examples.log'
require_text .github/workflows/ci.yml 'target/ci-logs/browser.log'
require_text .github/workflows/ci.yml './qa/ci/fuzz/check-fuzz.sh'
require_text .github/workflows/ci.yml '${{ github.workspace }}/fuzz-regression.log'
require_text .github/workflows/ci.yml "hashFiles('fuzz-regression.log') != ''"
require_text .github/workflows/ci.yml 'tee -a "$log_file"'
require_text .github/workflows/ci.yml 'cargo generate-lockfile'
require_text .github/workflows/ci.yml 'cargo fetch'
require_text .github/workflows/ci.yml 'GITHUB_STEP_SUMMARY'
require_text .github/workflows/release-validation.yml 'workflow_dispatch:'
require_text .github/workflows/release-validation.yml './qa/ci/check-all.sh --through examples --skip-permissions'
require_text .github/workflows/release-validation.yml 'target/ci-logs/core.log'
require_text .github/workflows/release-validation.yml 'HYDRA_RUN_COVERAGE: "1"'
require_text .github/workflows/release-validation.yml 'HYDRA_RUN_MUTATION: "1"'
require_text .github/workflows/release-validation.yml 'HYDRA_RUN_COVERAGE_GUIDED_FUZZ: "1"'
require_text .github/workflows/release-validation.yml '${{ github.workspace }}/release-fuzz.log'
require_text .github/workflows/release-validation.yml "hashFiles('release-fuzz.log') != ''"
require_text .github/workflows/release-validation.yml 'tee -a "$log_file"'
require_text .github/workflows/release-validation.yml 'cargo generate-lockfile'
require_text .github/workflows/release-validation.yml 'cargo fetch'
require_text .github/workflows/release-validation.yml 'GITHUB_STEP_SUMMARY'
require_text .github/dependabot.yml 'package-ecosystem: github-actions'

if grep -RInF '${{ runner.temp }}/hydra-ci-logs' .github/workflows; then
  echo "GitHub artifact logs must stay under github.workspace, not runner.temp" >&2
  exit 1
fi

unpinned_actions=$(grep -RInE '^[[:space:]]*uses:[[:space:]]+[^[:space:]]+@' .github/workflows \
  | grep -vE '@[0-9a-fA-F]{40}([[:space:]]|#|$)' || true)
if [ -n "$unpinned_actions" ]; then
  printf '%s\n' "$unpinned_actions" >&2
  echo "GitHub Actions must be pinned to immutable 40-character commit SHAs" >&2
  exit 1
fi
for workflow in .github/workflows/ci.yml .github/workflows/release-validation.yml; do
  require_text "$workflow" 'actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0'
  require_text "$workflow" 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2'
done
require_text .github/workflows/ci.yml 'actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0'
require_text .github/workflows/release-validation.yml 'actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0'

if grep -RInE 'example\.invalid|fake security email|Production release blocker until verified|must be verified before production release|public production release remains blocked until.*private reporting|GitHub Private Vulnerability Reporting availability is unverified' README.md SECURITY.md docs CHANGELOG.md; then
  echo "stale release-governance blocker or placeholder wording found" >&2
  exit 1
fi

if find docs/project -type f 2>/dev/null | grep .; then
  echo "long-lived docs still present under docs/project" >&2
  exit 1
fi

echo "release governance checks passed"
