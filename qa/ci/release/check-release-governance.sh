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
  if ! grep -Fq -- "$text" "$file"; then
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
require_text .github/workflows/ci.yml 'Core bounded CI'
require_text .github/workflows/ci.yml './qa/ci/core/check-tests.sh --skip-vectors --skip-release-static'
require_text .github/workflows/ci.yml './qa/ci/core/check-examples.sh'
require_text .github/workflows/ci.yml 'Browser lifecycle'
require_text .github/workflows/ci.yml 'HYDRA_RUN_BROWSER_E2E: "1"'
require_text .github/workflows/ci.yml './qa/ci/reliability/check-browser-e2e.sh'
require_text .github/workflows/ci.yml 'Deterministic fuzz regression'
require_text .github/workflows/ci.yml './qa/ci/fuzz/check-fuzz.sh'
require_text .github/workflows/ci.yml 'HYDRA_CI_EPHEMERAL_LOCK_REFRESH: "1"'
require_text .github/workflows/ci.yml 'cargo fetch'
require_text .github/workflows/ci.yml 'target/ci-logs/core.log'
require_text .github/workflows/ci.yml 'target/ci-logs/browser-lifecycle.log'
require_text .github/workflows/ci.yml 'target/ci-logs/fuzz-regression.log'
require_text qa/ci/core/check-rust.sh 'cargo metadata --locked'
require_text qa/ci/security/check-supply-chain.sh 'cargo fetch --locked'
require_text qa/ci/fuzz/check-fuzz.sh 'cargo run --locked -p hydra-fuzz-gate --'
require_text qa/ci/fuzz/check-fuzz.sh 'HYDRA_RUN_COVERAGE_GUIDED_FUZZ'
require_text qa/ci/check-all.sh 'fuzz_mode=${HYDRA_FUZZ_MODE:-smoke}'
require_text qa/ci/check-all.sh 'fuzz_runs=${fuzz_runs:-256}'
require_text qa/ci/check-all.sh '--overnight'
require_text qa/ci/check-all.sh '--deep-fuzz'
require_text qa/ci/fuzz/check-fuzz.sh 'message_stateful_flow'
require_text qa/ci/fuzz/check-fuzz.sh 'cargo fuzz build --fuzz-dir "$FUZZ_DIR"'
require_text qa/ci/fuzz/check-fuzz.ps1 'cargo fuzz build --fuzz-dir $FuzzDir'
require_text qa/fuzz/cargo-fuzz/fuzz_targets/group_commit_message_parser.rs 'encode_roster(GroupMode::Lite, &roster)'
require_text qa/ci/fuzz/check-fuzz.sh 'FAST_BUDGET="${HYDRA_COVERAGE_FUZZ_RUNS:-256}"'
require_text qa/ci/fuzz/check-fuzz.sh 'FAST_BUDGET="${HYDRA_COVERAGE_FUZZ_RUNS:-100000}"'
require_text crates/hydra-msg/Cargo.toml 'fuzzing = []'
require_text qa/fuzz/cargo-fuzz/Cargo.toml 'features = ["fuzzing"]'
require_text qa/fuzz/cargo-fuzz/fuzz_targets/message_codec.rs 'fuzzing::decode_message_payload'
require_text qa/fuzz/cargo-fuzz/fuzz_targets/message_stateful_flow.rs 'common::paired'
require_text .github/workflows/ci.yml 'tee -a "$log_file"'
require_text .github/workflows/ci.yml 'GITHUB_STEP_SUMMARY'
require_text .github/workflows/release-validation.yml 'workflow_dispatch:'
require_text .github/workflows/release-validation.yml './qa/ci/check-all.sh'
require_text .github/workflows/release-validation.yml 'target/ci-logs/release-check-all.log'
require_text .github/workflows/release-validation.yml 'Full sequential release check-all'
require_text .github/workflows/release-validation.yml 'cargo install cargo-mutants --locked'
require_text .github/workflows/release-validation.yml 'cargo install cargo-fuzz --locked'
require_text .github/workflows/release-validation.yml 'tee -a "$log_file"'
require_text .github/workflows/release-validation.yml 'HYDRA_RELEASE_FUZZ_RUNS'
require_text .github/workflows/release-validation.yml '--deep-fuzz'
require_text .github/workflows/release-validation.yml 'HYDRA_RELEASE_MUTATION_JOBS'
require_text .github/workflows/release-validation.yml 'GITHUB_STEP_SUMMARY'
require_text .github/dependabot.yml 'package-ecosystem: github-actions'

if grep -Eq 'common::(paired|fresh|temp_case_dir)|import_messages' qa/fuzz/cargo-fuzz/fuzz_targets/message_codec.rs; then
  echo "fast message_codec fuzz target must remain in-memory and stateless" >&2
  exit 1
fi

if grep -RInF '${{ runner.temp }}/hydra-ci-logs' .github/workflows; then
  echo "GitHub artifact logs must stay under github.workspace, not runner.temp" >&2
  exit 1
fi

lock_mutation=$(grep -RInE 'rm -f Cargo\.lock|Remove-Item.*Cargo\.lock|cargo generate-lockfile' qa/ci \
  --include '*.sh' --include '*.ps1' \
  --exclude 'check-release-governance.sh' --exclude 'check-release-governance.ps1' || true)
workflow_lock_mutation=$(grep -RInE 'rm -f Cargo\.lock|Remove-Item.*Cargo\.lock|cargo generate-lockfile' .github/workflows \
  --include '*.yml' --include '*.yaml' || true)
if [ -n "$lock_mutation$workflow_lock_mutation" ]; then
  [ -z "$lock_mutation" ] || printf '%s\n' "$lock_mutation" >&2
  [ -z "$workflow_lock_mutation" ] || printf '%s\n' "$workflow_lock_mutation" >&2
  echo "CI must validate the committed Cargo.lock with --locked; workflows and local QA scripts must not rewrite it." >&2
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
  require_text "$workflow" 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1'
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
