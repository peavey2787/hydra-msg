#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

manifest=qa/mutation/targets.tsv
audit=docs/validation/evidence/coverage-mutation-targets.md
output_dir=target/mutants
mutation_files_file=

cleanup() {
  if [ -n "$mutation_files_file" ] && [ -f "$mutation_files_file" ]; then
    rm -f -- "$mutation_files_file"
  fi
}
trap cleanup EXIT HUP INT TERM

require_file() {
  if [ ! -f "$1" ]; then
    echo "required mutation file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "mutation invariant missing from $file: $text" >&2
    exit 1
  fi
}

require_positive_integer() {
  name=$1
  value=$2
  case "$value" in
    ''|*[!0-9]*|0)
      echo "$name must be a positive integer, got: $value" >&2
      exit 1
      ;;
  esac
}

require_positive_number() {
  name=$1
  value=$2
  if ! awk -v value="$value" 'BEGIN { exit !(value ~ /^[0-9]+([.][0-9]+)?$/ && value + 0 > 0) }'; then
    echo "$name must be a positive number, got: $value" >&2
    exit 1
  fi
}

require_file "$manifest"
require_file "$audit"

mutation_files_file=$(mktemp "${TMPDIR:-/tmp}/hydra-mutation-files.XXXXXX")

while IFS='|' read -r id risk source_file test_file required_test focus; do
  case "$id" in
    ''|'#'*) continue ;;
  esac
  for value in "$risk" "$source_file" "$test_file" "$required_test" "$focus"; do
    if [ -z "$value" ]; then
      echo "mutation manifest row has empty field: $id" >&2
      exit 1
    fi
  done
  require_file "$source_file"
  require_file "$test_file"
  require_text "$test_file" "fn $required_test"
  require_text "$manifest" "$id|"
  if ! grep -Fxq -- "$source_file" "$mutation_files_file"; then
    printf '%s\n' "$source_file" >> "$mutation_files_file"
  fi
done < "$manifest"

if [ ! -s "$mutation_files_file" ]; then
  echo "mutation manifest contains no source targets" >&2
  exit 1
fi

for required in \
  replay-checks \
  domain-separation-labels \
  generation-rollback-checks \
  signature-verification \
  fragment-reassembly \
  group-membership-rekey \
  group-treekem-rekey
do
  require_text "$manifest" "$required|"
done

require_text "$audit" "Mutation testing target"
require_text "$audit" "replay checks"
require_text "$audit" "domain separation labels"
require_text "$audit" "generation rollback checks"
require_text "$audit" "signature verification"
require_text "$audit" "fragment reassembly"
require_text "$audit" "group membership/rekey rules"
require_text "$audit" "baseline-derived timeout"
require_text "$audit" "HYDRA_RUN_MUTATION=1"

if [ "${HYDRA_RUN_MUTATION:-0}" = "1" ]; then
  if ! cargo mutants --version >/dev/null 2>&1; then
    echo "HYDRA_RUN_MUTATION=1 requires cargo-mutants to be installed" >&2
    echo "install with: cargo install cargo-mutants --locked" >&2
    echo "or run: ./scripts/setup-dev-env.sh" >&2
    exit 1
  fi

  mutation_baseline=${HYDRA_MUTATION_BASELINE:-run}
  timeout_multiplier=${HYDRA_MUTATION_TIMEOUT_MULTIPLIER:-2}
  minimum_test_timeout=${HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT:-120}
  mutation_timeout=${HYDRA_MUTATION_TIMEOUT:-1200}
  mutation_jobs=${HYDRA_MUTATION_JOBS:-1}
  require_positive_number HYDRA_MUTATION_TIMEOUT_MULTIPLIER "$timeout_multiplier"
  require_positive_integer HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT "$minimum_test_timeout"
  require_positive_integer HYDRA_MUTATION_TIMEOUT "$mutation_timeout"
  require_positive_integer HYDRA_MUTATION_JOBS "$mutation_jobs"
  case "$mutation_baseline" in
    run|skip) ;;
    *)
      echo "HYDRA_MUTATION_BASELINE must be run or skip, got: $mutation_baseline" >&2
      exit 1
      ;;
  esac

  mkdir -p "$output_dir"

  set -- cargo mutants \
    --jobs "$mutation_jobs" \
    --output "$output_dir"
  if [ "$mutation_baseline" = "skip" ]; then
    set -- "$@" --baseline=skip --timeout "$mutation_timeout"
  else
    set -- "$@" \
      --timeout-multiplier "$timeout_multiplier" \
      --minimum-test-timeout "$minimum_test_timeout"
  fi
  while IFS= read -r source_file; do
    set -- "$@" --file "$source_file"
  done < "$mutation_files_file"

  echo "Mutation targets:"
  sed 's/^/  - /' "$mutation_files_file"
  if [ "$mutation_baseline" = "skip" ]; then
    echo "Mutation baseline: skipped by explicit request"
    echo "Mutation timeout policy: fixed ${mutation_timeout}s per mutant"
  else
    echo "Mutation baseline: required"
    echo "Mutation timeout policy: baseline-derived x${timeout_multiplier}, minimum ${minimum_test_timeout}s"
  fi
  echo "Mutation jobs: $mutation_jobs"
  "$@"
else
  echo "mutation manifest/static gate passed. Set HYDRA_RUN_MUTATION=1 to run cargo-mutants."
fi
