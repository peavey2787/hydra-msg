#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/lib/repo-root.sh"
hydra_enter_repo_root

usage() {
  cat <<'USAGE'
Usage: qa/ci/check-all.sh [options]

Run the complete HYDRA release-validation pipeline by default. The runner stops on the first failing section, or resumes/selects sections when flags are provided.

Section selection:
  --from SECTION            Start at SECTION and run everything after it.
  --resume-from SECTION     Alias for --from.
  --start-at SECTION        Alias for --from.
  --through SECTION         Stop after SECTION.
  --stop-after SECTION      Alias for --through.
  --only SECTION            Run exactly one SECTION.
  --section SECTION         Alias for --only.
  --list-sections           Print valid section names and exit.

Sections, in execution order:
  permissions, tests, examples, miri, sanitizers, browser, coverage, mutation, fuzz

Granular skips:
  --skip-permissions        Skip Linux executable-permission repair.
  --skip-tests              Skip workspace tests/static validation.
  --skip-examples           Skip example validation.
  --skip-miri               Skip Miri release evidence.
  --skip-sanitizers         Skip sanitizer release evidence.
  --skip-browser            Skip real-browser Playwright evidence.
  --skip-coverage           Skip measured LCOV/HTML coverage evidence.
  --skip-mutation           Skip cargo-mutants evidence.
  --skip-fuzz               Skip coverage-guided fuzz evidence.

Nested-gate options:
  --skip-vectors            Pass --skip-vectors to core/check-tests.sh.
  --skip-wasm               Pass --skip-wasm to core/check-examples.sh.
  --skip-browser-install    Reuse installed Playwright browser binaries.
  --skip-mutation-baseline  Skip cargo-mutants' clean baseline after separate green tests.
  --mutation-timeout N      Seconds allowed per mutant when the baseline is skipped.
  --mutation-timeout-multiplier N
                            Multiplier applied to the measured mutation baseline.
  --mutation-minimum-timeout N
                            Minimum seconds allowed per mutant after baseline measurement.
  --mutation-jobs N         Number of concurrent cargo-mutants jobs.
  --fuzz-runs N             Override coverage-guided runs per fuzz target.

Other:
  -h, --help                Show this help.

Examples:
  qa/ci/check-all.sh
  qa/ci/check-all.sh --from browser
  qa/ci/check-all.sh --resume-from browser
  qa/ci/check-all.sh --from coverage --through mutation
  qa/ci/check-all.sh --only browser --skip-browser-install
  qa/ci/check-all.sh --from mutation --skip-mutation-baseline
  qa/ci/check-all.sh --skip-miri --skip-sanitizers --skip-fuzz
USAGE
}

list_sections() {
  printf '%s\n' permissions tests examples miri sanitizers browser coverage mutation fuzz
}

normalize_section() {
  case "$1" in
    permissions|permission) printf '%s\n' permissions ;;
    tests|test|static) printf '%s\n' tests ;;
    examples|example) printf '%s\n' examples ;;
    miri) printf '%s\n' miri ;;
    sanitizers|sanitizer) printf '%s\n' sanitizers ;;
    browser|browsers|playwright|browser-e2e) printf '%s\n' browser ;;
    coverage|llvm-cov) printf '%s\n' coverage ;;
    mutation|mutants) printf '%s\n' mutation ;;
    fuzz|fuzzing) printf '%s\n' fuzz ;;
    *)
      echo "unknown validation section: $1" >&2
      echo "valid sections: $(list_sections | tr '\n' ' ')" >&2
      exit 2
      ;;
  esac
}

section_rank() {
  case "$1" in
    permissions) printf '%s\n' 1 ;;
    tests) printf '%s\n' 2 ;;
    examples) printf '%s\n' 3 ;;
    miri) printf '%s\n' 4 ;;
    sanitizers) printf '%s\n' 5 ;;
    browser) printf '%s\n' 6 ;;
    coverage) printf '%s\n' 7 ;;
    mutation) printf '%s\n' 8 ;;
    fuzz) printf '%s\n' 9 ;;
    *)
      echo "internal error: unranked section $1" >&2
      exit 2
      ;;
  esac
}

require_value() {
  option=$1
  value=${2:-}
  if [ -z "$value" ]; then
    echo "$option requires a value" >&2
    usage >&2
    exit 2
  fi
}

require_positive_integer() {
  option=$1
  value=$2
  case "$value" in
    ''|*[!0-9]*|0)
      echo "$option requires a positive integer, got: $value" >&2
      exit 2
      ;;
  esac
}

require_positive_number() {
  option=$1
  value=$2
  if ! awk -v value="$value" 'BEGIN { exit !(value ~ /^[0-9]+([.][0-9]+)?$/ && value + 0 > 0) }'; then
    echo "$option requires a positive number, got: $value" >&2
    exit 2
  fi
}

from_section=permissions
through_section=fuzz
only_section=
from_was_set=0
through_was_set=0
skip_permissions=0
skip_tests=0
skip_examples=0
skip_miri=0
skip_sanitizers=0
skip_browser=0
skip_coverage=0
skip_mutation=0
skip_fuzz=0
skip_vectors=0
skip_wasm=0
skip_browser_install=0
skip_mutation_baseline=0
mutation_timeout=${HYDRA_MUTATION_TIMEOUT:-1200}
mutation_timeout_multiplier=${HYDRA_MUTATION_TIMEOUT_MULTIPLIER:-2}
mutation_minimum_timeout=${HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT:-120}
mutation_jobs=${HYDRA_MUTATION_JOBS:-1}
fuzz_runs=${HYDRA_COVERAGE_FUZZ_RUNS:-100000}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from|--resume-from|--start-at)
      require_value "$1" "${2:-}"
      from_section=$(normalize_section "$2")
      from_was_set=1
      shift 2
      ;;
    --from=*|--resume-from=*|--start-at=*)
      from_section=$(normalize_section "${1#*=}")
      from_was_set=1
      shift
      ;;
    --through|--stop-after)
      require_value "$1" "${2:-}"
      through_section=$(normalize_section "$2")
      through_was_set=1
      shift 2
      ;;
    --through=*|--stop-after=*)
      through_section=$(normalize_section "${1#*=}")
      through_was_set=1
      shift
      ;;
    --only|--section)
      require_value "$1" "${2:-}"
      only_section=$(normalize_section "$2")
      shift 2
      ;;
    --only=*|--section=*)
      only_section=$(normalize_section "${1#*=}")
      shift
      ;;
    --list-sections)
      list_sections
      exit 0
      ;;
    --skip-permissions) skip_permissions=1; shift ;;
    --skip-tests) skip_tests=1; shift ;;
    --skip-examples) skip_examples=1; shift ;;
    --skip-miri) skip_miri=1; shift ;;
    --skip-sanitizers) skip_sanitizers=1; shift ;;
    --skip-browser) skip_browser=1; shift ;;
    --skip-coverage) skip_coverage=1; shift ;;
    --skip-mutation) skip_mutation=1; shift ;;
    --skip-fuzz) skip_fuzz=1; shift ;;
    --skip-vectors) skip_vectors=1; shift ;;
    --skip-wasm) skip_wasm=1; shift ;;
    --skip-browser-install) skip_browser_install=1; shift ;;
    --skip-mutation-baseline) skip_mutation_baseline=1; shift ;;
    --mutation-timeout)
      require_value "$1" "${2:-}"
      require_positive_integer "$1" "$2"
      mutation_timeout=$2
      shift 2
      ;;
    --mutation-timeout=*)
      mutation_timeout=${1#*=}
      require_positive_integer --mutation-timeout "$mutation_timeout"
      shift
      ;;
    --mutation-timeout-multiplier)
      require_value "$1" "${2:-}"
      require_positive_number "$1" "$2"
      mutation_timeout_multiplier=$2
      shift 2
      ;;
    --mutation-timeout-multiplier=*)
      mutation_timeout_multiplier=${1#*=}
      require_positive_number --mutation-timeout-multiplier "$mutation_timeout_multiplier"
      shift
      ;;
    --mutation-minimum-timeout)
      require_value "$1" "${2:-}"
      require_positive_integer "$1" "$2"
      mutation_minimum_timeout=$2
      shift 2
      ;;
    --mutation-minimum-timeout=*)
      mutation_minimum_timeout=${1#*=}
      require_positive_integer --mutation-minimum-timeout "$mutation_minimum_timeout"
      shift
      ;;
    --mutation-jobs)
      require_value "$1" "${2:-}"
      require_positive_integer "$1" "$2"
      mutation_jobs=$2
      shift 2
      ;;
    --mutation-jobs=*)
      mutation_jobs=${1#*=}
      require_positive_integer --mutation-jobs "$mutation_jobs"
      shift
      ;;
    --fuzz-runs)
      require_value "$1" "${2:-}"
      require_positive_integer "$1" "$2"
      fuzz_runs=$2
      shift 2
      ;;
    --fuzz-runs=*)
      fuzz_runs=${1#*=}
      require_positive_integer --fuzz-runs "$fuzz_runs"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -n "$only_section" ]; then
  if [ "$from_was_set" -eq 1 ] || [ "$through_was_set" -eq 1 ]; then
    echo "--only cannot be combined with --from or --through" >&2
    exit 2
  fi
  from_section=$only_section
  through_section=$only_section
fi

from_rank=$(section_rank "$from_section")
through_rank=$(section_rank "$through_section")
if [ "$from_rank" -gt "$through_rank" ]; then
  echo "--from $from_section occurs after --through $through_section" >&2
  exit 2
fi

should_run() {
  section=$1
  skip=$2
  rank=$(section_rank "$section")
  [ "$skip" -eq 0 ] && [ "$rank" -ge "$from_rank" ] && [ "$rank" -le "$through_rank" ]
}

run_step() {
  name=$1
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

run_env_step() {
  name=$1
  shift
  printf '\n==> %s\n' "$name"
  env "$@"
}

ran_any=0

if should_run permissions "$skip_permissions"; then
  ran_any=1
  # ZIP extraction on Linux can strip execute bits depending on the file manager.
  # Repair repository-owned shell-script permissions before invoking nested gates.
  run_step "Linux executable permissions" sh qa/ci/core/linux-permissions.sh
fi

if should_run tests "$skip_tests"; then
  ran_any=1
  set -- qa/ci/core/check-tests.sh --skip-release-static
  if [ "$skip_vectors" -eq 1 ]; then
    set -- "$@" --skip-vectors
  fi
  run_step "tests/static validation" "$@"
fi

if should_run examples "$skip_examples"; then
  ran_any=1
  if [ "$skip_wasm" -eq 1 ]; then
    run_step "example validation" qa/ci/core/check-examples.sh --skip-wasm
  else
    run_step "example validation" qa/ci/core/check-examples.sh
  fi
fi

release_header_printed=0
print_release_header() {
  if [ "$release_header_printed" -eq 0 ]; then
    printf '\n==> release evidence gates\n'
    printf 'Supply-chain evidence is included by core/check-tests.sh when the tests section is selected.\n'
    release_header_printed=1
  fi
}

if should_run miri "$skip_miri"; then
  ran_any=1
  print_release_header
  run_env_step "Miri release evidence" \
    HYDRA_RUN_MIRI=1 \
    qa/ci/reliability/check-memory-safety.sh
fi

if should_run sanitizers "$skip_sanitizers"; then
  ran_any=1
  print_release_header
  run_env_step "sanitizer release evidence" \
    HYDRA_RUN_SANITIZERS=1 \
    qa/ci/reliability/check-memory-safety.sh
fi

if should_run browser "$skip_browser"; then
  ran_any=1
  print_release_header
  if [ "$skip_browser_install" -eq 1 ]; then
    run_env_step "real browser Playwright lifecycle evidence" \
      HYDRA_RUN_BROWSER_E2E=1 \
      HYDRA_SKIP_PLAYWRIGHT_INSTALL=1 \
      qa/ci/reliability/check-browser-e2e.sh
  else
    run_env_step "real browser Playwright lifecycle evidence" \
      HYDRA_RUN_BROWSER_E2E=1 \
      qa/ci/reliability/check-browser-e2e.sh
  fi
fi

if should_run coverage "$skip_coverage"; then
  ran_any=1
  print_release_header
  run_env_step "coverage report release evidence" \
    HYDRA_RUN_COVERAGE=1 \
    qa/ci/quality/check-coverage.sh
fi

if should_run mutation "$skip_mutation"; then
  require_positive_integer --mutation-timeout "$mutation_timeout"
  require_positive_number --mutation-timeout-multiplier "$mutation_timeout_multiplier"
  require_positive_integer --mutation-minimum-timeout "$mutation_minimum_timeout"
  require_positive_integer --mutation-jobs "$mutation_jobs"
  ran_any=1
  print_release_header
  if [ "$skip_mutation_baseline" -eq 1 ]; then
    run_env_step "mutation testing release evidence" \
      HYDRA_RUN_MUTATION=1 \
      HYDRA_MUTATION_BASELINE=skip \
      HYDRA_MUTATION_TIMEOUT="$mutation_timeout" \
      HYDRA_MUTATION_JOBS="$mutation_jobs" \
      qa/ci/quality/check-mutation.sh
  else
    run_env_step "mutation testing release evidence" \
      HYDRA_RUN_MUTATION=1 \
      HYDRA_MUTATION_BASELINE=run \
      HYDRA_MUTATION_TIMEOUT_MULTIPLIER="$mutation_timeout_multiplier" \
      HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT="$mutation_minimum_timeout" \
      HYDRA_MUTATION_JOBS="$mutation_jobs" \
      qa/ci/quality/check-mutation.sh
  fi
fi

if should_run fuzz "$skip_fuzz"; then
  require_positive_integer --fuzz-runs "$fuzz_runs"
  ran_any=1
  print_release_header
  run_env_step "overnight coverage-guided fuzz evidence" \
    HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1 \
    HYDRA_COVERAGE_FUZZ_RUNS="$fuzz_runs" \
    qa/ci/fuzz/check-fuzz.sh
fi

if [ "$ran_any" -eq 0 ]; then
  printf '\nNo validation sections were selected.\n'
else
  printf '\nHYDRA-MSG selected release validation sections passed.\n'
fi
