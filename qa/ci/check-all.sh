#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/lib/repo-root.sh"
hydra_enter_repo_root

skip_vectors=0
skip_wasm=0
for arg in "$@"; do
  case "$arg" in
    --skip-vectors)
      skip_vectors=1
      ;;
    --skip-wasm)
      skip_wasm=1
      ;;
    *)
      echo "unknown argument: $arg" >&2
      echo "usage: $0 [--skip-vectors] [--skip-wasm]" >&2
      exit 2
      ;;
  esac
done

test_args=""
if [ "$skip_vectors" -eq 1 ]; then
  test_args="--skip-vectors"
fi

example_args=""
if [ "$skip_wasm" -eq 1 ]; then
  example_args="--skip-wasm"
fi

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

# ZIP extraction on Linux can strip execute bits depending on the file manager.
# Repair repository-owned shell-script permissions before invoking nested gates.
run_step "Linux executable permissions" sh qa/ci/core/linux-permissions.sh

# Release-complete full gate. The fast/mandatory validation runs first. The
# expensive release-evidence gates run near the bottom. The overnight
# coverage-guided fuzz campaign is intentionally last.
# shellcheck disable=SC2086
run_step "tests/static validation" qa/ci/core/check-tests.sh $test_args
# shellcheck disable=SC2086
run_step "example validation" qa/ci/core/check-examples.sh $example_args

printf '\n==> release evidence gates\n'
printf 'Supply-chain evidence is included above by core/check-tests.sh via qa/ci/security/check-supply-chain.sh.\n'

run_env_step "Miri release evidence" \
  HYDRA_RUN_MIRI=1 \
  qa/ci/reliability/check-memory-safety.sh

run_env_step "sanitizer release evidence" \
  HYDRA_RUN_SANITIZERS=1 \
  qa/ci/reliability/check-memory-safety.sh

run_env_step "real browser Playwright lifecycle evidence" \
  HYDRA_RUN_BROWSER_E2E=1 \
  qa/ci/reliability/check-browser-e2e.sh

run_env_step "coverage report release evidence" \
  HYDRA_RUN_COVERAGE=1 \
  qa/ci/quality/check-coverage.sh

run_env_step "mutation testing release evidence" \
  HYDRA_RUN_MUTATION=1 \
  qa/ci/quality/check-mutation.sh

if [ -z "${HYDRA_COVERAGE_FUZZ_RUNS:-}" ]; then
  HYDRA_COVERAGE_FUZZ_RUNS=100000
  export HYDRA_COVERAGE_FUZZ_RUNS
fi

run_env_step "overnight coverage-guided fuzz evidence" \
  HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1 \
  HYDRA_COVERAGE_FUZZ_RUNS="$HYDRA_COVERAGE_FUZZ_RUNS" \
  qa/ci/fuzz/check-fuzz.sh

printf '\nHYDRA-MSG full release validation passed.\n'
