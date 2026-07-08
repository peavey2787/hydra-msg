#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
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

# Tiered full gate: non-example tests/static checks first, then runnable examples/browser packages.
# shellcheck disable=SC2086
qa/ci/check-tests.sh $test_args
# shellcheck disable=SC2086
qa/ci/check-examples.sh $example_args

printf '\nHYDRA-MSG full validation passed.\n'
