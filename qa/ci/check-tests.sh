#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

skip_vectors=0
for arg in "$@"; do
  case "$arg" in
    --skip-vectors)
      skip_vectors=1
      ;;
    *)
      echo "unknown argument: $arg" >&2
      echo "usage: $0 [--skip-vectors]" >&2
      exit 2
      ;;
  esac
done

run_step() {
  name=$1
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

run_step "workspace Rust checks" qa/ci/check-rust.sh
run_step "Rust source-size ownership checks" qa/ci/check-rust-file-sizes.sh
run_step "privacy invariant checks" qa/ci/check-privacy-invariants.sh
run_step "docs/static checks" qa/ci/check-docs.sh
run_step "lock-file checks" qa/ci/check-locks.sh

if [ "$skip_vectors" -eq 0 ]; then
  run_step "QA vector checks" qa/ci/check-vectors.sh --check-format
else
  echo "QA vector checks skipped by --skip-vectors."
fi

printf '\nHYDRA-MSG tests-only validation passed.\n'
