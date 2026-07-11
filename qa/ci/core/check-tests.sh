#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
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

run_step "workspace Rust checks" qa/ci/core/check-rust.sh
run_step "supply-chain advisory/license checks" qa/ci/security/check-supply-chain.sh
run_step "Rust source-size ownership checks" qa/ci/policy/check-rust-file-sizes.sh
run_step "privacy invariant checks" qa/ci/security/check-privacy-invariants.sh
run_step "resource-exhaustion/DoS limit checks" qa/ci/security/check-resource-limits.sh
run_step "crash-consistency matrix checks" qa/ci/reliability/check-crash-consistency.sh
run_step "Miri/sanitizer/fault-injection checks" qa/ci/reliability/check-memory-safety.sh
run_step "WASM/browser lifecycle checks" qa/ci/reliability/check-browser-lifecycle.sh
run_step "metadata-leakage checks" qa/ci/security/check-metadata-leakage.sh
run_step "persistence API shape checks" qa/ci/security/check-persistence-api-shape.sh
run_step "persistence invariant checks" qa/ci/security/check-persistence-invariants.sh
run_step "cross-runtime interop harness checks" qa/ci/reliability/check-interop.sh
run_step "critical-path coverage target checks" qa/ci/quality/check-coverage.sh
run_step "mutation target checks" qa/ci/quality/check-mutation.sh
run_step "cross-version compatibility checks" qa/ci/reliability/check-cross-version-compat.sh
run_step "mobile perf web persistence checks" qa/ci/reliability/check-mobile-perf-web.sh
run_step "docs/static checks" qa/ci/policy/check-docs.sh
run_step "release-governance checks" qa/ci/release/check-release-governance.sh
run_step "lock-file checks" qa/ci/policy/check-locks.sh

if [ "$skip_vectors" -eq 0 ]; then
  run_step "QA vector checks" qa/ci/policy/check-vectors.sh --check-format
else
  echo "QA vector checks skipped by --skip-vectors."
fi

printf '\nHYDRA-MSG tests-only validation passed.\n'
