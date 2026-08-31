#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

if [ "${HYDRA_WORKSPACE_TESTS_ALREADY_RAN:-0}" = 1 ]; then
  echo "hydra-cross-version-compat already executed by cargo test --workspace --all-targets; not repeating."
else
  cargo test -p hydra-cross-version-compat
fi

echo "cross-version compatibility checks passed"
