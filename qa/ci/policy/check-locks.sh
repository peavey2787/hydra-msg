#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

root_lock="$HYDRA_REPO_ROOT/Cargo.lock"
vector_lock="$HYDRA_REPO_ROOT/qa/tools/vector-gen/Cargo.lock"

if [ ! -f "$root_lock" ] || [ ! -f "$vector_lock" ]; then
  echo "required lock file missing" >&2
  exit 1
fi

python3 "$HYDRA_REPO_ROOT/qa/ci/policy/check-workspace-lock.py"

python3 "$HYDRA_REPO_ROOT/qa/ci/policy/check-vector-lock-conflicts.py" "$root_lock" "$vector_lock"

echo "lock checks passed"
