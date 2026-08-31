#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

if command -v python3 >/dev/null 2>&1; then
  exec python3 qa/ci/security/check_persistence_invariants.py
elif command -v python >/dev/null 2>&1; then
  exec python qa/ci/security/check_persistence_invariants.py
fi

echo "HYDRA persistence invariant policy requires Python 3 on PATH." >&2
exit 1
