#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

if command -v python3 >/dev/null 2>&1; then
  exec python3 qa/ci/release/check_release_governance.py
fi
exec python qa/ci/release/check_release_governance.py
