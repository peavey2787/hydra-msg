#!/usr/bin/env sh
set -eu
. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root
python3 qa/ci/reliability/check_memory_safety.py
