#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

cargo test -p hydra-cross-version-compat

echo "cross-version compatibility checks passed"
