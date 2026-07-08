#!/usr/bin/env sh
set -eu

# Restore Unix execute permissions for repository shell scripts after ZIP extraction.
# Run from anywhere inside the repo with:
#   sh qa/ci/linux-permissions.sh
#
# This script also repairs stale git core.worktree metadata that can appear when
# a ZIP is extracted over a folder that was moved to Trash by a file manager.

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

printf 'HYDRA-MSG Linux permission setup\n'
printf 'Repo root: %s\n' "$HYDRA_REPO_ROOT"

count=0
while IFS= read -r script_path; do
  chmod +x "$script_path"
  count=$((count + 1))
  rel=${script_path#"$HYDRA_REPO_ROOT/"}
  printf '  +x %s\n' "$rel"
done <<EOF_FIND
$(find "$HYDRA_REPO_ROOT" \
  -path "$HYDRA_REPO_ROOT/.git" -prune -o \
  -path "$HYDRA_REPO_ROOT/target" -prune -o \
  -type f -name '*.sh' -print | sort)
EOF_FIND

printf '\nUpdated %s shell script(s).\n' "$count"
printf 'Next commands:\n'
printf '  ./qa/ci/check-all.sh\n'
printf '  ./qa/ci/check-tests.sh     # tests/static checks only\n'
printf '  ./qa/ci/check-examples.sh  # examples only\n'
printf '  ./qa/ci/build-wasm-web.sh\n'
printf '\nDo not run these scripts with sudo unless your Rust toolchain is installed for root.\n'
