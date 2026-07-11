#!/usr/bin/env sh
set -eu

# Restore Unix execute permissions for repository launchers/scripts after ZIP extraction.
# Run from anywhere inside the repo with:
#   sh qa/ci/core/linux-permissions.sh
#
# This script also repairs stale git core.worktree metadata that can appear when
# a ZIP is extracted over a folder that was moved to Trash by a file manager.

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

printf 'HYDRA-MSG Linux permission setup\n'
printf 'Repo root: %s\n' "$HYDRA_REPO_ROOT"

chmod_one() {
  script_path=$1
  chmod +x "$script_path"
  rel=${script_path#"$HYDRA_REPO_ROOT/"}
  printf '  +x %s\n' "$rel"
  count=$((count + 1))
}

count=0
while IFS= read -r script_path; do
  chmod_one "$script_path"
done <<EOF_FIND
$(find "$HYDRA_REPO_ROOT" \
  -path "$HYDRA_REPO_ROOT/.git" -prune -o \
  -path "$HYDRA_REPO_ROOT/target" -prune -o \
  -type f \( -name '*.sh' -o -name '*.desktop' -o -name '*.py' \) -print | sort)
EOF_FIND

printf '\nUpdated %s launcher/script file(s).\n' "$count"
printf 'Next commands:\n'
printf '  ./qa/ci/check-all.sh\n'
printf '  ./qa/ci/core/check-tests.sh     # tests/static checks only\n'
printf '  ./qa/ci/core/check-examples.sh  # examples only\n'
printf '  ./qa/ci/core/build-wasm-web.sh\n'
printf '\nDo not run these scripts with sudo unless your Rust toolchain is installed for root.\n'
