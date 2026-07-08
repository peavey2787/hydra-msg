#!/usr/bin/env sh
set -eu

# Restore Unix execute permissions for repository shell scripts after ZIP extraction.
# Run from anywhere inside the repo with:
#   sh qa/ci/linux-permissions.sh

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

printf 'HYDRA-MSG Linux permission setup\n'
printf 'Repo root: %s\n' "$repo_root"

count=0
while IFS= read -r script_path; do
  chmod +x "$script_path"
  count=$((count + 1))
  rel=${script_path#"$repo_root/"}
  printf '  +x %s\n' "$rel"
done <<EOF_FIND
$(find "$repo_root" \
  -path "$repo_root/.git" -prune -o \
  -path "$repo_root/target" -prune -o \
  -type f -name '*.sh' -print | sort)
EOF_FIND

printf '\nUpdated %s shell script(s).\n' "$count"
printf 'Next commands:\n'
printf '  ./qa/ci/check-all.sh\n'
printf '  ./qa/ci/check-examples.sh\n'
printf '\nDo not run these scripts with sudo unless your Rust toolchain is installed for root.\n'
