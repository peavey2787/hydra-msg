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

lock_pairs() {
  awk '
    $0 == "[[package]]" {
      if (name != "" && version != "") print name " " version
      name=""; version=""; next
    }
    $1 == "name" && $2 == "=" {
      name=$3; gsub(/\"/, "", name); next
    }
    $1 == "version" && $2 == "=" {
      version=$3; gsub(/\"/, "", version); next
    }
    END {
      if (name != "" && version != "") print name " " version
    }
  ' "$1" | sort -u
}

root_pairs=$(mktemp)
vector_pairs=$(mktemp)
conflict_pairs=$(mktemp)
trap 'rm -f "$root_pairs" "$vector_pairs" "$conflict_pairs"' EXIT HUP INT TERM

lock_pairs "$root_lock" > "$root_pairs"
lock_pairs "$vector_lock" | grep -v '^hydra-vector-gen 0\.1\.0$' > "$vector_pairs"

# The vector generator is intentionally locked as an independent tool. It may have
# tool-only transitive dependencies that are not present in the main workspace
# lock after Cargo regenerates the root graph. What must never happen is a shared
# package resolving to a different version between the two locks.
awk '
  NR == FNR { root_pair[$1 " " $2] = 1; root_name[$1] = 1; next }
  root_name[$1] && !root_pair[$1 " " $2] { print $0 }
' "$root_pairs" "$vector_pairs" > "$conflict_pairs"

if [ -s "$conflict_pairs" ]; then
  echo "vector tool lock conflicts with main workspace package versions:" >&2
  sed 's/^/  /' "$conflict_pairs" >&2
  echo "Regenerate both Cargo.lock files on a machine that can fetch crates, then commit them together." >&2
  exit 1
fi

echo "lock checks passed"
