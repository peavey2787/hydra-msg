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
missing_pairs=$(mktemp)
trap 'rm -f "$root_pairs" "$vector_pairs" "$missing_pairs"' EXIT HUP INT TERM

lock_pairs "$root_lock" > "$root_pairs"
lock_pairs "$vector_lock" | grep -v '^hydra-vector-gen 0\.1\.0$' > "$vector_pairs"
comm -23 "$vector_pairs" "$root_pairs" > "$missing_pairs"

if [ -s "$missing_pairs" ]; then
  echo "vector tool lock contains package versions not present in the main workspace lock:" >&2
  sed 's/^/  /' "$missing_pairs" >&2
  echo "Run the vector tool lock update on a machine that can fetch crates, then commit qa/tools/vector-gen/Cargo.lock." >&2
  exit 1
fi

echo "lock checks passed"
