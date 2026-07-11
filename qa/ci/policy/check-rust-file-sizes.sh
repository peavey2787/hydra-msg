#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

threshold=400
scan_roots="crates"
allowlist="qa/ci/policy/rust-size-allowlist.txt"

if [ ! -f "$allowlist" ]; then
  echo "missing Rust source-size allow-list: $allowlist" >&2
  exit 1
fi

large_files=$(mktemp)
allowed_paths=$(mktemp)
trap 'rm -f "$large_files" "$allowed_paths"' EXIT

for scan_root in $scan_roots; do
  find "$scan_root" -name '*.rs' -type f ! -path '*/target/*' | sort | while IFS= read -r file; do
    lines=$(wc -l < "$file" | tr -d ' ')
    if [ "$lines" -gt "$threshold" ]; then
      printf '%s|%s\n' "$file" "$lines"
    fi
  done
done > "$large_files"

failure=0

while IFS= read -r entry || [ -n "$entry" ]; do
  case "$entry" in
    ''|'#'*) continue ;;
  esac

  path=$(printf '%s' "$entry" | cut -d '|' -f 1)
  max_lines=$(printf '%s' "$entry" | cut -d '|' -f 2)
  reason=$(printf '%s' "$entry" | cut -d '|' -f 3-)

  if [ -z "$path" ] || [ -z "$max_lines" ] || [ -z "$reason" ] || [ "$reason" = "$entry" ]; then
    echo "invalid allow-list entry: $entry" >&2
    failure=1
    continue
  fi

  case "$max_lines" in
    *[!0-9]*|'')
      echo "invalid max line count in allow-list entry: $entry" >&2
      failure=1
      continue
      ;;
  esac

  if [ ! -f "$path" ]; then
    echo "allow-list entry points to missing file: $path" >&2
    failure=1
    continue
  fi

  lines=$(wc -l < "$path" | tr -d ' ')
  if [ "$lines" -le "$threshold" ]; then
    echo "stale allow-list entry no longer exceeds $threshold lines: $path ($lines lines)" >&2
    failure=1
  fi
  if [ "$lines" -gt "$max_lines" ]; then
    echo "allow-listed file exceeded documented max: $path ($lines > $max_lines lines)" >&2
    failure=1
  fi

  printf '%s\n' "$path" >> "$allowed_paths"
done < "$allowlist"

while IFS='|' read -r path lines; do
  if ! grep -Fxq "$path" "$allowed_paths"; then
    echo "Rust file exceeds $threshold lines without documented ownership exception: $path ($lines lines)" >&2
    failure=1
  fi
done < "$large_files"

if [ "$failure" -ne 0 ]; then
  echo "Rust source-size ownership check failed" >&2
  exit 1
fi

echo "Rust source-size ownership checks passed"
