#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

roots="README.md docs qa crates examples"
files=$(mktemp)
links=$(mktemp)
trap 'rm -f "$files" "$links"' EXIT

for root in $roots; do
  [ -e "$root" ] || continue
  if [ -f "$root" ]; then
    printf '%s\n' "$root"
  else
    find "$root" -name '*.md' -type f ! -path '*/target/*' ! -path '*/.git/*'
  fi
done | sort -u > "$files"

: > "$links"
while IFS= read -r file || [ -n "$file" ]; do
  [ -n "$file" ] || continue
  grep -oE '\[[^][]+\]\([^)]*\)' "$file" 2>/dev/null | while IFS= read -r raw || [ -n "$raw" ]; do
    target=${raw#*\(}
    target=${target%\)}
    printf '%s|%s\n' "$file" "$target"
  done >> "$links" || true
done < "$files"

failure=0
while IFS='|' read -r file target || [ -n "$file" ]; do
  [ -n "$file" ] || continue

  # Drop optional Markdown titles after the URL: [x](path "title") or [x](path 'title').
  case "$target" in
    *' "'*) target=${target%%' "'*} ;;
    *" '"*) target=${target%%" '"*} ;;
  esac

  case "$target" in
    ''|'#'*|http://*|https://*|mailto:*|tel:*) continue ;;
  esac

  target=${target%%#*}
  target=${target%%\?*}
  [ -n "$target" ] || continue

  case "$target" in
    /*) resolved=".${target}" ;;
    *) resolved="$(dirname -- "$file")/$target" ;;
  esac

  if [ ! -e "$resolved" ]; then
    echo "unresolved Markdown link: $file -> $target" >&2
    failure=1
  fi
done < "$links"

if [ "$failure" -ne 0 ]; then
  echo "Markdown link check failed" >&2
  exit 1
fi

echo "Markdown link checks passed"
