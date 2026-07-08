#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required to build the reusable web package." >&2
  echo "Install with: cargo install wasm-pack --locked" >&2
  exit 1
fi

output_dir="$HYDRA_REPO_ROOT/target/hydra-msg-wasm/web"
rm -rf "$output_dir"

wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../target/hydra-msg-wasm/web

printf '\nBuilt reusable HYDRA-MSG WASM web package:\n  %s\n' "$output_dir"
printf '\nUse example-specific scripts only when you want example-local web/pkg output.\n'
