#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required. Install it with cargo install wasm-pack --locked." >&2
  exit 1
fi

HYDRA_WASM_STACK_SIZE="${HYDRA_WASM_STACK_SIZE:-16777216}"
HYDRA_PREVIOUS_RUSTFLAGS="${RUSTFLAGS:-}"
restore_rustflags() {
  if [[ -n "$HYDRA_PREVIOUS_RUSTFLAGS" ]]; then
    export RUSTFLAGS="$HYDRA_PREVIOUS_RUSTFLAGS"
  else
    unset RUSTFLAGS
  fi
}
trap restore_rustflags EXIT
export RUSTFLAGS="${HYDRA_PREVIOUS_RUSTFLAGS} -C link-arg=-zstack-size=${HYDRA_WASM_STACK_SIZE}"

out_dir="examples/stego_lan_chat/web/pkg"
rm -rf "$out_dir"
wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/stego_lan_chat/web/pkg
printf '*\n!.gitignore\n!.gitkeep\n' > "$out_dir/.gitignore"
touch "$out_dir/.gitkeep"
echo "Built the steganographic LAN chat WASM package."
