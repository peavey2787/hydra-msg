#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required to build the reusable web package." >&2
  echo "Install with: cargo install wasm-pack --locked" >&2
  echo "or run: ./scripts/setup-dev-env.sh" >&2
  exit 1
fi

# HYDRA's browser handshake path performs ML-KEM + ML-DSA work. Some browsers
# trap with the wasm-ld default stack during that path, so build the web package
# with an explicit stack. Apps may override this, but should not lower it without
# rerunning the browser persistence/handshake probes.
HYDRA_WASM_STACK_SIZE="${HYDRA_WASM_STACK_SIZE:-16777216}"
HYDRA_PREVIOUS_RUSTFLAGS="${RUSTFLAGS:-}"
export RUSTFLAGS="${HYDRA_PREVIOUS_RUSTFLAGS} -C link-arg=-zstack-size=${HYDRA_WASM_STACK_SIZE}"

output_dir="$HYDRA_REPO_ROOT/target/hydra-msg-wasm/web"
rm -rf "$output_dir"

wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../target/hydra-msg-wasm/web

printf '\nBuilt reusable HYDRA-MSG WASM web package:\n  %s\n' "$output_dir"
printf '\nUse example-specific scripts only when you want example-local web/pkg output.\n'
