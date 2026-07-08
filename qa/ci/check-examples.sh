#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

skip_wasm=0
if [ "${1:-}" = "--skip-wasm" ]; then
  skip_wasm=1
fi

run_step() {
  name=$1
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

run_step "handshake_roundtrip example" \
  cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
run_step "contact_card example" \
  cargo run --manifest-path examples/contact_card/Cargo.toml
run_step "attachment_roundtrip example" \
  cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
run_step "lobby_roundtrip example" \
  cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
run_step "manual_file_carrier example" \
  cargo run --manifest-path examples/manual_file_carrier/Cargo.toml

run_step "mobile_perf_web host compile" \
  cargo check --manifest-path examples/mobile_perf_web/Cargo.toml
run_step "webrtc_manual_carrier host compile" \
  cargo check --manifest-path examples/webrtc_manual_carrier/Cargo.toml

if [ "$skip_wasm" -eq 0 ]; then
  if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "wasm-pack is required for browser example packages." >&2
    echo "Install with: cargo install wasm-pack --locked" >&2
    exit 1
  fi

  run_step "mobile_perf_web WASM package" \
    examples/mobile_perf_web/scripts/build-wasm.sh
  run_step "webrtc_manual_carrier WASM package" \
    examples/webrtc_manual_carrier/scripts/build-wasm.sh
else
  echo "WASM browser package checks skipped by --skip-wasm."
fi

printf '\nHYDRA-MSG example checks passed.\n'
