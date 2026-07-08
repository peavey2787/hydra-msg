#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required for this example. Install with: cargo install wasm-pack --locked" >&2
  exit 1
fi

wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/webrtc_manual_carrier/web/pkg
echo "Built WebRTC manual carrier WASM package."
