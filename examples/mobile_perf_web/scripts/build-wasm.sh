#!/usr/bin/env bash
set -euo pipefail

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required. Install it with: cargo install wasm-pack --locked" >&2
  exit 1
fi

wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
