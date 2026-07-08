#!/usr/bin/env sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
manifest="$repository/qa/tools/vector-gen/Cargo.toml"

if [ "${1:-}" = "--check-format" ]; then
  cargo fmt --manifest-path "$manifest" -- --check
else
  cargo fmt --manifest-path "$manifest"
fi
cargo test --release --locked --offline --manifest-path "$manifest"
cargo clippy --release --locked --offline --manifest-path "$manifest" \
  --all-targets -- -D warnings
cargo run --release --locked --offline --manifest-path "$manifest" -- --verify
