#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

manifest="$HYDRA_REPO_ROOT/qa/tools/vector-gen/Cargo.toml"

if [ "${1:-}" = "--check-format" ]; then
  cargo fmt --manifest-path "$manifest" -- --check
else
  cargo fmt --manifest-path "$manifest"
fi
cargo test --release --locked --offline --manifest-path "$manifest"
cargo clippy --release --locked --offline --manifest-path "$manifest" \
  --all-targets -- -D warnings
cargo run --release --locked --offline --manifest-path "$manifest" -- --verify
