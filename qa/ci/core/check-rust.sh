#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

# Fail immediately and explicitly when manifests and Cargo.lock disagree.
cargo metadata --locked --format-version 1 --no-deps >/dev/null

cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
