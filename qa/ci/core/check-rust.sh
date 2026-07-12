#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

# Validate the committed lockfile before running heavier checks. Local CI must not
# rewrite Cargo.lock; stale locks are real failures that should be committed fixes.
cargo metadata --locked --format-version 1 --no-deps >/dev/null

cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
