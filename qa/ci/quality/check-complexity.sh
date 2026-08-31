#!/usr/bin/env sh
set -eu
. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root
out=target/qa-tools/complexity
mkdir -p "$out"
rustc --edition=2021 -D warnings --test qa/quality/rust_source.rs -o "$out/rust-source-tests"
"$out/rust-source-tests"
rustc --edition=2021 -D warnings qa/quality/check_complexity.rs -o "$out/check-complexity"
"$out/check-complexity"
