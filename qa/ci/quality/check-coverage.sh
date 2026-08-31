#!/usr/bin/env sh
set -eu
. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root
critical=qa/coverage/critical-functions.tsv
tool=qa/quality/enforce_quality.rs
tool_dir=target/qa-tools/coverage
tool_bin=$tool_dir/enforce-quality
tool_tests=$tool_dir/enforce-quality-tests
audit=docs/validation/evidence/coverage-mutation-targets.md
lcov=target/coverage/hydra.lcov
function_report=target/coverage/function-quality.tsv

require_file() { [ -f "$1" ] || { echo "required coverage file missing: $1" >&2; exit 1; }; }
require_text() { grep -Fq -- "$2" "$1" || { echo "coverage invariant missing from $1: $2" >&2; exit 1; }; }
for file in "$critical" "$tool" qa/quality/lcov.rs qa/quality/rust_source.rs "$audit"; do require_file "$file"; done
if find qa/coverage -type f -name '*.py' -print | grep .; then
  echo "Python coverage helper found; coverage enforcement must remain Rust-only" >&2
  exit 1
fi
for required in \
  "Critical cryptographic functions require 100% line and branch coverage" \
  "Native production function ranges require at least 85% aggregate line coverage and 65% aggregate branch coverage" \
  "Cyclomatic complexity is capped at 12" \
  "CRAP is capped at 25" \
  "target/coverage/hydra.lcov" \
  "target/coverage/function-quality.tsv"
do require_text "$audit" "$required"; done

command -v rustc >/dev/null 2>&1 || { echo "coverage/CRAP enforcement requires rustc on PATH" >&2; exit 1; }
mkdir -p "$tool_dir"
rustc --edition=2021 -D warnings --test "$tool" -o "$tool_tests"
"$tool_tests"
rustc --edition=2021 -D warnings "$tool" -o "$tool_bin"
while IFS='|' read -r id source function reason; do
  case "$id" in ''|'#'*) continue ;; esac
  [ -n "$source" ] && [ -n "$function" ] && [ -n "$reason" ] || { echo "critical coverage row has empty field: $id" >&2; exit 1; }
  require_file "$source"
done < "$critical"

if [ "${HYDRA_RUN_COVERAGE:-0}" != 1 ]; then
  echo "coverage/CRAP manifest and helper checks passed. Set HYDRA_RUN_COVERAGE=1 to generate LCOV and enforce thresholds."
  exit 0
fi
coverage_toolchain=${HYDRA_COVERAGE_TOOLCHAIN:-nightly}
command -v rustup >/dev/null 2>&1 || { echo "HYDRA coverage requires rustup" >&2; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "HYDRA coverage requires cargo" >&2; exit 1; }
coverage_rustc=$(rustup run "$coverage_toolchain" rustc --version)
case "$coverage_rustc" in *nightly*) ;; *) echo "branch coverage requires nightly Rust: $coverage_rustc" >&2; exit 1 ;; esac
if ! rustup component list --toolchain "$coverage_toolchain" --installed | grep -Eq '^llvm-tools'; then
  rustup component add llvm-tools-preview --toolchain "$coverage_toolchain"
fi
cargo "+$coverage_toolchain" llvm-cov --version >/dev/null
mkdir -p target/coverage
cargo "+$coverage_toolchain" llvm-cov clean --workspace
cargo "+$coverage_toolchain" llvm-cov --workspace --all-targets --branch --lcov --output-path "$lcov"
"$tool_bin" "$lcov" "$critical" "$function_report"
# Reuse the existing profiling data; do not execute the workspace a second time for HTML.
cargo "+$coverage_toolchain" llvm-cov report --branch --html --output-dir target/coverage/html
echo "LCOV/coverage/CC/CRAP checks passed."
