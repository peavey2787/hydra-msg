#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

manifest=qa/coverage/critical-paths.tsv
coverage_tool=qa/coverage/enforce_lcov_thresholds.rs
coverage_tool_dir=target/qa-tools/coverage
coverage_tool_bin=$coverage_tool_dir/enforce-lcov-thresholds
coverage_tool_tests=$coverage_tool_dir/enforce-lcov-thresholds-tests
audit=docs/validation/evidence/coverage-mutation-targets.md

require_file() {
  if [ ! -f "$1" ]; then
    echo "required coverage file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "coverage invariant missing from $file: $text" >&2
    exit 1
  fi
}

require_file "$manifest"
require_file "$coverage_tool"
require_file "$audit"

if find qa/coverage -type f -name '*.py' -print | grep .; then
  echo "Python coverage helper found; coverage enforcement must remain Rust-only" >&2
  exit 1
fi

if ! command -v rustc >/dev/null 2>&1; then
  echo "the Rust coverage threshold helper requires rustc on PATH" >&2
  echo "load the rustup environment or run: ./scripts/setup-dev-env.sh" >&2
  exit 1
fi
mkdir -p "$coverage_tool_dir"
rustc --edition=2021 -D warnings --test "$coverage_tool" -o "$coverage_tool_tests"
"$coverage_tool_tests"
rustc --edition=2021 -D warnings "$coverage_tool" -o "$coverage_tool_bin"

while IFS='|' read -r id coverage_class min_line min_branch source_file test_file required_test; do
  case "$id" in
    ''|'#'*) continue ;;
  esac
  for value in "$coverage_class" "$min_line" "$min_branch" "$source_file" "$test_file" "$required_test"; do
    if [ -z "$value" ]; then
      echo "coverage manifest row has empty field: $id" >&2
      exit 1
    fi
  done
  require_file "$source_file"
  require_file "$test_file"
  require_text "$test_file" "fn $required_test"
  require_text "$manifest" "$id|"
done < "$manifest"

for required in \
  "parser/codec branch and negative-path coverage" \
  "state-machine replay and skipped-key transition coverage" \
  "generation rollback and stale-state rejection" \
  "signature verification negative-path coverage" \
  "fragment reassembly branch and malformed-input coverage" \
  "group membership transition and authorization coverage" \
  "group rekey transition and TreeKEM validation coverage"
do
  require_text "$manifest" "$required"
done

require_text "$audit" "coverage report"
require_text "$audit" "critical-path coverage threshold"
require_text "$audit" "parser/codec branch coverage"
require_text "$audit" "negative-path coverage"
require_text "$audit" "state-machine transition coverage"
require_text "$audit" "HYDRA_RUN_COVERAGE=1"

if [ "${HYDRA_RUN_COVERAGE:-0}" = "1" ]; then
  coverage_toolchain=${HYDRA_COVERAGE_TOOLCHAIN:-nightly}

  if ! command -v rustup >/dev/null 2>&1; then
    echo "HYDRA branch coverage requires rustup and a nightly toolchain" >&2
    echo "install Rust with rustup, then run: ./scripts/setup-dev-env.sh" >&2
    exit 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo "HYDRA branch coverage requires cargo on PATH" >&2
    echo "load the rustup environment or run: ./scripts/setup-dev-env.sh" >&2
    exit 1
  fi
  if ! rustup run "$coverage_toolchain" rustc --version >/dev/null 2>&1; then
    echo "coverage toolchain is unavailable: $coverage_toolchain" >&2
    echo "install it with: rustup toolchain install $coverage_toolchain" >&2
    exit 1
  fi
  coverage_rustc_version=$(rustup run "$coverage_toolchain" rustc --version)
  case "$coverage_rustc_version" in
    *nightly*) ;;
    *)
      echo "HYDRA branch coverage requires a nightly Rust toolchain" >&2
      echo "HYDRA_COVERAGE_TOOLCHAIN=$coverage_toolchain selected: $coverage_rustc_version" >&2
      exit 1
      ;;
  esac

  if ! rustup component list --toolchain "$coverage_toolchain" --installed \
    | grep -Eq '^llvm-tools'; then
    echo "==> installing llvm-tools-preview for coverage toolchain: $coverage_toolchain"
    rustup component add llvm-tools-preview --toolchain "$coverage_toolchain"
  fi

  if ! cargo "+$coverage_toolchain" llvm-cov --version >/dev/null 2>&1; then
    echo "HYDRA_RUN_COVERAGE=1 requires cargo-llvm-cov to be installed" >&2
    echo "install with: cargo install cargo-llvm-cov --locked" >&2
    echo "or run: ./scripts/setup-dev-env.sh" >&2
    exit 1
  fi

  echo "==> branch coverage toolchain: $coverage_rustc_version"
  mkdir -p target/coverage
  cargo "+$coverage_toolchain" llvm-cov clean --workspace
  cargo "+$coverage_toolchain" llvm-cov \
    --workspace --all-targets --branch --lcov \
    --output-path target/coverage/hydra.lcov
  "$coverage_tool_bin" "$manifest" target/coverage/hydra.lcov
  cargo "+$coverage_toolchain" llvm-cov \
    --workspace --all-targets --branch --html \
    --output-dir target/coverage/html
else
  echo "coverage manifest/static gate passed. Set HYDRA_RUN_COVERAGE=1 to generate and enforce LCOV/HTML coverage."
fi
