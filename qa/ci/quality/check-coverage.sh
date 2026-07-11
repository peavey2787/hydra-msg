#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

manifest=qa/coverage/critical-paths.tsv
coverage_tool=qa/coverage/enforce_lcov_thresholds.py
audit=qa/evidence/coverage-mutation-targets.md

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

python3 - "$coverage_tool" <<'PY'
import ast
from pathlib import Path
import sys
ast.parse(Path(sys.argv[1]).read_text(encoding='utf-8'), filename=sys.argv[1])
PY

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
  if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "HYDRA_RUN_COVERAGE=1 requires cargo-llvm-cov to be installed" >&2
    echo "install with: cargo install cargo-llvm-cov --locked" >&2
    echo "or run: ./scripts/setup-dev-env.sh" >&2
    exit 1
  fi
  mkdir -p target/coverage
  cargo llvm-cov clean --workspace
  cargo llvm-cov --workspace --all-targets --branch --lcov --output-path target/coverage/hydra.lcov
  python3 "$coverage_tool" "$manifest" target/coverage/hydra.lcov
  cargo llvm-cov --workspace --all-targets --branch --html --output-dir target/coverage/html
else
  echo "coverage manifest/static gate passed. Set HYDRA_RUN_COVERAGE=1 to generate and enforce LCOV/HTML coverage."
fi
