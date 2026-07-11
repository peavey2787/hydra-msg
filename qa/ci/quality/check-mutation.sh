#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

manifest=qa/mutation/targets.tsv
audit=qa/evidence/coverage-mutation-targets.md

require_file() {
  if [ ! -f "$1" ]; then
    echo "required mutation file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "mutation invariant missing from $file: $text" >&2
    exit 1
  fi
}

require_file "$manifest"
require_file "$audit"

while IFS='|' read -r id risk source_file test_file required_test focus; do
  case "$id" in
    ''|'#'*) continue ;;
  esac
  for value in "$risk" "$source_file" "$test_file" "$required_test" "$focus"; do
    if [ -z "$value" ]; then
      echo "mutation manifest row has empty field: $id" >&2
      exit 1
    fi
  done
  require_file "$source_file"
  require_file "$test_file"
  require_text "$test_file" "fn $required_test"
  require_text "$manifest" "$id|"
done < "$manifest"

for required in \
  replay-checks \
  domain-separation-labels \
  generation-rollback-checks \
  signature-verification \
  fragment-reassembly \
  group-membership-rekey \
  group-treekem-rekey
do
  require_text "$manifest" "$required|"
done

require_text "$audit" "Mutation testing target"
require_text "$audit" "replay checks"
require_text "$audit" "domain separation labels"
require_text "$audit" "generation rollback checks"
require_text "$audit" "signature verification"
require_text "$audit" "fragment reassembly"
require_text "$audit" "group membership/rekey rules"
require_text "$audit" "HYDRA_RUN_MUTATION=1"

if [ "${HYDRA_RUN_MUTATION:-0}" = "1" ]; then
  if ! cargo mutants --version >/dev/null 2>&1; then
    echo "HYDRA_RUN_MUTATION=1 requires cargo-mutants to be installed" >&2
    echo "install with: cargo install cargo-mutants --locked" >&2
    echo "or run: ./scripts/setup-dev-env.sh" >&2
    exit 1
  fi
  mkdir -p target/mutants
  cargo mutants --workspace --timeout 120 --jobs 1 --output target/mutants
else
  echo "mutation manifest/static gate passed. Set HYDRA_RUN_MUTATION=1 to run cargo-mutants."
fi
