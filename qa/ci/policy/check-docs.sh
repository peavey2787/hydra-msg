#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

python3 qa/ci/policy/check_docs.py
qa/ci/policy/check-markdown-links.sh

echo "docs checks passed"
