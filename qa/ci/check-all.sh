#!/usr/bin/env sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repository"

qa/ci/check-rust.sh
qa/ci/check-docs.sh
qa/ci/check-vectors.sh

echo "HYDRA-MSG full validation passed"
echo "Run qa/ci/check-examples.sh separately for runnable examples and browser package checks."
