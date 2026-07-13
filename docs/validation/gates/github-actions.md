# GitHub Actions validation

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)
- [QA workspace](../../../qa/README.md)

HYDRA keeps local validation scripts under `qa/ci/` and invokes the same gates
from GitHub-hosted runners. A push is not considered remotely validated merely
because a developer reports a local result; the commit's Actions page records
the independently executed workflow result.

## Pull-request and push CI

`.github/workflows/ci.yml` runs on pushes to `main`, pull requests targeting
`main`, and manual dispatch. Normal GitHub CI is a bounded commit gate, not the
local release-complete `check-all` runner. It runs separate jobs for:

- core workspace/static validation plus maintained examples and WASM package
  checks;
- the real Chromium, Firefox, and mobile-Chromium browser lifecycle suite; and
- the deterministic fuzz regression gate.

The GitHub jobs may regenerate their temporary runner copy of `Cargo.lock` before
fetching dependencies so remote CI is not blocked by a stale checked-in lock while
validating the current manifests. Local QA scripts do not rewrite committed lock
files; `./qa/ci/check-all.sh` treats stale locks as failures that must be fixed
and committed.

Each job stops on the first failing command inside that job and uploads a
commit-named evidence log. The expensive release-evidence gates remain reserved
for local `check-all` and the release-validation workflow.

## Release validation

`.github/workflows/release-validation.yml` runs by manual dispatch and for
version tags matching `v*`. It invokes the full sequential `qa/ci/check-all.sh`
pipeline, using the same section order and stop-on-first-failure behavior as
the local release-complete gate.

The release workflow uploads its validation console log and generated diagnostic
directories using a commit-specific artifact name. Artifacts are supporting
evidence, not source files, and are not committed to the repository.

The manual workflow accepts the fuzz-run count, mutation-job count, and optional
extra `check-all` arguments for an intentional partial/resumed release-evidence
run. The normal release default selects deep fuzz mode: 100,000 runs per fast target,
1,000 runs for the stateful message-flow target, and one mutation worker.

## Security and reproducibility rules

- Workflow permissions default to read-only repository contents.
- Checkout credentials are not retained.
- Third-party GitHub-maintained actions are pinned to immutable commit SHAs, with the audited release version recorded in an inline comment.
- Dependabot monitors GitHub Action releases through
  `.github/dependabot.yml`.
- Expensive release jobs do not silently replace local validation; both paths
  call the checked-in `qa/ci/` scripts.
- A green workflow proves only the exact commit, runner image, tool versions,
  and inputs displayed by that run. It is not a substitute for external
  cryptographic review.
