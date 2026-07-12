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
`main`, and manual dispatch. It runs:

- workspace formatting, tests, Clippy, policy, supply-chain, and documentation
  gates;
- all maintained examples and WASM builds; and
- the real Chromium, Firefox, and mobile-Chromium storage lifecycle suite; and
- the deterministic fuzz corpus/state-machine regression gate.

All normal jobs retain their complete validation console logs as commit-named Actions artifacts, and a final summary job records each gate result on the workflow run. The browser job also uploads its JSON report, HTML report, screenshots, and retry traces when present.

Normal CI runs deterministic fuzz regression cases, but it intentionally omits the expensive mutation, measured coverage, Miri, sanitizer, and 100,000-run-per-target libFuzzer campaigns so every push receives prompt feedback.

## Release validation

`.github/workflows/release-validation.yml` runs by manual dispatch and for
version tags matching `v*`. Its independent jobs cover:

- the complete core workspace, policy, and example gates;
- release governance and supply-chain checks;
- Miri;
- address-sanitizer execution;
- cross-browser lifecycle evidence;
- measured line and branch coverage;
- mutation testing; and
- coverage-guided fuzzing.

Each job uploads its validation console log and any generated diagnostic directory using a
commit-specific artifact name. A final summary job records all eight release-gate results on the workflow run. Artifacts are supporting evidence, not source
files, and are not committed to the repository.

The manual workflow accepts the fuzz-run count and mutation-job count. The normal release default remains 100,000 runs per fuzz target and one mutation worker.

This release workflow is the GitHub-hosted counterpart to the complete local `qa/ci/check-all.sh` pipeline; normal push/PR CI is deliberately smaller.

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
