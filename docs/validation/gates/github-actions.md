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
`main`, and manual dispatch. Its default job invokes `qa/ci/check-all.sh` without
a section cutoff, so CI follows the same ordered pipeline as the local full gate:

- workspace formatting, tests, Clippy, policy, supply-chain, and documentation
  gates;
- all maintained examples and WASM builds;
- Miri and sanitizer evidence;
- the real Chromium, Firefox, and mobile-Chromium storage lifecycle suite;
- measured branch coverage;
- mutation testing; and
- deterministic plus coverage-guided fuzzing, with the coverage-guided fuzz
  campaign intentionally last.

The job is sequential and stops on the first failing section. Manual dispatch can
pass extra `check-all` arguments such as `--from browser`, `--only fuzz`, or
`--fuzz-runs 10000` through the `check_all_args` input when a maintainer
intentionally wants a partial/resumed run. The default push/PR path remains the
complete run.

The job retains its complete validation console log as a commit-named Actions
artifact and also uploads generated coverage, mutation, fuzz, and browser
reports when present.

## Release validation

`.github/workflows/release-validation.yml` runs by manual dispatch and for
version tags matching `v*`. It also invokes the full sequential `qa/ci/check-all.sh`
pipeline, using the same section order and stop-on-first-failure behavior as
push/PR CI.

The release workflow uploads its validation console log and generated diagnostic
directories using a commit-specific artifact name. Artifacts are supporting
evidence, not source files, and are not committed to the repository.

The manual workflow accepts the fuzz-run count, mutation-job count, and optional
extra `check-all` arguments for an intentional partial/resumed release-evidence
run. The normal release default remains 100,000 runs per fuzz target and one
mutation worker.

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
