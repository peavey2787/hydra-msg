# HYDRA-MSG validation documentation

This directory contains long-lived validation policy, evidence, and release-governance documentation. Executable gates remain under `qa/ci/`; human-readable validation records belong here.

## Navigation

- [Main README](../../README.md)
- [Validation index](README.md)
- [Spec document index](../spec/README.md)
- [Threat model](../spec/threat-model.md)
- [QA workspace](../../qa/README.md)

## Benchmarks

- [Real-world benchmark notes](benchmarks/benchmark-results.md)

## Validation gates

- [Production QA gate](gates/production-qa-gate.md)
- [Browser lifecycle E2E](gates/browser-lifecycle-e2e.md)
- [Miri, sanitizer, and fault-injection gate](gates/miri-sanitizer-fault-injection.md)
- [Coverage-guided fuzzing](gates/coverage-guided-fuzzing.md)
- [Test-vector requirements](gates/test-vectors.md)

## Validation evidence

- [Coverage and mutation targets](evidence/coverage-mutation-targets.md)
- [Crash-consistency matrix](evidence/crash-consistency-matrix.md)
- [Interop test harness](evidence/interop-test-harness.md)
- [Metadata-leakage audit](evidence/metadata-leakage-audit.md)
- [Resource-exhaustion and denial-of-service limits](evidence/resource-exhaustion-dos-limits.md)
- [WASM/browser lifecycle policy](evidence/wasm-browser-lifecycle-policy.md)

## Release governance

- [Release criteria](release/release-criteria.md)
- [Release checklist](release/release-checklist.md)
- [Release artifacts](release/release-artifacts.md)
- [Release signing](release/release-signing.md)
- [Reproducible builds](release/reproducible-builds.md)
- [SBOM policy](release/sbom.md)
- [Supply-chain policy](release/supply-chain-policy.md)
- [Dependency update policy](release/dependency-update-policy.md)
- [MSRV policy](release/msrv-policy.md)
- [Supported platforms](release/supported-platforms.md)
- [Changelog policy](release/changelog-policy.md)
- [Security advisory policy](release/security-advisory-policy.md)
- [Responsible disclosure](release/responsible-disclosure.md)
- [External review status](release/external-review-status.md)

## Ownership rule

- `qa/ci/` owns executable validation gates.
- `qa/coverage/`, `qa/fuzz/`, `qa/fixtures/`, and `qa/vectors/` own machine-readable inputs and generated-test seeds.
- `docs/validation/evidence/` owns long-lived audit notes and evidence matrices.
- `docs/validation/gates/` owns descriptions of release-quality validation stages.
- `docs/validation/release/` owns release policy and governance.
