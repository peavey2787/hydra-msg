# HYDRA-MSG production QA gate

## Navigation

- [Main README](../../README.md)
- [Spec document index](../spec/README.md)
- [Protocol spec](../spec/protocol-spec.md)
- [Threat model](../spec/threat-model.md)
- [Security proof sketch](../spec/security-proof-sketch.md)
- [State machines](../spec/state-machines.md)
- [Envelope serialization](../spec/envelope-serialization.md)
- [Chain-key evolution](../spec/chain-key-evolution.md)
- [TreeKEM profile](../spec/tree-kem.md)
- [Group modes](../spec/group-modes.md)
- [Group rekey](../spec/group-rekey.md)
- [Anonymous authorization](../spec/anonymous-authorization.md)

The production QA gate is `qa/ci/check-all.*`. It now includes the normal workspace/static/example checks plus the heavy release-evidence gates. The final step is the long coverage-guided fuzz campaign.

## Full release gate

Run from a clean checkout after first-time setup:

```bash
./qa/ci/check-all.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

On Unix, resume after a failure without repeating earlier green sections:

```bash
./qa/ci/check-all.sh --from browser --skip-browser-install
./qa/ci/check-all.sh --from coverage
./qa/ci/check-all.sh --from coverage --through mutation
```

The canonical section order is `permissions`, `tests`, `examples`, `miri`, `sanitizers`, `browser`, `coverage`, `mutation`, `fuzz`. Use `--only SECTION` for one gate or the corresponding granular `--skip-*` flag for an omission.

This proves that:

- Rust formatting, tests, and clippy warnings are clean;
- docs, Markdown links, lockfiles, vectors, and source-size gates pass;
- supply-chain advisory/license/source checks pass through `check-supply-chain.*`;
- resource-limit, metadata-leakage, crash-consistency, persistence, privacy, interop, cross-version, and browser-lifecycle gates pass;
- examples build and smoke-run as configured;
- reusable WASM web package builds;
- Miri release evidence runs;
- sanitizer release evidence runs;
- real-browser Playwright lifecycle evidence runs;
- coverage report evidence runs;
- mutation testing evidence runs;
- overnight coverage-guided fuzz evidence runs last; and
- no runtime `hydra-msg-data/` or local identity material is staged.

The default coverage-guided fuzz campaign is `HYDRA_COVERAGE_FUZZ_RUNS=100000` per target. Override that environment variable only when intentionally changing release campaign length.

Archive the command line, tool versions, logs, generated reports, crash artifacts, minimized fuzz reproducers, and exit status under `release-evidence/<version>/`.

## Release package gate

After validation evidence is archived, create and verify release artifacts with:

```bash
scripts/release/create-release-package.sh vX.Y.Z
scripts/release/sign-release-artifacts.sh vX.Y.Z [gpg-key-id]
scripts/release/verify-release-artifacts.sh vX.Y.Z
scripts/release/create-signed-tag.sh vX.Y.Z [gpg-key-id]
```

## What this gate does not prove

Passing these gates does not hide carrier/network metadata, prove third-party service security, or replace external cryptographic review. Those claims require separate evidence and release-note wording.
