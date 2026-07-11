# HYDRA-MSG release criteria

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

This document defines what evidence a HYDRA-MSG release must have before it is published.

## Release levels

| Level | Meaning |
|---|---|
| Development build | Local code under active development. No artifact guarantee. |
| Release candidate | Mandatory gates pass and heavy evidence is being archived for a specific version. |
| Production release | Signed tag, release artifacts, hashes, SBOM, signatures, changelog, and evidence are published. |
| Externally reviewed release | Production release plus archived independent review evidence for the claimed scope. |

## Mandatory release gate

Run from the repository root on a clean checkout:

```bash
./qa/ci/check-all.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

`check-all` is release-complete. It includes workspace fmt/test/clippy, supply-chain checks, static policy gates, examples, WASM package checks, Miri, sanitizers, real-browser Playwright E2E, coverage, mutation testing, and the overnight coverage-guided fuzz campaign last.

The final fuzz campaign defaults to 100,000 libFuzzer runs per target. For publication, save the logs and generated reports under `release-evidence/<version>/`.

Individual lower-level scripts may still be run while debugging a failure, but they are no longer separate release steps.

## Evidence matrix

| Area | Required evidence |
|---|---|
| Public API | Rust/WASM API docs, API misuse tests, and frozen developer surface checks. |
| Protocol correctness | Handshake, session, group/lobby, cross-context, replay, rekey, and domain-separation tests. |
| Persistence | Encrypted state/backup tests, chunk tamper tests, rollback evidence, crash consistency, native lock, and browser CAS. |
| Resource limits | Exact-edge tests and static gates tied to `crates/hydra-msg/src/limits.rs`. |
| Browser lifecycle | Playwright tests for IndexedDB denial, quota, stale tabs, delete while open, reload, pagehide, and persistent storage. |
| Fuzzing | Deterministic CI fuzz plus coverage-guided cargo-fuzz campaigns with saved run logs. |
| Memory safety | Fault-injection tests plus optional Miri/sanitizer evidence. |
| Supply chain | `cargo-audit`, `cargo-deny`, lockfile, license, and duplicate-version review. |
| Metadata leakage | metadata-leakage gate green; release notes must not claim HYDRA is metadata-free, traffic-flow private, or fully unlinkable through bearer anonymous auth. |
| Release provenance | Signed Git tag, source archive, SBOM, checksums, signatures, and verification commands. |
| Security reporting | Root `SECURITY.md` with GitHub Private Vulnerability Reporting. |

## Production blockers

Do not publish a production release if any of these are true:

```text
full release `check-all` gate fails
known high/critical advisory is unresolved
SECURITY.md is missing or does not point to GitHub Private Vulnerability Reporting
SBOM is missing
signed Git tag is missing
artifact checksum file is missing
checksum signature is missing
release artifact provenance is unknown
heavy-gate crash or fuzz reproducer is unresolved
wire/API-breaking change is undocumented
```

External review is tracked separately. Do not claim a release is externally reviewed unless the review evidence is archived.

## Release workflow summary

```bash
./qa/ci/check-all.sh
# archive the check-all logs and generated release evidence
scripts/release/create-signed-tag.sh vX.Y.Z [gpg-key-id]
scripts/release/create-release-package.sh vX.Y.Z
scripts/release/sign-release-artifacts.sh vX.Y.Z [gpg-key-id]
scripts/release/verify-release-artifacts.sh vX.Y.Z
```
