# HYDRA-MSG versioned release checklist

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

## Release status rule

A release may be published only from a clean checkout at a signed tag. A release may claim only the evidence that is archived for that exact version.

Maintainer-run validation evidence for the current candidate includes green mandatory gates, supply-chain checks, and the heavier release-evidence gates. Archive those logs under `release-evidence/<version>/` before publishing the tag or artifacts.

## Required release metadata

Record all of this for each release:

```text
version
release date
source commit
signed Git tag
release manager
supported target matrix
MSRV
rustc and cargo versions
Cargo.lock SHA-256
SBOM SHA-256
artifact SHA-256 hashes
signature files
known limitations
external review status
```

## Required release gate

Run from the repository root on a clean checkout:

```bash
./qa/ci/check-all.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

`check-all` includes the full release-evidence set:

| Evidence | Included by `check-all` |
|---|---|
| Supply chain | `qa/ci/security/check-supply-chain.*` through `core/check-tests.*` |
| Miri | `HYDRA_RUN_MIRI=1 qa/ci/reliability/check-memory-safety.*` |
| Sanitizers | `HYDRA_RUN_SANITIZERS=1 qa/ci/reliability/check-memory-safety.*` |
| Browser lifecycle E2E | `HYDRA_RUN_BROWSER_E2E=1 qa/ci/reliability/check-browser-e2e.*` |
| Coverage report | `HYDRA_RUN_COVERAGE=1 qa/ci/quality/check-coverage.*` |
| Mutation testing | `HYDRA_RUN_MUTATION=1 qa/ci/quality/check-mutation.*` |
| Coverage-guided fuzzing | `qa/ci/check-all.* --deep-fuzz`: 100,000 runs per fast target and 1,000 stateful message-flow runs |

Archive the command line, tool versions, logs, generated reports, crash artifacts, minimized fuzz reproducers, and exit status. If a gate is impossible on a target, the release notes must say which target was skipped, why it was skipped, and what alternative evidence was used.

## Required release artifacts

A production release must include or link to:

```text
signed Git tag
source archive from the signed tag
Cargo.lock
CycloneDX SBOM
checksums file
checksums signature
published crate/package artifacts, if publishing crates
WASM web package, if releasing WASM artifacts
release evidence summary
reproducible-build verification notes
```

The helper scripts are:

```bash
scripts/release/create-release-package.sh vX.Y.Z
scripts/release/sign-release-artifacts.sh vX.Y.Z [gpg-key-id]
scripts/release/verify-release-artifacts.sh vX.Y.Z
scripts/release/create-signed-tag.sh vX.Y.Z [gpg-key-id]
```

## Required sign-off questions

Every answer must be yes or explicitly scoped out in release notes:

```text
Can a clean checkout reproduce or source-verify each release artifact?
Can the SBOM be regenerated from the signed source and lockfile?
Can every published artifact hash be verified?
Is the Git tag signed?
Are release checksums signed?
Does SECURITY.md point to GitHub Private Vulnerability Reporting?
Is the changelog complete for app developers?
Are compatibility-breaking changes absent or clearly versioned?
Are all advisory/license gates green?
Are all heavy release-evidence gates archived or justified?
Is external review complete or accurately marked if not performed?
```

## Version compatibility rule

Before v1, old formats may fail closed unless migration support is explicitly documented. Starting with v1, compatibility tests must prove every supported upgrade path named in release notes:

```text
state written by version N opens in version N+1
backup exported by version N imports in version N+1
unknown future fields follow the documented fail-closed/ignore policy
rollback-generation evidence remains valid across compatible upgrades
older compatible packet fragments still reassemble
```

## Release blockers

Do not publish a production release if any of these are true:

```text
full release `check-all` gate fails
known high/critical advisory is unresolved
SECURITY.md is missing or does not point to GitHub Private Vulnerability Reporting
SBOM is missing
release hashes or signatures are missing
signed Git tag is missing
release artifact provenance is unknown
heavy-gate crash or fuzz reproducer is unresolved
wire/API-breaking change is undocumented
external review is claimed but evidence is not archived
```
