# HYDRA-MSG SBOM policy

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

Every production release must include a software bill of materials.

## Current implementation

HYDRA-MSG generates a CycloneDX JSON SBOM with:

```bash
python3 scripts/release/generate-sbom.py --repo . --version vX.Y.Z --output release-artifacts/vX.Y.Z/sbom/hydra-msg-vX.Y.Z-cyclonedx.json
```

`create-release-package.sh` runs that command automatically and also stores raw Cargo metadata:

```text
release-artifacts/<version>/sbom/hydra-msg-<version>-cyclonedx.json
release-artifacts/<version>/sbom/hydra-msg-<version>-cargo-metadata.json
```

The SBOM source of truth is `cargo metadata --locked` from the signed source and `Cargo.lock`.

## SBOM requirements

The SBOM must include:

```text
release version
source commit
workspace packages
third-party Cargo packages
package versions
license expressions when Cargo metadata provides them
dependency relationships when resolvable from Cargo metadata
```

The SBOM must be hashed in `SHA256SUMS.txt` and covered by the detached signature over that checksum file.

## Verification

A verifier should be able to:

```bash
git checkout vX.Y.Z
cargo metadata --locked --format-version 1
python3 scripts/release/generate-sbom.py --repo . --version vX.Y.Z --output /tmp/hydra-sbom.json
```

The regenerated SBOM should match the published SBOM when the same `SOURCE_DATE_EPOCH` and signed commit are used. If a tool version changes the JSON shape in the future, release notes must document that change.

## Advisory link

SBOM generation does not replace `cargo-audit` or `cargo-deny`. Run both through:

```bash
./qa/ci/security/check-supply-chain.sh
```
