# HYDRA-MSG dependency update policy

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

Dependency changes are security-sensitive.

## Required gates

Every dependency update must pass:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
./qa/ci/check-all.sh
./qa/ci/security/check-supply-chain.sh
```

The supply-chain gate uses `cargo-audit`, `cargo-deny`, the workspace lockfile, and `deny.toml`.

## Update rules

- Prefer small, reviewable dependency updates.
- Keep `Cargo.lock` committed.
- Do not add wildcard dependencies.
- Add explicit versions to path dependencies when `cargo-deny` requires them.
- Do not add a new cryptographic primitive or backend without updating the spec, backend profile, threat model, and tests.
- Review duplicate dependency versions before release.
- Security updates may bypass normal batching but must still pass the release gate before publication unless an emergency advisory says otherwise.

## Release SBOM rule

Every production release regenerates the SBOM from the signed source and lockfile. Dependency updates are not considered release-ready until they appear in the release SBOM and signed hashes.
