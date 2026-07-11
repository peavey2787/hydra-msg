# HYDRA-MSG minimum supported Rust version policy

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

The minimum supported Rust version is declared in workspace package metadata:

```toml
rust-version = "1.88"
```

All workspace packages inherit this value through `rust-version.workspace = true` unless a standalone QA workspace must declare it directly.

## Policy

- Do not raise MSRV accidentally.
- Any MSRV increase must be called out in `CHANGELOG.md`.
- Any MSRV increase must be justified by dependency requirements, language features, or security/tooling requirements.
- Release evidence must record `rustc --version --verbose`.

## Validation

The normal validation command uses the installed toolchain:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Release managers should additionally run, or document why they cannot run, the same validation on Rust `1.88.x` before claiming MSRV support for a release.
