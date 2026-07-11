# HYDRA-MSG minimum supported Rust version policy

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

## Policy

- The workspace manifest declares `rust-version = "1.88"`.
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
