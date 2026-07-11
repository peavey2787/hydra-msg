# HYDRA candidate vector generator

This isolated tool generates deterministic envelope and 1:1 handshake vectors from `hydra-core`, `hydra-envelope`, and the `hydra-crypto` candidate adapter.

## Navigation

- [Main README](../../../README.md)
- [Parent workspace](../../README.md)

## Generate vectors

```bash
cargo run --release --manifest-path qa/tools/vector-gen/Cargo.toml
```

Output:

```text
qa/vectors/candidate/
```

## Verify existing output

```bash
cargo run --release --manifest-path qa/tools/vector-gen/Cargo.toml -- --verify
```

## Scope

The tool verifies the generated manifest, artifact inventory, hashes, and binary/hex mirrors. The handshake set contains byte-complete INIT, RESP, and FINISH envelopes plus transcript, hybrid KDF, session, and confirmation artifacts.

The tool uses the test-only entropy schedule in `docs/validation/gates/test-vectors.md`. Deterministic primitive internals are confined to this isolated tool; production signing remains randomized through `hydra-crypto`.
