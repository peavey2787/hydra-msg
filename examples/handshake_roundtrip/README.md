# HYDRA handshake roundtrip

Minimal two-device-style flow using the public `hydra-msg` SDK.

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md)

## What it does

1. Alice and Bob open local HYDRA stores.
2. Each generates an identity.
3. They exchange contact cards over an imaginary carrier.
4. Alice creates canonical INIT.
5. Bob verifies INIT and returns canonical RESP.
6. Alice verifies RESP and emits authenticated FINISH.
7. Bob authenticates FINISH and only then installs the responder session.
8. Alice sends an encrypted message.
9. Bob receives plaintext.

## Run

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
```
