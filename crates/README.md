# HYDRA-MSG crates

`crates/` contains the maintained Rust components.

## Navigation

- [Main README](../README.md)
- [How HYDRA messaging works](../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../docs/spec/README.md)
- [Crates](README.md)
- [Examples](../examples/README.md)
- [Public developer API](../docs/spec/public-developer-api.md)
- [Benchmark notes](../docs/validation/benchmarks/benchmark-results.md)

## Crate map

| Crate | Purpose |
|---|---|
| `hydra-core` | Protocol constants, shared types, errors, and domain labels. |
| `hydra-crypto` | Fixed-suite crypto backend internals. |
| `hydra-envelope` | Byte-exact envelope/header encoding and validation. |
| `hydra-session` | 1:1 sessions, ratchets, replay handling, refresh, and close logic. |
| `hydra-group` | Group and lobby internals behind the public SDK. |
| `hydra-msg` | Simple Rust SDK entry point. |
| `hydra-stego` | Optional zero-model deterministic telemetry and AI-backed cover carriers for compact HYDRA envelopes. |
| `hydra-msg-wasm` | Browser/mobile package over `hydra-msg`. |
| `hydra-msg-cli` | Developer CLI over `hydra-msg`. |

## Ownership rules

- App developers should start with `hydra-msg`.
- Browser/mobile apps should use `hydra-msg-wasm`.
- Low-level crates should not depend on higher-level crates.
- Protocol behavior belongs in the owner crate for that area.
- The public SDK must stay small and app-friendly.
- Wire encoding must be manual and byte-indexed.
- Secret-bearing types must avoid accidental cloning, formatting, serialization, and persistence.

## Dependency direction

```text
hydra-core / hydra-crypto / hydra-envelope / hydra-session / hydra-group
    ↓
hydra-msg
    ↓
hydra-msg-wasm
hydra-msg-cli
examples/*
```

`hydra-stego` is an independent carrier-layer crate. Native apps can use its
small `Stego` facade directly. AI-backed profiles run in the browser LAN
example's native host so both peers share one deterministic local model;
`hydra-msg-wasm` only exposes the compact HYDRA send/receive boundary.

The public SDK does not expose configs, profiles, builders, protocol-info APIs, session import/export APIs, chunk APIs, checkpoint APIs, predicate APIs, or lobby-state APIs.
