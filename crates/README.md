# HYDRA-MSG crates

`crates/` contains the maintained Rust components.

## Navigation

- [Main README](../README.md)
- [How HYDRA messaging works](../docs/project/message-flow/README.md)
- [Examples](../examples/README.md)
- [Public developer API](../docs/project/public-developer-api.md)
- [Roadmap](../docs/roadmap.md)

## Crate map

| Crate | Purpose |
|---|---|
| `hydra-core` | Protocol constants, shared types, errors, and domain labels. |
| `hydra-crypto` | Fixed-suite crypto backend internals. |
| `hydra-envelope` | Byte-exact envelope/header encoding and validation. |
| `hydra-session` | 1:1 sessions, ratchets, replay handling, refresh, and close logic. |
| `hydra-group` | Group and lobby internals behind the public SDK. |
| `hydra-msg` | Simple Rust SDK entry point. |
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

The public SDK does not expose configs, profiles, builders, protocol-info APIs, session import/export APIs, chunk APIs, checkpoint APIs, predicate APIs, or lobby-state APIs.
