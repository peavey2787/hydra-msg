# HYDRA-MSG crates

`crates/` is for protocol/product crates only. App/demo code belongs under top-level `examples/`.

## Active protocol/product crate map

| Crate | Current purpose | Rule |
|---|---|---|
| `hydra-core` | Protocol constants, closed discriminants, shared types, errors, and domain labels. | Low-level protocol foundation. |
| `hydra-crypto` | Fixed-suite backend abstraction and RustCrypto candidate adapter. | Internal crypto backend, not the normal developer entry point. |
| `hydra-envelope` | Byte-exact outer-header encoding, parsing, protected-record layout, and fixed-class length validation. | Wire-format owner. |
| `hydra-session` | Atomic 1:1 send/receive ratchets, replay window, bounded skipped keys, authenticated refresh cutover, and close logic. | Session engine behind the facade. |
| `hydra-group` | Group modes, roster/governance state, epoch commits, sender chains, welcomes, and TreeKEM integration. | Group/lobby internals behind the facade. |
| `hydra-msg` | Public developer facade crate. | Stupid-simple SDK entry point: open, identity, contacts, handshake/session setup, messages with optional attachments, lobbies, backup/restore, storage status, and benchmark. |
| `hydra-msg-wasm` | Browser/mobile WASM bindings over `hydra-msg`. | Thin JS-friendly wrapper over the facade. |
| `hydra-msg-cli` | Developer CLI over `hydra-msg`. | Thin terminal helper, not protocol authority. |

## Retired demo app crates

The old demo app crates are retired from the active workspace and kept only as reference material under:

```text
examples/hydra-app-core
examples/hydra-app
```

They are not public protocol APIs and must not receive new product functionality. Useful flows should be rewritten against `hydra-msg` examples or `hydra-msg-cli`.

## Authority rules

* Public developer entry point is `hydra-msg`.
* Protocol authority lives in `docs/spec/`.
* Refactor direction lives in `docs/roadmap.md`.
* Public facade API target lives in `docs/project/public-developer-api.md`.
* Facade implementation ownership audit lives in `docs/project/audit/api-inventory-ownership-audit.md`.
* Implementation requirements live in `docs/impl/`.
* Validation criteria and vectors live in `docs/validation/` and `qa/`.
* Constants and shared wire discriminants have one owner: `hydra-core`.
* Envelope wire encoding and decoding have one owner: `hydra-envelope`.
* Session/ratchet behavior has one owner: `hydra-session`.
* App-domain and GUI behavior belong in examples or external apps, not in protocol/product crates.
* Crates must implement the spec; they must not silently redefine it.
* Wire encoding must be manual and byte-indexed, never native Rust struct serialization.
* Secret-bearing types must avoid accidental cloning, formatting, serialization, and persistence.
* Any implementation-discovered ambiguity must be fixed in the docs before being treated as stable behavior.

## Dependency rule

Lower-level crates may not depend on higher-level protocol, facade, app, or example crates. The active stack is:

```text
hydra-core / hydra-crypto / hydra-envelope / hydra-session / hydra-group
    ↓
hydra-msg         ← public developer facade
    ↓
hydra-msg-wasm    ← browser/mobile bindings
hydra-msg-cli     ← developer CLI over the facade
examples/*        ← WebRTC, benchmark, contact-card, and carrier demos
```

The v1 facade must not expose public `HydraConfig`, profiles, builders, protocol-info APIs, session import/export APIs, chunk APIs, checkpoint APIs, predicate APIs, or lobby-state APIs.
