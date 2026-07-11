# Interop test harness audit

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

HYDRA-MSG has a dedicated interop gate instead of relying only on fresh same-code round trips.

## Coverage matrix

| Boundary | Enforced by |
| --- | --- |
| Frozen packet generated from a candidate vector opens correctly | `qa/tests/interop` receives `TV-DATA-000/envelope.bin` through the current `hydra-session` runtime. |
| Frozen outer-header fixture remains canonical | `qa/tests/interop` verifies `TV-HDR-000/outer_header.bin` against the current encoder. |
| Current state fixture opens across runtime boundary | `qa/tests/interop` creates current chunked encrypted state bytes, writes them as native `state.hydra`, and opens them through the normal public `Hydra::open` path. |
| Current backup fixture imports across runtime boundary | `qa/tests/interop` creates a current chunked backup, verifies it, and imports it through the public runtime. |
| Rust native ↔ WASM compatibility | Native accepts the same chunked encrypted state byte format stored by the WASM IndexedDB adapter when those opaque bytes are placed in the normal native state file path. |
| CLI ↔ WASM compatibility | The CLI creates and opens a current chunked encrypted state profile while the browser probe verifies the same IndexedDB persistence boundary. |
| Pre-v1 and future fixture contracts | Pre-v1 unpadded state/backup fixtures and unknown-future fixtures fail closed because HYDRA has not shipped a v1 migration contract yet. |

## Policy

HYDRA is still pre-v1. The first production version is the chunked padded state/backup format. There is no migration behavior for old unpadded persistence records, old backups, or old IndexedDB `updatedAtMs` records.

The browser probe is intentionally hosted by `examples/mobile_perf_web`: it needs a real browser IndexedDB implementation. Node-only tests are not a substitute for the multi-tab/version/quota browser lifecycle path.
