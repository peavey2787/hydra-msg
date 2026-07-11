# HYDRA-MSG real-world benchmark notes

## Navigation

- [Main README](../../../README.md)
- [How HYDRA messaging works](../../impl/message-flow/README.md)
- [Spec docs and repo structure](../../spec/README.md)
- [Crates](../../../crates/README.md)
- [Examples](../../../examples/README.md)
- [Public developer API](../../spec/public-developer-api.md)
- [Benchmark notes](benchmark-results.md)
## Important caveats

- These are informal real-world runs, not a locked lab benchmark suite.
- Browser, OS, thermals, battery mode, background load, timer precision, JIT warmup, background tabs, and browser privacy/timer policies can affect results.
- WASM results measure the device/browser that opened the page.
- Server/native results measure the computer hosting the page, not the phone/tablet.
- Message timings are batched internally and reported as per-operation averages.
- Sub-millisecond send/receive differences, such as `0.02 ms` vs `0.04 ms`, are too small to use as proof that one runtime is universally faster. At this scale, timer resolution, batching, memory copies, JIT/warmup effects, CPU turbo state, and benchmark harness differences can dominate the measurement.
- Native/server and browser/WASM results are useful for sanity checking, but they are not always apples-to-apples: the browser benchmark runs inside the JS/WASM environment, while the server benchmark runs native Rust and returns JSON over the example HTTP host.

## Current release-candidate spot checks

Payload: 1,024 bytes. Results are manual captures reported from the `examples/mobile_perf_web` page unless otherwise noted.

| Device | Runtime | Iterations | Browser wall time | Handshake avg | Send+receive avg | Notes |
|---|---:|---:|---:|---:|---:|---|
| Samsung Galaxy device | Browser WASM | not captured | not captured | ~17 ms | ~0.2 ms | Manual mobile browser capture. Record exact model/browser in final release evidence. |
| ASUS TUF A16 laptop | Browser WASM | not captured | not captured | ~10 ms | ~0.2 ms | Manual laptop browser capture. |
| ASUS TUF A16 laptop | Native Rust/server | 30 | 224 ms from browser | 5.528641 ms | 0.042093 ms | Server JSON: `HYDRA1-MK768-M65`. Measures the host process, not the browser runtime. |

## Interpreting browser vs server send/receive timings

A server/native result around `0.04 ms` and a browser/WASM result around `0.02 ms` or `0.2 ms` should not be read as a hard ranking by itself.

For the 1 KiB message path, both runtimes are already far below human-perceptible latency. The most defensible conclusion is:

> HYDRA-MSG message send/receive is sub-millisecond on the measured modern browser and native/server paths.

Do **not** claim:

> WASM is faster than native Rust.

without a controlled benchmark that uses the same machine, same power profile, same payloads, same warmup, same iteration count, same timer source, and repeated runs with confidence intervals.

Possible reasons browser/WASM can appear faster in one small-message measurement:

- JS/WASM JIT warmup and hot-loop optimization;
- different batching or timing boundaries;
- browser timer quantization or precision policy;
- native/server path measuring extra facade/reporting/JSON work;
- CPU turbo or scheduler differences between runs;
- noise being large relative to a `0.02 ms` to `0.04 ms` delta.

## Browser persistence validation harness

The `examples/mobile_perf_web` page includes a browser persistence validation suite in addition to the facade benchmark. It is designed to capture release-candidate evidence for IndexedDB-backed encrypted snapshots on desktop and real mobile browsers.

The suite measures:

- first open with an empty IndexedDB profile;
- reopen of an existing persistent profile;
- save after identity mutation;
- save after contact and session mutation;
- save after message and attachment growth;
- backup export, passworded backup verification, backup import, restore dirty-state check, and restore flush;
- encrypted IndexedDB snapshot byte length;
- browser-reported `navigator.storage.estimate()` and `navigator.storage.persisted()` where available.

It also includes a **Reopen persistent profile** button for page-reload durability checks, a browser API misuse guard for missing name/password/empty profile cases, and a non-destructive quota/lifecycle probe. The quota probe records browser storage estimates; it does not intentionally fill storage.

Manual release-candidate captures should be archived under `release-evidence/<version>/` when a release makes browser-persistence or mobile-performance claims. The automated Playwright browser lifecycle gate is the correctness evidence; this benchmark page is the performance snapshot and manual-device evidence guide.

## Older development snapshots

The following older raw captures are retained for historical comparison. They may have been captured before the latest release-candidate benchmark run and should not override newer release evidence.

### 1 KiB payload browser/WASM results

Payload: 1,024 bytes. Envelope: 4,096 bytes. Message batch: 256 encrypt/decrypt operations per timed sample.

| Device | Runtime | Wall time | Handshake avg | Handshake min | Handshake max | Encrypt avg | Encrypt min | Encrypt max | Decrypt avg | Decrypt min | Decrypt max | Send+receive avg | Send+receive min | Send+receive max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Desktop PC | Browser WASM | 535.8 ms | 4.6633 ms | 2.0000 ms | 9.8000 ms | 0.0178 ms | 0.0168 ms | 0.0219 ms | 0.0234 ms | 0.0223 ms | 0.0293 ms | 0.0412 ms | 0.0398 ms | 0.0469 ms |
| ASUS TUF Ryzen 7 A16 laptop | Browser WASM | 632.0 ms | 5.7333 ms | 2.0000 ms | 14.0000 ms | 0.0230 ms | 0.0195 ms | 0.0273 ms | 0.0290 ms | 0.0234 ms | 0.0312 ms | 0.0521 ms | 0.0469 ms | 0.0547 ms |
| Samsung Galaxy S20 Ultra | Browser WASM | 1,064 ms | 10.0 ms | 5.4 ms | 20.6 ms | 0.0340 ms | 0.0300 ms | 0.0340 ms | 0.0432 ms | 0.0400 ms | 0.0450 ms | 0.0775 ms | 0.0762 ms | 0.0797 ms |
| BLU M8L (Original), released August 2020, 1GB RAM, Android 11 Go edition | Browser WASM | 17,042.5 ms | 162.5 ms | not captured | 310.2 ms | 0.5 ms | not captured | 0.7 ms | 0.7 ms | not captured | 1.03 ms | 1.27 ms | not captured | 1.69 ms |

### Earlier laptop native/server reference

These numbers are useful only as an older native Rust baseline on the host machine.

Payload: 1,024 bytes. Envelope: 4,096 bytes. Message batch: 256 encrypt/decrypt operations per timed sample.

| Device | Runtime | Wall time | Handshake avg | Handshake min | Handshake max | Encrypt avg | Encrypt min | Encrypt max | Decrypt avg | Decrypt min | Decrypt max | Send+receive avg | Send+receive min | Send+receive max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ASUS TUF Ryzen 7 A16 laptop | Native Rust/server | 291.0 ms | 1.7384 ms | 0.8866 ms | 5.1896 ms | 0.0104 ms | 0.0094 ms | 0.0145 ms | 0.0115 ms | 0.0108 ms | 0.0131 ms | 0.0218 ms | 0.0203 ms | 0.0262 ms |

### 64 KiB payload larger-message reference

Payload: 64,024 bytes. Envelope: 147,456 bytes. Message batch: 16 encrypt/decrypt operations per timed sample.

| Runtime | Wall time | Handshake avg | Handshake min | Handshake max | Encrypt avg | Encrypt min | Encrypt max | Decrypt avg | Decrypt min | Decrypt max | Send+receive avg | Send+receive min | Send+receive max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Browser WASM | 878.0 ms | 4.7333 ms | 2.0000 ms | 10.0000 ms | 0.5854 ms | 0.5000 ms | 0.6875 ms | 0.7875 ms | 0.6875 ms | 0.9375 ms | 1.3729 ms | 1.3125 ms | 1.5000 ms |
| Native Rust/server | 412.0 ms | 2.0073 ms | 0.9650 ms | 3.7086 ms | 0.2091 ms | 0.1799 ms | 0.2644 ms | 0.2123 ms | 0.1770 ms | 0.2897 ms | 0.4214 ms | 0.3589 ms | 0.5462 ms |

## Interpretation

The reported data supports these conclusions:

1. The normal 1 KiB message path is fast on desktop, laptop, modern mobile, and even a BLU M8L (Original).
2. The current manual release-candidate spot checks show about `17 ms` average browser/WASM handshake on a Samsung Galaxy device and about `10 ms` average browser/WASM handshake on an ASUS TUF A16 laptop.
3. The measured browser and native/server send+receive path is sub-millisecond for 1 KiB messages on modern hardware.
4. The BLU M8L (Original) is still usable for message send/receive, but full handshakes are visibly heavier and should remain session setup/rekey events, not per-message work.
5. The larger-message result suggests payload sizes around 64 KiB remain practical, but padding/envelope expansion and sustained thermal behavior should be remeasured for any release that makes performance claims around larger payloads.
6. The likely bottlenecks for a real app are carrier setup, WebRTC negotiation/reconnect, storage writes, UI rendering, network latency, background mobile behavior, and optional relay/mailbox behavior — not HYDRA message encryption itself.

## Release language

Allowed when the release evidence is archived:

> HYDRA-MSG has real-world Rust/WASM benchmark snapshots on desktop, laptop, Samsung Galaxy-class mobile hardware, and a BLU M8L (Original). The message path appears mobile-viable for the measured payload sizes.

Not allowed unless a release includes formal benchmark methodology and reproduced captures:

> HYDRA-MSG is formally benchmarked, performance-final, or proven faster in WASM than native Rust.
