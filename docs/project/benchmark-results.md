# HYDRA-MSG real-world benchmark notes

These numbers came from real browser/WASM runs reported during HYDRA-MSG development. They are useful evidence that the `hydra-msg` message path is viable on modern mobile hardware, but they are not a substitute for the final validation gate.

## Important caveats

- These are informal real-world runs, not a locked lab benchmark suite.
- Browser, OS, thermals, battery mode, background load, and timer precision can affect results.
- WASM results measure the device/browser that opened the page.
- Server/native results measure the computer hosting the page, not the phone/tablet.
- Message timings are batched internally and reported as per-operation averages.
- The final validation gate still needs to run format, tests, clippy, examples, docs checks, and fresh benchmark captures on the release candidate.

## 1 KiB payload browser/WASM results

Payload: 1,024 bytes. Envelope: 4,096 bytes. Message batch: 256 encrypt/decrypt operations per timed sample.

| Device | Runtime | Wall time | Handshake avg | Handshake min | Handshake max | Encrypt avg | Encrypt min | Encrypt max | Decrypt avg | Decrypt min | Decrypt max | Send+receive avg | Send+receive min | Send+receive max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Desktop PC | Browser WASM | 535.8 ms | 4.6633 ms | 2.0000 ms | 9.8000 ms | 0.0178 ms | 0.0168 ms | 0.0219 ms | 0.0234 ms | 0.0223 ms | 0.0293 ms | 0.0412 ms | 0.0398 ms | 0.0469 ms |
| ASUS TUF Ryzen 7 A16 laptop | Browser WASM | 632.0 ms | 5.7333 ms | 2.0000 ms | 14.0000 ms | 0.0230 ms | 0.0195 ms | 0.0273 ms | 0.0290 ms | 0.0234 ms | 0.0312 ms | 0.0521 ms | 0.0469 ms | 0.0547 ms |
| Samsung Galaxy S20 Ultra | Browser WASM | 1,064 ms | 10.0 ms | 5.4 ms | 20.6 ms | 0.0340 ms | 0.0300 ms | 0.0340 ms | 0.0432 ms | 0.0400 ms | 0.0450 ms | 0.0775 ms | 0.0762 ms | 0.0797 ms |
| BLU M8L (Original), released August 2020, 1GB RAM, Android 11 Go edition | Browser WASM | 17,042.5 ms | 162.5 ms | not captured | 310.2 ms | 0.5 ms | not captured | 0.7 ms | 0.7 ms | not captured | 1.03 ms | 1.27 ms | not captured | 1.69 ms |

## Laptop native/server reference

These numbers are useful only as a native Rust baseline on the host machine.

Payload: 1,024 bytes. Envelope: 4,096 bytes. Message batch: 256 encrypt/decrypt operations per timed sample.

| Device | Runtime | Wall time | Handshake avg | Handshake min | Handshake max | Encrypt avg | Encrypt min | Encrypt max | Decrypt avg | Decrypt min | Decrypt max | Send+receive avg | Send+receive min | Send+receive max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ASUS TUF Ryzen 7 A16 laptop | Native Rust/server | 291.0 ms | 1.7384 ms | 0.8866 ms | 5.1896 ms | 0.0104 ms | 0.0094 ms | 0.0145 ms | 0.0115 ms | 0.0108 ms | 0.0131 ms | 0.0218 ms | 0.0203 ms | 0.0262 ms |

## 64 KiB payload larger-message reference

Payload: 64,024 bytes. Envelope: 147,456 bytes. Message batch: 16 encrypt/decrypt operations per timed sample.

| Runtime | Wall time | Handshake avg | Handshake min | Handshake max | Encrypt avg | Encrypt min | Encrypt max | Decrypt avg | Decrypt min | Decrypt max | Send+receive avg | Send+receive min | Send+receive max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Browser WASM | 878.0 ms | 4.7333 ms | 2.0000 ms | 10.0000 ms | 0.5854 ms | 0.5000 ms | 0.6875 ms | 0.7875 ms | 0.6875 ms | 0.9375 ms | 1.3729 ms | 1.3125 ms | 1.5000 ms |
| Native Rust/server | 412.0 ms | 2.0073 ms | 0.9650 ms | 3.7086 ms | 0.2091 ms | 0.1799 ms | 0.2644 ms | 0.2123 ms | 0.1770 ms | 0.2897 ms | 0.4214 ms | 0.3589 ms | 0.5462 ms |

## Interpretation

The reported data supports these conclusions:

1. The normal 1 KiB message path is fast on desktop, laptop, modern mobile, and even a BLU M8L (Original).
2. The modern mobile result is especially strong: about 10 ms average handshake and under 0.1 ms average send+receive for 1 KiB payloads.
3. The BLU M8L (Original) is still usable for message send/receive, but full handshakes are visibly heavier and should remain session setup/rekey events, not per-message work.
4. The larger-message result suggests payload sizes around 64 KiB remain practical, but padding/envelope expansion and sustained thermal behavior still need release-candidate validation.
5. The likely bottlenecks for a real app are carrier setup, WebRTC negotiation/reconnect, storage writes, UI rendering, network latency, background mobile behavior, and optional relay/mailbox behavior — not HYDRA message encryption itself.

## Release language before final validation

Allowed:

> HYDRA-MSG has promising real-world Rust/WASM benchmark results on desktop, laptop, a Samsung Galaxy S20 Ultra, and a BLU M8L (Original). The message path appears mobile-viable, pending final validation.

Not allowed yet:

> HYDRA-MSG is production audited, formally benchmarked, or performance-final.
