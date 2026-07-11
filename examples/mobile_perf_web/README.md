# HYDRA mobile performance web host

Hosts a LAN web page for browser/device WASM benchmarks and IndexedDB persistence validation.

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md)

## Build example-local WASM

Unix:

```bash
examples/mobile_perf_web/scripts/build-wasm.sh
```

PowerShell:

```powershell
examples\mobile_perf_web\scripts\build-wasm.ps1
```

This writes the example package to:

```text
examples/mobile_perf_web/web/pkg/
```

The build script sets an explicit WASM stack size because the browser handshake path performs ML-KEM and ML-DSA work. The default is 16 MiB:

```bash
HYDRA_WASM_STACK_SIZE=16777216 examples/mobile_perf_web/scripts/build-wasm.sh
```

Do not lower this value unless the browser benchmark and IndexedDB persistence suite still pass.

For a reusable package for your own app, use `qa/ci/core/build-wasm-web.sh` or `qa/ci/core/build-wasm-web.ps1`; that output goes to `target/hydra-msg-wasm/web/`.

## Run

From the repo root, build the example-local WASM package first:

```bash
examples/mobile_perf_web/scripts/build-wasm.sh
```

Then start the host:

```bash
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Open it on the same machine with:

```text
http://127.0.0.1:8788
```

For a phone or another LAN device, find your laptop IP and open that address:

```bash
hostname -I
```

Example:

```text
http://192.168.1.50:8788
```


## WASM package troubleshooting

If browser buttons fail with an error like:

```text
TypeError: error loading dynamically imported module: /pkg/hydra_msg_wasm.js
```

then the browser could not import the example-local WASM package. Usually this means `web/pkg/` was not built, the host is serving from the wrong runtime path, or the page cached an earlier failed import. Rebuild the package, restart the host, and hard-refresh the page:

```bash
examples/mobile_perf_web/scripts/build-wasm.sh
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

The host exposes a diagnostic endpoint:

```text
http://127.0.0.1:8788/pkg-health
```

It reports whether `hydra_msg_wasm.js` and `hydra_msg_wasm_bg.wasm` exist in the package directory that the server is actually using. The server resolves this directory from `CARGO_MANIFEST_DIR`, so it works even if `cargo run` is launched from outside the repo root.

## Browser actions

The page exposes these actions:

| Button | Purpose |
|---|---|
| Run server-side facade benchmark | Runs `hydra.benchmark()` on the machine hosting the page. |
| Run browser/device HYDRA WASM benchmark | Runs the normal WASM facade benchmark on the browser/device in explicit ephemeral mode. |
| Run IndexedDB persistence validation suite | Deletes validation profiles, opens empty persistent state, saves identity/contact/session/message/attachment mutations, verifies backup export/verification/import, checks restore dirty-state before flush, reopens persistent state, and records encrypted snapshot byte size plus browser storage estimates. |
| Reopen persistent profile | Reopens the prior validation profile without deleting it. Use this after a full page reload to validate durable IndexedDB state survived the reload lifecycle. |
| Run browser API misuse guard | Confirms missing name/password/empty profile cases reject instead of producing the previous undefined-argument crash class. |
| Probe browser quota/lifecycle | Reads `navigator.storage.estimate()` and `navigator.storage.persisted()` where available. It does not intentionally fill device storage. |
| Clear validation profiles | Deletes the validation records from IndexedDB. |

## IndexedDB persistence validation

Persistent browser validation uses `WasmHydra.openPersistent(name, password)` and commits mutations with `await hydra.flush()`. The message-growth portion opens a separate ephemeral peer, exchanges contact cards, completes the normal offer/answer handshake, and then validates that persistent `send(...)` packets are received by the peer session. Backup restore follows the same boundary: `importBackup(bytes, password)` authenticates and applies the restore snapshot in memory, marks the wrapper dirty, and becomes durable only after `await hydra.flush()`. The example stores the same opaque authenticated-encrypted HYDRA snapshot bytes as native persistence. The page only measures record byte length and public facade status; it does not parse HYDRA plaintext snapshots or secrets in JavaScript.

A complete manual pass should run the validation suite on desktop and at least one real mobile browser, reload the page, then click **Reopen persistent profile**. Capture the JSON output and record it under [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md).

## Quota and lifecycle notes

The quota probe is intentionally non-destructive. It records browser-reported quota and persistence status without trying to exhaust storage. If `flush()` fails because IndexedDB is unavailable, blocked, private-browsing restricted, evicted, user-cleared, or quota-limited, the browser app must surface that error. HYDRA must not silently fall back to plaintext, synchronous browser key/value storage, or durable-looking in-memory state.
