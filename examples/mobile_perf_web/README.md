# HYDRA mobile performance web host

Hosts a LAN web page for browser/device WASM benchmarks.

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmark-results.md)

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

For a reusable package for your own app, use `qa/ci/build-wasm-web.sh` or `qa/ci/build-wasm-web.ps1`; that output goes to `target/hydra-msg-wasm/web/`.

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

Use the page buttons to run either the server-side facade benchmark or the browser/device WASM benchmark.
