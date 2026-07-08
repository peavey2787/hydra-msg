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

```bash
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Open the LAN URL from another device and run the browser/device benchmark.
