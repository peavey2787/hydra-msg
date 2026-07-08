# HYDRA mobile performance web host

Hosts a tiny LAN web page that can run two benchmarks:

1. **Server-side facade benchmark** — calls `hydra.benchmark()` on the machine hosting this page.
2. **Browser/device WASM benchmark** — calls the `hydra-msg-wasm` binding on the phone/tablet/browser that opened the page.

Build the WASM package first:

```bash
wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
```

Or:

```powershell
examples\mobile_perf_web\scripts\build-wasm.ps1
```

Run the LAN host from the repo root:

```bash
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Then open the LAN URL from another device.

The WASM binding is intentionally still stupid-simple: no configs, no profiles, no advanced public API. Browser persistence in this phase is in-memory unless the app explicitly uses `exportBackup` / `importBackup` or individual export/import helpers.
