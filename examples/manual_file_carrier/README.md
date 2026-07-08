# Manual file carrier example

This example demonstrates the simplest possible carrier: files on disk.

HYDRA creates opaque bytes for contact cards, handshake offers/answers, and encrypted envelopes. This example writes those bytes to files and reads them back.

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmark-results.md)

## Run

```bash
cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
```

Carrier files are written under:

```text
target/examples/manual_file_carrier/carrier
```
