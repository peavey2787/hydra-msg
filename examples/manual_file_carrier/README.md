# Manual file carrier example

This example demonstrates the simplest possible carrier: files on disk.

HYDRA creates opaque bytes for contact cards, handshake offers/answers, and encrypted envelopes. This example writes those bytes to files and reads them back.

## Navigation

- [Main README](../../README.md)
- [Examples](../README.md)
- [How HYDRA messaging works](../../docs/project/message-flow/README.md)
- [Carrier example rules](../../docs/project/carrier-examples.md)

## Run

```bash
cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
```

Carrier files are written under:

```text
target/examples/manual_file_carrier/carrier
```
