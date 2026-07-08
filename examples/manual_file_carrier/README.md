# Manual file carrier example

This example demonstrates the simplest possible carrier: files on disk.

HYDRA creates opaque bytes for contact cards, handshake offers/answers, and
encrypted envelopes. This example writes those bytes to files and reads them
back to prove the carrier has no protocol authority.

Run from the repo root:

```bash
cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
```

The example writes carrier files under `target/examples/manual_file_carrier/carrier`.
