# HYDRA attachment roundtrip

Shows text plus file and byte attachments through the public send/receive API.

## Navigation

- [Main README](../../README.md)
- [Examples](../README.md)
- [Rust SDK facade](../../crates/hydra-msg/README.md)

## Code shape

```rust
let envelope = hydra.send(
    contact_id,
    HydraMessage::text("hello")
        .attach_file("./photo.jpg")?
        .attach_bytes("data.bin", bytes_here)?,
)?;

let data = hydra.receive(envelope)?;
println!("{}", data.text()?);
for attachment in data.attachments() {
    std::fs::write(attachment.filename(), attachment.bytes())?;
}
```

## Run

```bash
cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
```
