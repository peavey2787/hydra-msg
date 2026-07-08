# HYDRA attachment roundtrip

Shows text plus file and byte attachments through the public send/receive API.

## Navigation

- [Main README](../../README.md)
- [Examples](../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)

## Shape

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
