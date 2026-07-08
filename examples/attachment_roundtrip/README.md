# HYDRA attachment roundtrip

Shows the clean public send/receive design:

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

Run from the repo root:

```bash
cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
```
