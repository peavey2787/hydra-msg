use hydra_msg::{Hydra, HydraAttachment, HydraMessage, HydraResult};

fn main() -> HydraResult<()> {
    let _ = std::fs::remove_dir_all("target/examples/attachment_roundtrip");
    std::fs::create_dir_all("target/examples/attachment_roundtrip/files")?;

    let file_path = "target/examples/attachment_roundtrip/files/from-disk.txt";
    std::fs::write(file_path, b"file attachment bytes")?;

    let mut alice = Hydra::open_with_state_password(
        "target/examples/attachment_roundtrip/alice",
        "example-state",
    )?;
    let mut bob = Hydra::open_with_state_password(
        "target/examples/attachment_roundtrip/bob",
        "example-state",
    )?;

    let alice_id = alice.generate_id("alice-password")?;
    let bob_id = bob.generate_id("bob-password")?;
    alice.set_active_id(alice_id, "alice-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    let alice_contact = bob.add_contact(alice.create_contact_card()?)?;
    let bob_contact = alice.add_contact(bob.create_contact_card()?)?;

    let answer = bob.reply_handshake(alice.init_handshake(bob_contact.id())?)?;
    alice.finish_handshake(answer)?;

    let anonymous_bytes = HydraAttachment::from_bytes(b"anonymous byte attachment".to_vec())?;
    let message = HydraMessage::text("hello with attachments")
        .attach_file(file_path)?
        .attach_bytes("named-bytes.bin", b"named byte attachment".to_vec())?;

    let mut message = message;
    message.attachments.push(anonymous_bytes);

    let envelope = alice.send(bob_contact.id(), message)?;
    let data = bob.receive(envelope)?;

    println!("Bob received from {}: {}", data.from().hex(), data.text()?);
    for attachment in data.attachments() {
        println!(
            "attachment: {} ({} bytes, file={}, bytes={})",
            attachment.filename(),
            attachment.bytes().len(),
            attachment.is_file(),
            attachment.is_bytes()
        );
    }

    assert_eq!(data.from(), alice_contact.id());
    Ok(())
}
