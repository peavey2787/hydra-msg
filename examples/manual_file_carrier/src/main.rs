use std::{fs, path::PathBuf};

use hydra_msg::{Hydra, HydraMessage, HydraResult};

fn main() -> HydraResult<()> {
    let root = PathBuf::from("target/examples/manual_file_carrier");
    let carrier = root.join("carrier");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&carrier)?;

    let mut alice = Hydra::open(root.join("alice"), "example-state")?;
    let mut bob = Hydra::open(root.join("bob"), "example-state")?;

    let alice_id = alice.generate_id("alice-password")?;
    alice.set_active_id(alice_id, "alice-password")?;

    let bob_id = bob.generate_id("bob-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    // Contact cards are opaque HYDRA bytes. The file carrier just moves them.
    fs::write(carrier.join("alice.contact"), alice.create_contact_card()?)?;
    fs::write(carrier.join("bob.contact"), bob.create_contact_card()?)?;

    let bob_contact = alice.add_contact(fs::read(carrier.join("bob.contact"))?)?;
    let alice_contact = bob.add_contact(fs::read(carrier.join("alice.contact"))?)?;

    alice.verify_contact(bob_contact.id(), bob_contact.safety_code())?;
    bob.verify_contact(alice_contact.id(), alice_contact.safety_code())?;

    // Handshake bytes are opaque too. Files are only a manual carrier.
    let offer = alice.init_handshake(bob_contact.id())?;
    fs::write(
        carrier.join("alice-to-bob.handshake-offer"),
        offer.as_bytes(),
    )?;

    let answer = bob.reply_handshake(fs::read(carrier.join("alice-to-bob.handshake-offer"))?)?;
    fs::write(
        carrier.join("bob-to-alice.handshake-answer"),
        answer.as_bytes(),
    )?;

    alice.finish_handshake(fs::read(carrier.join("bob-to-alice.handshake-answer"))?)?;

    let envelope = alice.send(
        bob_contact.id(),
        HydraMessage::text("hello through manual file carrier")
            .attach_bytes("note.bin", b"opaque attachment bytes".to_vec())?,
    )?;
    fs::write(carrier.join("alice-to-bob.envelope"), envelope.as_bytes())?;

    let received = bob.receive(fs::read(carrier.join("alice-to-bob.envelope"))?)?;
    println!("Bob decrypted: {}", received.text()?);
    for attachment in received.attachments() {
        println!(
            "Attachment {}: {} bytes",
            attachment.filename(),
            attachment.bytes().len()
        );
    }

    println!("Carrier files written to {}", carrier.display());
    Ok(())
}
