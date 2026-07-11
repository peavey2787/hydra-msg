use hydra_msg::{Hydra, HydraMessage, HydraResult};

fn main() -> HydraResult<()> {
    let _ = std::fs::remove_dir_all("target/examples/handshake_roundtrip/alice");
    let _ = std::fs::remove_dir_all("target/examples/handshake_roundtrip/bob");

    let mut alice = Hydra::open("target/examples/handshake_roundtrip/alice", "example-state")?;
    let mut bob = Hydra::open("target/examples/handshake_roundtrip/bob", "example-state")?;

    let alice_id = alice.generate_id("alice-password")?;
    let bob_id = bob.generate_id("bob-password")?;
    alice.set_active_id(alice_id, "alice-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    // These opaque bytes can move over QR, WebRTC, HTTP, file, relay, libp2p, etc.
    let alice_card = alice.create_contact_card()?;
    let bob_card = bob.create_contact_card()?;

    let alice_contact = bob.add_contact(alice_card)?;
    let bob_contact = alice.add_contact(bob_card)?;

    alice.verify_contact(bob_contact.id(), bob_contact.safety_code())?;
    bob.verify_contact(alice_contact.id(), alice_contact.safety_code())?;

    let offer = alice.init_handshake(bob_contact.id())?;
    let answer = bob.reply_handshake(offer)?;
    alice.finish_handshake(answer)?;

    let packets = alice.send(bob_contact.id(), HydraMessage::text("hello from Alice"))?;
    let mut received = None;
    for packet in packets {
        received = bob.receive(packet)?.or(received);
    }
    let received = received.ok_or(hydra_msg::HydraMsgError::InvalidEncoding(
        "message did not complete",
    ))?;

    println!(
        "Bob received from {}: {}",
        received.from().hex(),
        received.text()?
    );
    Ok(())
}
