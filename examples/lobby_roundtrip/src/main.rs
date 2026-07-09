use hydra_msg::{Hydra, HydraLobbyPolicy, HydraMessage, HydraResult};

fn main() -> HydraResult<()> {
    let _ = std::fs::remove_dir_all("target/examples/lobby_roundtrip/alice");
    let _ = std::fs::remove_dir_all("target/examples/lobby_roundtrip/bob");

    let mut alice = Hydra::open("target/examples/lobby_roundtrip/alice", "example-state")?;
    let mut bob = Hydra::open("target/examples/lobby_roundtrip/bob", "example-state")?;

    let alice_id = alice.generate_id("alice-password")?;
    let bob_id = bob.generate_id("bob-password")?;
    alice.set_active_id(alice_id, "alice-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    let alice_contact = bob.add_contact(alice.create_contact_card()?)?;
    let bob_contact = alice.add_contact(bob.create_contact_card()?)?;

    let answer = bob.reply_handshake(alice.init_handshake(bob_contact.id())?)?;
    alice.finish_handshake(answer)?;

    let lobby = alice.create_lobby(HydraLobbyPolicy::new("demo lobby", 4))?;
    alice.add_lobby_member(lobby.id(), bob_contact.id())?;

    let invite = alice.create_lobby_invite(lobby.id())?;
    let joined = bob.join_lobby(invite)?;
    bob.add_lobby_member(joined.id(), alice_contact.id())?;

    let outbound = alice.send_lobby(
        lobby.id(),
        HydraMessage::text("hello lobby").attach_bytes("note.txt", b"lobby attachment".to_vec())?,
    )?;

    for copy in outbound {
        // The app/carrier uses this recipient hint to deliver each opaque envelope.
        if copy.recipient() == bob_contact.id() {
            let received = bob.receive_lobby(copy.into_envelope())?;
            println!(
                "Bob received lobby {} from {}: {}",
                received.lobby_id().unwrap_or(joined.id()).hex(),
                received.from().hex(),
                received.text()?
            );
            println!("attachment: {}", received.attachments()[0].filename());
        }
    }

    assert_eq!(bob.lobby_members(joined.id())?, vec![alice_contact.id()]);
    Ok(())
}
