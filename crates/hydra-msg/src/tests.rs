use super::*;

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

#[test]
fn identity_export_import_roundtrip() {
    let mut hydra = fresh("target/hydra-msg-test-identity");
    let id = hydra.generate_id("pw").unwrap();
    assert_eq!(hydra.list_ids().len(), 1);
    assert_eq!(hydra.get_id(id).unwrap().id(), id);
    hydra.rename_id(id, "main").unwrap();
    assert_eq!(hydra.get_id(id).unwrap().label(), "main");
    let exported = hydra.export_id(id, "pw").unwrap();
    let imported = hydra.import_id(exported, "new-pw").unwrap();
    assert_eq!(id, imported);
    hydra.set_active_id(imported, "new-pw").unwrap();
    assert_eq!(hydra.active_id(), Some(imported));
    hydra.lock_active_id().unwrap();
    assert_eq!(hydra.active_id(), None);
    hydra.unlock_id(imported, "new-pw").unwrap();
    hydra.delete_id(imported, "new-pw").unwrap();
}

#[test]
fn contact_import_export_and_verification_roundtrip() {
    let mut alice = fresh("target/hydra-msg-test-contact-alice");
    let mut bob = fresh("target/hydra-msg-test-contact-bob");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();

    let bob_card = bob.create_contact_card().unwrap();
    let bob_contact = alice.add_contact(bob_card).unwrap();
    let safety = bob_contact.safety_code();
    alice.verify_contact(bob_contact.id(), safety).unwrap();
    assert!(alice.get_contact(bob_contact.id()).unwrap().verified());
    alice.unverify_contact(bob_contact.id()).unwrap();
    assert!(!alice.get_contact(bob_contact.id()).unwrap().verified());
    alice.rename_contact(bob_contact.id(), "Bob").unwrap();
    assert_eq!(alice.get_contact(bob_contact.id()).unwrap().label(), "Bob");

    let exported = alice.export_contacts().unwrap();
    let mut imported = fresh("target/hydra-msg-test-contact-import");
    imported.import_contacts(exported).unwrap();
    assert_eq!(imported.list_contacts().len(), 1);
    assert_eq!(
        imported.get_contact(bob_contact.id()).unwrap().label(),
        "Bob"
    );
    assert!(!imported.get_contact(bob_contact.id()).unwrap().verified());
    imported.block_contact(bob_contact.id()).unwrap();
    assert!(imported.get_contact(bob_contact.id()).unwrap().blocked());
    imported.unblock_contact(bob_contact.id()).unwrap();
    assert!(!imported.get_contact(bob_contact.id()).unwrap().blocked());
}

#[test]
fn contact_handshake_and_attachment_roundtrip() {
    let mut alice = fresh("target/hydra-msg-test-alice");
    let mut bob = fresh("target/hydra-msg-test-bob");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();

    let alice_card = alice.create_contact_card().unwrap();
    let bob_card = bob.create_contact_card().unwrap();
    let alice_contact = bob.add_contact(alice_card).unwrap();
    let bob_contact = alice.add_contact(bob_card).unwrap();

    let offer = alice.init_handshake(bob_contact.id()).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    alice.finish_handshake(answer).unwrap();
    assert_eq!(
        alice.session_status(bob_contact.id()).unwrap(),
        HydraSessionStatus::Active
    );
    assert_eq!(
        bob.session_status(alice_contact.id()).unwrap(),
        HydraSessionStatus::Active
    );

    let bytes_attachment = HydraAttachment::from_bytes(b"anonymous-bytes".to_vec()).unwrap();
    assert_eq!(bytes_attachment.filename(), "attachment.bin");
    assert!(bytes_attachment.is_bytes());

    let named_attachment = HydraAttachment::from_bytes(b"named-bytes".to_vec())
        .unwrap()
        .with_filename("note.bin")
        .unwrap();

    let envelope = alice
        .send(
            bob_contact.id(),
            HydraMessage {
                plaintext: b"hello".to_vec(),
                attachments: vec![bytes_attachment, named_attachment],
            },
        )
        .unwrap();
    let received = bob.receive(envelope).unwrap();
    assert_eq!(received.from(), alice_contact.id());
    assert_eq!(received.text().unwrap(), "hello");
    assert_eq!(received.attachments()[0].filename(), "attachment.bin");
    assert_eq!(received.attachments()[0].bytes(), b"anonymous-bytes");
    assert_eq!(received.attachments()[1].filename(), "note.bin");
    assert_eq!(received.attachments()[1].bytes(), b"named-bytes");
}

#[test]
fn authenticated_hybrid_handshake_rejects_tampered_offer_and_answer() {
    let mut alice = fresh("target/hydra-msg-test-handshake-tamper-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-tamper-bob");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();

    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();

    let offer = alice.init_handshake(bob_contact.id()).unwrap();
    let mut tampered_offer = offer.clone().into_bytes();
    let last = tampered_offer.len() - 2;
    tampered_offer[last] ^= 1;
    assert!(bob
        .reply_handshake(HandshakeOffer::from_bytes(tampered_offer))
        .is_err());

    let answer = bob.reply_handshake(offer).unwrap();
    let mut tampered_answer = answer.into_bytes();
    let last = tampered_answer.len() - 2;
    tampered_answer[last] ^= 1;
    assert!(alice
        .finish_handshake(HandshakeAnswer::from_bytes(tampered_answer))
        .is_err());

    let answer = bob
        .reply_handshake(alice.init_handshake(bob_contact.id()).unwrap())
        .unwrap();
    alice.finish_handshake(answer).unwrap();
    assert_eq!(
        alice.session_status(bob_contact.id()).unwrap(),
        HydraSessionStatus::Active
    );
    assert_eq!(
        bob.session_status(alice_contact.id()).unwrap(),
        HydraSessionStatus::Active
    );
}

#[test]
fn fluent_message_attachment_roundtrip() {
    let mut alice = fresh("target/hydra-msg-test-fluent-alice");
    let mut bob = fresh("target/hydra-msg-test-fluent-bob");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();
    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    let answer = bob
        .reply_handshake(alice.init_handshake(bob_contact.id()).unwrap())
        .unwrap();
    alice.finish_handshake(answer).unwrap();

    let envelope = alice
        .send(
            bob_contact.id(),
            HydraMessage::text("hello")
                .attach_bytes("data.bin", b"bytes".to_vec())
                .unwrap(),
        )
        .unwrap();
    let received = bob.receive(envelope).unwrap();
    assert_eq!(received.from(), alice_contact.id());
    assert_eq!(received.text().unwrap(), "hello");
    assert_eq!(received.attachments()[0].filename(), "data.bin");
    assert!(received.attachments()[0].is_bytes());
}

#[test]
fn lobby_backup_storage_and_benchmark_surface_exists() {
    let mut hydra = fresh("target/hydra-msg-test-lobby");
    let id = hydra.generate_id("pw").unwrap();
    hydra.set_active_id(id, "pw").unwrap();
    let lobby = hydra
        .create_lobby(HydraLobbyPolicy::new("test", 4))
        .unwrap();
    let invite = hydra.create_lobby_invite(lobby.id()).unwrap();
    let joined = hydra.join_lobby(invite).unwrap();
    assert_eq!(joined.id(), lobby.id());
    assert_eq!(hydra.list_lobbies().len(), 1);
    assert!(hydra.lobby_members(lobby.id()).unwrap().is_empty());
    hydra.rekey_lobby(lobby.id()).unwrap();
    let backup = hydra.export_backup("pw").unwrap();
    hydra.verify_backup(&backup).unwrap();
    hydra.import_backup(&backup, "pw").unwrap();
    let status = hydra.storage_status();
    assert_eq!(status.identity_count, 1);
    let report = hydra.benchmark().unwrap();
    assert_eq!(report.iterations, 30);
    hydra.close_lobby(lobby.id()).unwrap();
}

#[test]
fn lobby_send_receive_uses_recipient_tagged_envelopes_and_membership_checks() {
    let mut alice = fresh("target/hydra-msg-test-lobby-alice");
    let mut bob = fresh("target/hydra-msg-test-lobby-bob");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();

    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    let answer = bob
        .reply_handshake(alice.init_handshake(bob_contact.id()).unwrap())
        .unwrap();
    alice.finish_handshake(answer).unwrap();

    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("party", 4))
        .unwrap();
    alice
        .add_lobby_member(lobby.id(), bob_contact.id())
        .unwrap();
    let invite = alice.create_lobby_invite(lobby.id()).unwrap();
    let joined = bob.join_lobby(invite).unwrap();
    assert_eq!(joined.id(), lobby.id());
    assert_eq!(
        bob.lobby_members(joined.id()).unwrap(),
        vec![alice_contact.id()]
    );

    let outbound = alice
        .send_lobby(
            lobby.id(),
            HydraMessage::text("hello lobby")
                .attach_bytes("lobby.bin", b"payload".to_vec())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].recipient(), bob_contact.id());
    let received = bob.receive_lobby(outbound[0].envelope().clone()).unwrap();
    assert_eq!(received.from(), alice_contact.id());
    assert_eq!(received.lobby_id(), Some(joined.id()));
    assert_eq!(received.text().unwrap(), "hello lobby");
    assert_eq!(received.attachments()[0].filename(), "lobby.bin");

    let normal = alice.send(bob_contact.id(), "not a lobby message").unwrap();
    assert!(bob.receive_lobby(normal.clone()).is_err());
    assert_eq!(
        bob.receive(normal).unwrap().text().unwrap(),
        "not a lobby message"
    );
}
