use super::*;

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

#[test]
fn password_rotation_packet_size_and_previews_use_public_api() {
    let mut hydra = fresh("target/hydra-msg-test-api-freeze");
    assert_eq!(hydra.packet_size(), 56 * 1024);
    hydra.set_packet_size(4 * 1024).unwrap();
    assert_eq!(hydra.packet_size(), 4 * 1024);

    let id = hydra.generate_id("old-id-pw").unwrap();
    hydra
        .change_id_password(id, "old-id-pw", "new-id-pw")
        .unwrap();
    assert!(hydra.export_id(id, "old-id-pw").is_err());
    assert!(hydra.export_id(id, "new-id-pw").is_ok());

    hydra
        .change_state_password("state-pw", "new-state-pw")
        .unwrap();
    drop(hydra);
    assert!(Hydra::open("target/hydra-msg-test-api-freeze", "state-pw").is_err());
    let mut reopened = Hydra::open("target/hydra-msg-test-api-freeze", "new-state-pw").unwrap();
    reopened.set_active_id(id, "new-id-pw").unwrap();

    let card = reopened.create_labeled_contact_card("preview").unwrap();
    let contact = reopened.preview_contact_card(&card).unwrap();
    assert_eq!(contact.label(), "preview");
    assert!(reopened.list_contacts().is_empty());

    let lobby = reopened
        .create_lobby(HydraLobbyPolicy::new("preview-lobby", 4))
        .unwrap();
    let invite = reopened.create_labeled_lobby_invite(lobby.id()).unwrap();
    let preview = reopened.preview_lobby_invite(invite).unwrap();
    assert_eq!(preview.id(), lobby.id());
    assert_eq!(preview.policy().label, "preview-lobby");
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
fn contact_cards_default_to_minimized_metadata_and_one_time_ids() {
    let mut alice = fresh("target/hydra-msg-test-contact-p4-alice");
    let alice_id = alice.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();

    let default_card = alice.create_contact_card().unwrap();
    let default_text = String::from_utf8(default_card.clone()).unwrap();
    assert!(default_text.contains("HYDRA-MSG-CONTACT"));
    assert!(default_text.contains("public_key:"));
    assert!(!default_text.contains("label:"));
    assert!(!default_text.contains("id:"));
    assert!(!default_text.contains("safety:"));

    let labeled_card = alice.create_labeled_contact_card("Alice").unwrap();
    let labeled_text = String::from_utf8(labeled_card).unwrap();
    assert!(labeled_text.contains("label:"));

    let one_time_a = alice.create_one_time_contact_card("one-time-a").unwrap();
    let one_time_b = alice.create_one_time_contact_card("one-time-b").unwrap();
    assert_ne!(one_time_a.identity_id(), alice_id);
    assert_ne!(one_time_a.identity_id(), one_time_b.identity_id());
    assert_ne!(one_time_a.card(), one_time_b.card());
    assert_eq!(alice.active_id(), Some(one_time_b.identity_id()));
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

    let packets = alice
        .send(
            bob_contact.id(),
            HydraMessage {
                plaintext: b"hello".to_vec(),
                attachments: vec![bytes_attachment, named_attachment],
            },
        )
        .unwrap();
    assert_eq!(packets.len(), 1);
    let received = bob.receive(packets[0].clone()).unwrap().unwrap();
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

    let packets = alice
        .send(
            bob_contact.id(),
            HydraMessage::text("hello")
                .attach_bytes("data.bin", b"bytes".to_vec())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(packets.len(), 1);
    let received = bob.receive(packets[0].clone()).unwrap().unwrap();
    assert_eq!(received.from(), alice_contact.id());
    assert_eq!(received.text().unwrap(), "hello");
    assert_eq!(received.attachments()[0].filename(), "data.bin");
    assert!(received.attachments()[0].is_bytes());
}

#[test]
fn lobby_invites_default_to_minimized_metadata_and_one_time_ids() {
    let mut alice = fresh("target/hydra-msg-test-lobby-p4-alice");
    let alice_id = alice.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();

    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("private party", 4))
        .unwrap();
    let invite = alice.create_lobby_invite(lobby.id()).unwrap();
    let invite_text = String::from_utf8(invite.clone().into_bytes()).unwrap();
    assert!(invite_text.contains("HYDRA-MSG-LOBBY-INVITE"));
    assert!(invite_text.contains("id:"));
    assert!(invite_text.contains("max_members:"));
    assert!(!invite_text.lines().any(|line| line.starts_with("label:")));
    assert!(!invite_text.lines().any(|line| line.starts_with("members:")));

    let labeled_invite = alice.create_labeled_lobby_invite(lobby.id()).unwrap();
    let labeled_text = String::from_utf8(labeled_invite.into_bytes()).unwrap();
    assert!(labeled_text.contains("label:"));

    let one_time_a = alice.create_one_time_lobby_invite(4).unwrap();
    let one_time_b = alice.create_one_time_lobby_invite(4).unwrap();
    assert_ne!(one_time_a.lobby_id(), lobby.id());
    assert_ne!(one_time_a.lobby_id(), one_time_b.lobby_id());
    assert_ne!(
        one_time_a.invite().as_bytes(),
        one_time_b.invite().as_bytes()
    );
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
    hydra.verify_backup(&backup, "pw").unwrap();
    hydra.import_backup(&backup, "pw").unwrap();
    let status = hydra.storage_debug_status();
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
    assert!(bob.lobby_members(joined.id()).unwrap().is_empty());
    bob.add_lobby_member(joined.id(), alice_contact.id())
        .unwrap();
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
    let received = bob
        .receive_lobby(outbound[0].envelope().clone())
        .unwrap()
        .unwrap();
    assert_eq!(received.from(), alice_contact.id());
    assert_eq!(received.lobby_id(), Some(joined.id()));
    assert_eq!(received.text().unwrap(), "hello lobby");
    assert_eq!(received.attachments()[0].filename(), "lobby.bin");

    let normal = alice.send(bob_contact.id(), "not a lobby message").unwrap();
    assert_eq!(normal.len(), 1);
    assert!(bob.receive_lobby(normal[0].clone()).is_err());
    assert_eq!(
        bob.receive(normal[0].clone())
            .unwrap()
            .unwrap()
            .text()
            .unwrap(),
        "not a lobby message"
    );
}
