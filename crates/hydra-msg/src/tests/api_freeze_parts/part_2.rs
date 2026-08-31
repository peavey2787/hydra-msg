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
    assert_eq!(
        HydraSessionSecurityPolicy::fresh_session_every_message()
            .max_outbound_messages_per_session(),
        Some(1)
    );
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
    let finish = alice.finish_handshake(answer).unwrap();
    bob.accept_handshake_finish(finish).unwrap();

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
