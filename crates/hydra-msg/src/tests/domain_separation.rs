use super::*;
use std::fs;

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn unlocked(path: &str) -> Hydra {
    let mut hydra = fresh(path);
    let id = hydra.generate_id("id-pw").unwrap();
    hydra.set_active_id(id, "id-pw").unwrap();
    hydra
}

fn connect(alice: &mut Hydra, bob: &mut Hydra) -> (ContactId, ContactId) {
    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    let offer = alice.init_handshake(bob_contact.id()).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    alice.finish_handshake(answer).unwrap();
    (alice_contact.id(), bob_contact.id())
}

#[test]
fn lobby_ciphertext_is_not_accepted_as_direct_message() {
    let mut alice = unlocked("target/hydra-msg-test-domain-lobby-direct-alice");
    let mut bob = unlocked("target/hydra-msg-test-domain-lobby-direct-bob");
    let (alice_contact, bob_contact) = connect(&mut alice, &mut bob);
    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("domain lobby", 8))
        .unwrap();
    alice.add_lobby_member(lobby.id(), bob_contact).unwrap();
    bob.join_lobby(alice.create_lobby_member_invite(lobby.id()).unwrap())
        .unwrap();

    let lobby_packet = alice
        .send_lobby(lobby.id(), HydraMessage::text("lobby only"))
        .unwrap()
        .into_iter()
        .find(|copy| copy.recipient() == bob_contact)
        .unwrap()
        .into_envelope();

    assert!(bob.receive(lobby_packet).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());

    let fresh_lobby_packet = alice
        .send_lobby(lobby.id(), HydraMessage::text("lobby only"))
        .unwrap()
        .into_iter()
        .find(|copy| copy.recipient() == bob_contact)
        .unwrap()
        .into_envelope();
    let received = bob.receive_lobby(fresh_lobby_packet).unwrap().unwrap();
    assert_eq!(received.lobby_id(), Some(lobby.id()));
    assert_eq!(received.text().unwrap(), "lobby only");
}

#[test]
fn direct_ciphertext_is_not_accepted_as_lobby_message() {
    let mut alice = unlocked("target/hydra-msg-test-domain-direct-lobby-alice");
    let mut bob = unlocked("target/hydra-msg-test-domain-direct-lobby-bob");
    let (alice_contact, bob_contact) = connect(&mut alice, &mut bob);
    let packet = alice
        .send(bob_contact, HydraMessage::text("direct only"))
        .unwrap()
        .remove(0);

    assert!(bob.receive_lobby(packet.clone()).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());
    let received = bob.receive(packet).unwrap().unwrap();
    assert_eq!(received.lobby_id(), None);
    assert_eq!(received.text().unwrap(), "direct only");
}

#[test]
fn handshake_offer_and_answer_are_bound_to_identity_pair() {
    let mut alice = unlocked("target/hydra-msg-test-domain-handshake-alice");
    let bob = unlocked("target/hydra-msg-test-domain-handshake-bob");
    let mut carol = unlocked("target/hydra-msg-test-domain-handshake-carol");
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    alice
        .add_contact(carol.create_contact_card().unwrap())
        .unwrap();

    let offer_for_bob = alice.init_handshake(bob_contact.id()).unwrap();
    let carol_answer_to_bob_offer = carol.reply_handshake(offer_for_bob).unwrap();

    assert_eq!(
        alice.finish_handshake(carol_answer_to_bob_offer),
        Err(HydraMsgError::InvalidInput(
            "handshake answer does not match pending contact"
        ))
    );
    assert_eq!(
        alice.session_status(bob_contact.id()).unwrap(),
        HydraSessionStatus::Missing
    );
}

#[test]
fn storage_ciphertexts_do_not_parse_as_contact_message_or_lobby_formats() {
    let mut hydra = unlocked("target/hydra-msg-test-domain-storage-source");
    let contact = hydra
        .add_contact(hydra.create_contact_card().unwrap())
        .unwrap();
    hydra
        .store_message(contact.id(), true, b"domain storage".to_vec(), Vec::new())
        .unwrap();
    let state = hydra.flush_encrypted_state_snapshot().unwrap();
    let backup = hydra.export_backup("backup-pw").unwrap();

    for blob in [&state, &backup] {
        assert!(hydra.preview_contact_card(blob).is_err());
        assert!(hydra.add_contact(blob).is_err());
        assert!(hydra.import_contacts(blob).is_err());
        assert!(hydra.import_messages(blob).is_err());
        assert!(hydra.preview_lobby_invite(blob).is_err());
        assert!(hydra.join_lobby(blob).is_err());
    }
}

#[test]
fn anonymous_auth_tokens_are_bound_to_scope_and_action() {
    let mut hydra = fresh("target/hydra-msg-test-domain-auth-scope-action");
    let token = hydra
        .issue_anonymous_auth_token(HydraAnonymousAuthPolicy::new("scope-a", "join"))
        .unwrap();

    assert!(hydra
        .accept_anonymous_auth_token(&token, "scope-b", "join", 0)
        .is_err());
    assert!(hydra
        .accept_anonymous_auth_token(&token, "scope-a", "send", 0)
        .is_err());
    hydra
        .accept_anonymous_auth_token(&token, "scope-a", "join", 0)
        .unwrap();
}
