use super::*;
use hydra_core::MAX_SKIP;
use hydra_crypto::SecretBytes;
use hydra_session::{derive_initial_secrets, SessionError, SessionRole, SessionState};

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn unlocked(path: &str) -> Hydra {
    let mut hydra = fresh(path);
    let id = hydra.generate_id("pw").unwrap();
    hydra.set_active_id(id, "pw").unwrap();
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
    let finish = alice.finish_handshake(answer).unwrap();
    bob.accept_handshake_finish(finish).unwrap();
    (alice_contact.id(), bob_contact.id())
}

#[test]
fn valid_envelope_with_wrong_route_tag_is_rejected_without_mutation() {
    let mut alice = unlocked("target/hydra-msg-test-adversarial-route-alice");
    let mut bob = unlocked("target/hydra-msg-test-adversarial-route-bob");
    let (alice_contact, bob_contact) = connect(&mut alice, &mut bob);
    let packet = alice
        .send(bob_contact, HydraMessage::text("route tag bound"))
        .unwrap()
        .remove(0);
    let mut bytes = packet.into_bytes();
    bytes[24] ^= 0x80;

    assert!(bob.receive(bytes).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());
}

#[test]
fn valid_envelope_replayed_to_another_contact_is_rejected() {
    let mut alice = unlocked("target/hydra-msg-test-adversarial-replay-alice");
    let mut bob = unlocked("target/hydra-msg-test-adversarial-replay-bob");
    let mut carol = unlocked("target/hydra-msg-test-adversarial-replay-carol");
    let (_alice_for_bob, bob_contact) = connect(&mut alice, &mut bob);
    let (alice_for_carol, _carol_contact) = connect(&mut alice, &mut carol);

    let packet = alice
        .send(bob_contact, HydraMessage::text("for bob only"))
        .unwrap()
        .remove(0);

    assert!(carol.receive(packet).is_err());
    assert!(carol.list_messages(alice_for_carol).is_empty());
}

#[test]
fn valid_envelope_for_removed_contact_is_rejected() {
    let mut alice = unlocked("target/hydra-msg-test-adversarial-removed-alice");
    let mut bob = unlocked("target/hydra-msg-test-adversarial-removed-bob");
    let (alice_contact, bob_contact) = connect(&mut alice, &mut bob);
    let packet = alice
        .send(bob_contact, HydraMessage::text("removed contact"))
        .unwrap()
        .remove(0);

    bob.remove_contact(alice_contact).unwrap();
    assert!(bob.receive(packet).is_err());
}

#[test]
fn lobby_packet_for_unknown_lobby_is_rejected_after_valid_transport_open() {
    let mut alice = unlocked("target/hydra-msg-test-adversarial-wrong-lobby-alice");
    let mut bob = unlocked("target/hydra-msg-test-adversarial-wrong-lobby-bob");
    let (alice_contact, bob_contact) = connect(&mut alice, &mut bob);
    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("sender-only", 8))
        .unwrap();
    alice.add_lobby_member(lobby.id(), bob_contact).unwrap();
    let packet = alice
        .send_lobby(lobby.id(), HydraMessage::text("wrong lobby"))
        .unwrap()
        .remove(0)
        .into_envelope();

    assert!(bob.receive_lobby(packet).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());
}

#[test]
fn old_direct_packet_after_fresh_session_is_rejected() {
    let mut alice = unlocked("target/hydra-msg-test-adversarial-old-after-rekey-alice");
    let mut bob = unlocked("target/hydra-msg-test-adversarial-old-after-rekey-bob");
    let (alice_contact, bob_contact) = connect(&mut alice, &mut bob);
    let packet = alice
        .send(bob_contact, HydraMessage::text("before rekey"))
        .unwrap()
        .remove(0);
    bob.receive(packet.clone()).unwrap();
    let offer = alice.begin_session_refresh(bob_contact).unwrap();
    let answer = bob.reply_session_refresh(offer).unwrap();
    let finish = alice.finish_session_refresh(answer).unwrap();
    bob.accept_session_refresh_finish(finish).unwrap();

    assert!(bob.receive(packet).is_err());
    assert_eq!(bob.list_messages(alice_contact).len(), 1);
}

#[test]
fn valid_session_message_under_wrong_role_is_rejected() {
    let secret = SecretBytes::from_array([0x42; 32]);
    let transcript = [0x24; 64];
    let secrets_sender = derive_initial_secrets(&secret, &transcript).unwrap();
    let secrets_wrong_receiver = derive_initial_secrets(&secret, &transcript).unwrap();
    let mut sender = SessionState::established(
        SessionRole::Initiator,
        transcript,
        [0x11; 32],
        [0x22; 32],
        secrets_sender,
    );
    let mut wrong_receiver = SessionState::established(
        SessionRole::Initiator,
        transcript,
        [0x11; 32],
        [0x22; 32],
        secrets_wrong_receiver,
    );
    let outbound = sender.send_data(b"wrong role").unwrap();

    assert_eq!(
        wrong_receiver.receive(&outbound.envelope),
        Err(SessionError::AuthenticationFailed)
    );
}

#[test]
fn future_session_counter_too_far_ahead_is_rejected() {
    let secret = SecretBytes::from_array([0x42; 32]);
    let transcript = [0x24; 64];
    let secrets_sender = derive_initial_secrets(&secret, &transcript).unwrap();
    let secrets_receiver = derive_initial_secrets(&secret, &transcript).unwrap();
    let mut sender = SessionState::established(
        SessionRole::Initiator,
        transcript,
        [0x11; 32],
        [0x22; 32],
        secrets_sender,
    );
    let mut receiver = SessionState::established(
        SessionRole::Responder,
        transcript,
        [0x22; 32],
        [0x11; 32],
        secrets_receiver,
    );
    let mut future = None;
    for _ in 0..=(MAX_SKIP + 1) {
        future = Some(sender.send_data(b"future").unwrap().envelope);
    }

    assert_eq!(
        receiver.receive(&future.unwrap()),
        Err(SessionError::MessageTooFarAhead)
    );
}

#[test]
fn handshake_answer_for_wrong_offer_is_rejected() {
    let mut alice = unlocked("target/hydra-msg-test-adversarial-wrong-answer-alice");
    let mut bob = unlocked("target/hydra-msg-test-adversarial-wrong-answer-bob");
    let carol = unlocked("target/hydra-msg-test-adversarial-wrong-answer-carol");
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    let carol_contact = alice
        .add_contact(carol.create_contact_card().unwrap())
        .unwrap();
    let bob_offer = alice.init_handshake(bob_contact.id()).unwrap();
    let _carol_offer = alice.init_handshake(carol_contact.id()).unwrap();
    let bob_answer = bob.reply_handshake(bob_offer).unwrap();
    let mut wrong_answer = bob_answer.into_bytes();
    // RESP control starts after the 64-byte outer header and 4-byte control length;
    // flip one byte inside the signed init_hash field.
    wrong_answer[hydra_core::OUTER_HEADER_SIZE + 4 + 1 + hydra_core::SUITE_ID.len()] ^= 1;

    assert_eq!(
        alice.finish_handshake(HandshakeAnswer::from_bytes(wrong_answer)),
        Err(HydraMsgError::InvalidInput("unknown handshake answer"))
    );
    assert_eq!(
        alice.session_status(bob_contact.id()).unwrap(),
        HydraSessionStatus::Pending
    );
    assert_eq!(
        alice.session_status(carol_contact.id()).unwrap(),
        HydraSessionStatus::Pending
    );
}

#[test]
fn replayed_handshake_answer_after_close_is_rejected() {
    let mut alice = unlocked("target/hydra-msg-test-adversarial-replayed-answer-alice");
    let mut bob = unlocked("target/hydra-msg-test-adversarial-replayed-answer-bob");
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    bob.add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let answer = bob
        .reply_handshake(alice.init_handshake(bob_contact.id()).unwrap())
        .unwrap();
    alice.finish_handshake(answer.clone()).unwrap();
    alice.close_session(bob_contact.id()).unwrap();

    assert_eq!(
        alice.finish_handshake(answer),
        Err(HydraMsgError::InvalidInput("unknown handshake answer"))
    );
    assert_eq!(
        alice.session_status(bob_contact.id()).unwrap(),
        HydraSessionStatus::Closed
    );
}
