use super::*;

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn connect(alice: &mut Hydra, bob: &mut Hydra) -> (ContactId, ContactId) {
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
    (alice_contact.id(), bob_contact.id())
}

#[test]
fn lobby_routing_hints_are_randomized_and_not_authentication() {
    let mut alice = fresh("target/hydra-msg-test-lobby-routing-alice");
    let mut bob = fresh("target/hydra-msg-test-lobby-routing-bob");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();

    let (alice_contact, bob_contact) = connect(&mut alice, &mut bob);

    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("routing", 4))
        .unwrap();
    alice
        .add_lobby_member(lobby.id(), bob_contact)
        .unwrap();
    let joined = bob
        .join_lobby(alice.create_lobby_invite(lobby.id()).unwrap())
        .unwrap();
    bob.add_lobby_member(joined.id(), alice_contact).unwrap();

    let first = alice
        .send_lobby(lobby.id(), HydraMessage::text("first"))
        .unwrap();
    let second = alice
        .send_lobby(lobby.id(), HydraMessage::text("second"))
        .unwrap();
    assert_eq!(first[0].recipient(), bob_contact);
    assert_eq!(second[0].recipient(), bob_contact);
    assert_ne!(first[0].routing_hint(), second[0].routing_hint());

    let mut mislabeled = first[0].clone();
    mislabeled.recipient = ContactId::from_bytes([7; hydra_core::HASH_SIZE]);
    mislabeled.routing_hint = HydraLobbyRoutingHint::from_bytes([9; 32]);
    let received = bob.receive_lobby(mislabeled.into_envelope()).unwrap();
    assert_eq!(received.from(), alice_contact);
    assert_eq!(received.text().unwrap(), "first");
}

#[test]
fn lobby_envelope_sent_to_wrong_recipient_does_not_decrypt() {
    let mut alice = fresh("target/hydra-msg-test-lobby-wrong-route-alice");
    let mut bob = fresh("target/hydra-msg-test-lobby-wrong-route-bob");
    let mut carol = fresh("target/hydra-msg-test-lobby-wrong-route-carol");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    let carol_id = carol.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();
    carol.set_active_id(carol_id, "pw").unwrap();

    let (alice_for_bob, bob_contact) = connect(&mut alice, &mut bob);
    let (alice_for_carol, carol_contact) = connect(&mut alice, &mut carol);

    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("wrong-route", 4))
        .unwrap();
    alice.add_lobby_member(lobby.id(), bob_contact).unwrap();
    alice.add_lobby_member(lobby.id(), carol_contact).unwrap();

    let bob_joined = bob
        .join_lobby(alice.create_lobby_invite(lobby.id()).unwrap())
        .unwrap();
    bob.add_lobby_member(bob_joined.id(), alice_for_bob)
        .unwrap();
    let carol_joined = carol
        .join_lobby(alice.create_lobby_invite(lobby.id()).unwrap())
        .unwrap();
    carol
        .add_lobby_member(carol_joined.id(), alice_for_carol)
        .unwrap();

    let outbound = alice
        .send_lobby(lobby.id(), HydraMessage::text("private copy"))
        .unwrap();
    let bob_copy = outbound
        .iter()
        .find(|copy| copy.recipient() == bob_contact)
        .unwrap()
        .clone();

    assert!(carol.receive_lobby(bob_copy.envelope().clone()).is_err());
    let received = bob.receive_lobby(bob_copy.into_envelope()).unwrap();
    assert_eq!(received.from(), alice_for_bob);
    assert_eq!(received.text().unwrap(), "private copy");
}
