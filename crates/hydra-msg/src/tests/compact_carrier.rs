use super::*;

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn connected_pair(suffix: &str) -> (Hydra, Hydra, ContactId, ContactId) {
    let mut alice = fresh(&format!("target/hydra-msg-test-compact-{suffix}-alice"));
    let mut bob = fresh(&format!("target/hydra-msg-test-compact-{suffix}-bob"));
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
    (alice, bob, alice_contact.id(), bob_contact.id())
}

#[test]
fn compact_and_fixed_messages_share_one_ratchet_and_can_arrive_out_of_order() {
    let (mut alice, mut bob, alice_contact, bob_contact) = connected_pair("interleave");
    let compact_first = alice.send_compact(bob_contact, "compact zero").unwrap();
    let fixed = alice.send(bob_contact, "fixed one").unwrap().remove(0);
    let compact_last = alice.send_compact(bob_contact, "compact two").unwrap();

    assert!(compact_first.as_bytes().len() < hydra_core::LITE_ENVELOPE_SIZE);
    assert_eq!(
        bob.receive(fixed).unwrap().unwrap().text().unwrap(),
        "fixed one"
    );
    let received = bob.receive_compact(compact_first.clone()).unwrap();
    assert_eq!(received.from(), alice_contact);
    assert_eq!(received.text().unwrap(), "compact zero");
    assert_eq!(
        bob.receive_compact(compact_last).unwrap().text().unwrap(),
        "compact two"
    );
    assert!(bob.receive_compact(compact_first).is_err());
}

#[test]
fn compact_envelope_tampering_is_rejected_without_consuming_the_message_key() {
    let (mut alice, mut bob, _, bob_contact) = connected_pair("tamper");
    let envelope = alice.send_compact(bob_contact, "authenticated").unwrap();
    let mut tampered = envelope.as_bytes().to_vec();
    *tampered.last_mut().unwrap() ^= 1;

    assert!(bob.receive_compact(tampered).is_err());
    assert_eq!(
        bob.receive_compact(envelope).unwrap().text().unwrap(),
        "authenticated"
    );
}
