use super::*;

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    let mut hydra = Hydra::open(path, "state-pw").unwrap();
    let id = hydra.generate_id("pw").unwrap();
    hydra.set_active_id(id, "pw").unwrap();
    hydra
}

fn connected(test_name: &str) -> (Hydra, Hydra, ContactId, ContactId) {
    let alice_path = format!("target/hydra-msg-test-rollback-{test_name}-alice");
    let bob_path = format!("target/hydra-msg-test-rollback-{test_name}-bob");
    let mut alice = fresh(&alice_path);
    let mut bob = fresh(&bob_path);
    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap()
        .id();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap()
        .id();
    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    let finish = alice.finish_handshake(answer).unwrap();
    bob.accept_handshake_finish(finish).unwrap();
    (alice, bob, alice_contact, bob_contact)
}

#[test]
fn authenticated_generation_rollback_burns_only_the_broken_session() {
    let (mut alice, mut bob, alice_contact, bob_contact) =
        connected("authenticated-generation-rollback");
    let first = alice
        .send(bob_contact, HydraMessage::text("advance floor"))
        .unwrap()
        .remove(0);
    bob.receive(first).unwrap().unwrap();
    let floor = bob.peer_generation_floors[&alice_contact];
    assert!(floor > 0);

    bob.burn_contact_session(alice_contact);
    alice.burn_contact_session(bob_contact);
    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    let finish = alice.finish_handshake(answer).unwrap();
    bob.accept_handshake_finish(finish).unwrap();

    alice.state_generation = floor.saturating_sub(2);
    let stale = alice
        .send(bob_contact, HydraMessage::text("rolled back"))
        .unwrap()
        .remove(0);
    assert_eq!(
        bob.receive(stale),
        Err(HydraMsgError::StateRollbackDetected)
    );
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Missing
    );
}

#[test]
fn delayed_authenticated_packet_in_the_same_session_is_not_false_rollback() {
    let (mut alice, mut bob, _alice_contact, bob_contact) =
        connected("delayed-authenticated-packet");
    let older = alice
        .send(bob_contact, HydraMessage::text("older"))
        .unwrap()
        .remove(0);
    let newer = alice
        .send(bob_contact, HydraMessage::text("newer"))
        .unwrap()
        .remove(0);
    assert_eq!(
        bob.receive(newer).unwrap().unwrap().text().unwrap(),
        "newer"
    );
    assert_eq!(
        bob.receive(older).unwrap().unwrap().text().unwrap(),
        "older"
    );
}

#[test]
fn authenticated_external_freshness_anchor_detects_local_snapshot_rollback() {
    let mut hydra = fresh("target/hydra-msg-test-freshness-anchor");
    let anchor = hydra.state_freshness_anchor();
    assert!(anchor.generation() > 0);
    hydra.state_generation = anchor.generation() - 1;
    assert_eq!(
        hydra.verify_state_freshness_anchor(anchor),
        Err(HydraMsgError::StateRollbackDetected)
    );
}

#[test]
fn tampered_external_freshness_anchor_is_rejected_without_rollback_claim() {
    let mut hydra = fresh("target/hydra-msg-test-freshness-anchor-tamper");
    let mut bytes = hydra.state_freshness_anchor().into_bytes();
    bytes[39] ^= 1;
    let anchor = HydraStateFreshnessAnchor::from_bytes(bytes).unwrap();
    assert_eq!(
        hydra.verify_state_freshness_anchor(anchor),
        Err(HydraMsgError::InvalidEncoding(
            "state freshness anchor authenticator"
        ))
    );
}
