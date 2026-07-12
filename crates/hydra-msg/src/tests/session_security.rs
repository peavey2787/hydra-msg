use super::*;

fn unlocked(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    let mut hydra = Hydra::open(path, "state-pw").unwrap();
    let id = hydra.generate_id("identity-pw").unwrap();
    hydra.set_active_id(id, "identity-pw").unwrap();
    hydra
}

fn connected(prefix: &str) -> (Hydra, Hydra, ContactId, ContactId) {
    let mut alice = unlocked(&format!("target/{prefix}-alice"));
    let mut bob = unlocked(&format!("target/{prefix}-bob"));
    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    let offer = alice.init_handshake(bob_contact.id()).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    alice.finish_handshake(answer).unwrap();
    (alice, bob, alice_contact.id(), bob_contact.id())
}

fn complete_refresh(alice: &mut Hydra, bob: &mut Hydra, bob_contact: ContactId) {
    let offer = alice.begin_session_refresh(bob_contact).unwrap();
    let answer = bob.reply_session_refresh(offer).unwrap();
    alice.finish_session_refresh(answer).unwrap();
}

#[test]
fn policy_builders_reject_zero_and_expose_precise_intervals() {
    assert_eq!(
        HydraSessionSecurityPolicy::ratchet_only().max_outbound_messages_per_session(),
        None
    );
    assert_eq!(
        HydraSessionSecurityPolicy::fresh_session_every_message()
            .max_outbound_messages_per_session(),
        Some(1)
    );
    assert_eq!(
        HydraSessionSecurityPolicy::every_messages(0),
        Err(HydraMsgError::InvalidInput(
            "session refresh interval must be at least one message"
        ))
    );
}

#[test]
fn every_message_policy_blocks_the_next_send_until_refresh_completes() {
    let (mut alice, mut bob, alice_contact, bob_contact) =
        connected("hydra-msg-test-session-security-every-message");
    alice.set_session_refresh_interval(bob_contact, 1).unwrap();
    assert_eq!(
        alice
            .session_security_policy(bob_contact)
            .unwrap()
            .max_outbound_messages_per_session(),
        Some(1)
    );

    let packet = alice
        .send(bob_contact, HydraMessage::text("first session message"))
        .unwrap()
        .remove(0);
    bob.receive(packet).unwrap().unwrap();
    let status = alice.session_security_status(bob_contact).unwrap();
    assert_eq!(status.outbound_messages_in_session(), 1);
    assert_eq!(status.remaining_messages(), Some(0));
    assert!(status.refresh_required());

    let before = alice.list_messages(bob_contact).len();
    assert_eq!(
        alice.send(bob_contact, HydraMessage::text("must refresh")),
        Err(HydraMsgError::SessionRefreshRequired)
    );
    assert_eq!(alice.list_messages(bob_contact).len(), before);

    complete_refresh(&mut alice, &mut bob, bob_contact);
    let status = alice.session_security_status(bob_contact).unwrap();
    assert_eq!(status.outbound_messages_in_session(), 0);
    assert!(!status.refresh_required());

    let packet = alice
        .send(bob_contact, HydraMessage::text("after refresh"))
        .unwrap()
        .remove(0);
    let received = bob.receive(packet).unwrap().unwrap();
    assert_eq!(received.from(), alice_contact);
    assert_eq!(received.text().unwrap(), "after refresh");

    alice.set_session_refresh_interval(bob_contact, 0).unwrap();
    assert_eq!(
        alice
            .session_security_policy(bob_contact)
            .unwrap()
            .max_outbound_messages_per_session(),
        None
    );
}

#[test]
fn fragmented_direct_send_counts_as_one_logical_message() {
    let (mut alice, _bob, _alice_contact, bob_contact) =
        connected("hydra-msg-test-session-security-fragmented");
    alice
        .set_packet_size(hydra_core::STANDARD_ENVELOPE_SIZE)
        .unwrap();
    alice.set_session_refresh_interval(bob_contact, 2).unwrap();

    let packets = alice
        .send(
            bob_contact,
            vec![b'x'; hydra_core::STANDARD_MAX_CONTENT_SIZE + 1],
        )
        .unwrap();
    assert!(packets.len() > 1);
    let status = alice.session_security_status(bob_contact).unwrap();
    assert_eq!(status.outbound_messages_in_session(), 1);
    assert_eq!(status.remaining_messages(), Some(1));
    assert!(!status.refresh_required());
}

#[test]
fn lobby_send_counts_one_logical_message_per_recipient_session() {
    let (mut alice, _bob, _alice_contact, bob_contact) =
        connected("hydra-msg-test-session-security-lobby");
    alice
        .set_session_security_policy(
            bob_contact,
            HydraSessionSecurityPolicy::fresh_session_every_message(),
        )
        .unwrap();
    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("cadence", 4))
        .unwrap();
    alice.add_lobby_member(lobby.id(), bob_contact).unwrap();

    assert!(!alice
        .send_lobby(lobby.id(), HydraMessage::text("one logical lobby message"))
        .unwrap()
        .is_empty());
    assert_eq!(
        alice.send_lobby(lobby.id(), HydraMessage::text("must refresh")),
        Err(HydraMsgError::SessionRefreshRequired)
    );
}

#[test]
fn security_policy_persists_but_session_counter_does_not_claim_persistence() {
    let path = "target/hydra-msg-test-session-security-persistence";
    let mut alice = unlocked(path);
    let bob = unlocked("target/hydra-msg-test-session-security-persistence-bob");
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap()
        .id();
    alice
        .set_session_security_policy(
            bob_contact,
            HydraSessionSecurityPolicy::every_messages(7).unwrap(),
        )
        .unwrap();
    drop(alice);

    let reopened = Hydra::open(path, "state-pw").unwrap();
    assert_eq!(
        reopened
            .session_security_policy(bob_contact)
            .unwrap()
            .max_outbound_messages_per_session(),
        Some(7)
    );
    assert_eq!(
        reopened.session_security_status(bob_contact),
        Err(HydraMsgError::SessionNotFound)
    );
}

#[test]
fn refresh_apis_require_an_existing_active_session() {
    let mut alice = unlocked("target/hydra-msg-test-session-security-no-session-alice");
    let bob = unlocked("target/hydra-msg-test-session-security-no-session-bob");
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap()
        .id();

    assert_eq!(
        alice.begin_session_refresh(bob_contact),
        Err(HydraMsgError::SessionNotFound)
    );
    assert!(alice.reply_session_refresh(b"not an offer").is_err());
}

#[test]
fn finish_methods_reject_answers_for_the_wrong_local_handshake_purpose() {
    let (mut alice, mut bob, _alice_contact, bob_contact) =
        connected("hydra-msg-test-session-security-purpose");

    let refresh_offer = alice.begin_session_refresh(bob_contact).unwrap();
    let refresh_answer = bob.reply_session_refresh(refresh_offer).unwrap();
    assert_eq!(
        alice.finish_handshake(refresh_answer.clone()),
        Err(HydraMsgError::InvalidInput(
            "handshake answer has the wrong local purpose"
        ))
    );
    alice.finish_session_refresh(refresh_answer).unwrap();

    let standard_offer = alice.init_handshake(bob_contact).unwrap();
    let standard_answer = bob.reply_handshake(standard_offer).unwrap();
    assert_eq!(
        alice.finish_session_refresh(standard_answer.clone()),
        Err(HydraMsgError::InvalidInput(
            "handshake answer has the wrong local purpose"
        ))
    );
    alice.finish_handshake(standard_answer).unwrap();
}

#[test]
fn session_security_policy_snapshot_rejects_duplicates_zero_and_orphans() {
    let (mut alice, _bob, _alice_contact, bob_contact) =
        connected("hydra-msg-test-session-security-snapshot-validation");
    alice.set_session_refresh_interval(bob_contact, 7).unwrap();
    let snapshot = String::from_utf8(alice.encode_state_snapshot().unwrap()).unwrap();
    let policy_line = snapshot
        .lines()
        .find(|line| line.starts_with("session_security_policy\t"))
        .expect("snapshot contains session security policy")
        .to_owned();

    let mut duplicate = snapshot.clone();
    duplicate.push_str(&policy_line);
    duplicate.push('\n');
    assert!(Hydra::verify_state_snapshot(duplicate.as_bytes()).is_err());

    let zero_policy = snapshot.replace(
        &policy_line,
        &format!("session_security_policy\t{}\t0", bob_contact.hex()),
    );
    assert!(Hydra::verify_state_snapshot(zero_policy.as_bytes()).is_err());

    let orphan = snapshot.replace(
        &policy_line,
        &format!(
            "session_security_policy\t{}\t7",
            ContactId([0xFE; 32]).hex()
        ),
    );
    assert!(Hydra::verify_state_snapshot(orphan.as_bytes()).is_err());
}

#[test]
fn removing_a_contact_removes_its_persisted_session_security_policy() {
    let (mut alice, _bob, _alice_contact, bob_contact) =
        connected("hydra-msg-test-session-security-remove-contact");
    alice.set_session_refresh_interval(bob_contact, 7).unwrap();
    alice.remove_contact(bob_contact).unwrap();
    assert_eq!(
        alice.session_security_policy(bob_contact),
        Err(HydraMsgError::ContactNotFound)
    );
    assert!(!String::from_utf8(alice.encode_state_snapshot().unwrap())
        .unwrap()
        .contains("session_security_policy\t"));
}
