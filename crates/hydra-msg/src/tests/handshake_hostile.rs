use super::*;

#[test]
fn many_duplicate_inits_reuse_one_cached_response_and_one_session() {
    let mut alice = fresh("target/hydra-msg-test-hostile-many-init-alice");
    let mut bob = fresh("target/hydra-msg-test-hostile-many-init-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let offer = alice.init_handshake(bob_contact).unwrap();
    let parsed = crate::codec::decode_handshake_offer(offer.as_bytes()).unwrap();
    let first = bob.reply_handshake(offer.clone()).unwrap();
    let key = crate::handshake::AcceptedInitKey {
        initiator_fingerprint: parsed.initiator_fingerprint,
        init_nonce: parsed.nonce,
        init_hash: parsed.init_hash,
    };
    let session_id = bob.accepted_inits[&key]
        .candidate
        .as_ref()
        .unwrap()
        .material
        .session_id;

    for _ in 0..64 {
        assert_eq!(bob.reply_handshake(offer.clone()).unwrap(), first);
        assert_eq!(bob.accepted_inits.len(), 1);
        assert_eq!(bob.sessions.len(), 0);
        assert_eq!(
            bob.accepted_inits[&key]
                .candidate
                .as_ref()
                .unwrap()
                .material
                .session_id,
            session_id
        );
    }

    let finish = alice.finish_handshake(first.clone()).unwrap();
    bob.accept_handshake_finish(finish).unwrap();
    assert_eq!(bob.sessions.len(), 1);
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Active
    );
    for _ in 0..16 {
        assert_eq!(bob.reply_handshake(offer.clone()).unwrap(), first);
        assert_eq!(bob.sessions.len(), 1);
        assert_eq!(bob.accepted_inits.len(), 1);
    }
}

#[test]
fn reordered_responses_complete_their_original_contacts_only() {
    let mut alice = fresh("target/hydra-msg-test-hostile-reorder-alice");
    let mut bob = fresh("target/hydra-msg-test-hostile-reorder-bob");
    let mut carol = fresh("target/hydra-msg-test-hostile-reorder-carol");
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap()
        .id();
    let carol_contact = alice
        .add_contact(carol.create_contact_card().unwrap())
        .unwrap()
        .id();

    let bob_offer = alice.init_handshake(bob_contact).unwrap();
    let carol_offer = alice.init_handshake(carol_contact).unwrap();
    let bob_answer = bob.reply_handshake(bob_offer).unwrap();
    let carol_answer = carol.reply_handshake(carol_offer).unwrap();

    let carol_finish = alice.finish_handshake(carol_answer).unwrap();
    carol.accept_handshake_finish(carol_finish).unwrap();
    let bob_finish = alice.finish_handshake(bob_answer).unwrap();
    bob.accept_handshake_finish(bob_finish).unwrap();

    assert_eq!(
        alice.session_status(bob_contact).unwrap(),
        HydraSessionStatus::Active
    );
    assert_eq!(
        alice.session_status(carol_contact).unwrap(),
        HydraSessionStatus::Active
    );
}

#[test]
fn protocol_version_and_suite_downgrade_attempts_are_rejected() {
    let mut alice = fresh("target/hydra-msg-test-hostile-downgrade-alice");
    let mut bob = fresh("target/hydra-msg-test-hostile-downgrade-bob");
    let (_alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let original = alice.init_handshake(bob_contact).unwrap();
    let signer = signing_key(&alice);

    let mut version = original.clone().into_bytes();
    version[OUTER_HEADER_SIZE + 4] ^= 1;
    resign_init_core(&mut version, &signer);
    assert_eq!(
        bob.reply_handshake(HandshakeOffer::from_bytes(version)),
        Err(HydraMsgError::InvalidEncoding("INIT protocol version"))
    );

    let mut suite = original.into_bytes();
    suite[OUTER_HEADER_SIZE + 5] ^= 1;
    resign_init_core(&mut suite, &signer);
    assert_eq!(
        bob.reply_handshake(HandshakeOffer::from_bytes(suite)),
        Err(HydraMsgError::InvalidEncoding("INIT suite"))
    );
    assert!(bob.accepted_inits.is_empty());
}

#[test]
fn responder_fingerprint_pin_rejects_changed_contact_binding() {
    let mut alice = fresh("target/hydra-msg-test-hostile-fingerprint-alice");
    let mut bob = fresh("target/hydra-msg-test-hostile-fingerprint-bob");
    let carol = fresh("target/hydra-msg-test-hostile-fingerprint-carol");
    let (_alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    alice.contacts.get_mut(&bob_contact).unwrap().public_key =
        carol.active_record().unwrap().public_key;

    assert_eq!(
        alice.finish_handshake(answer),
        Err(HydraMsgError::InvalidInput(
            "RESP responder fingerprint does not match contact"
        ))
    );
    assert_eq!(
        alice.session_status(bob_contact).unwrap(),
        HydraSessionStatus::Pending
    );
}
