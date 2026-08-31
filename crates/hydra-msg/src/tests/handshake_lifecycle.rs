use super::*;

#[test]
fn init_is_bound_to_the_expected_responder() {
    let mut alice = fresh("target/hydra-msg-test-handshake-bound-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-bound-bob");
    let mut mallory = fresh("target/hydra-msg-test-handshake-bound-mallory");
    let (_alice_contact, bob_contact) = contacts(&mut alice, &mut bob);

    let offer = alice.init_handshake(bob_contact).unwrap();
    assert_eq!(
        mallory.reply_handshake(offer),
        Err(HydraMsgError::InvalidInput(
            "INIT expected responder fingerprint mismatch"
        ))
    );
    assert_eq!(
        alice.session_status(bob_contact).unwrap(),
        HydraSessionStatus::Pending
    );
}

#[test]
fn responder_is_provisional_until_authenticated_finish() {
    let mut alice = fresh("target/hydra-msg-test-handshake-finish-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-finish-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);

    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Pending
    );

    let finish = alice.finish_handshake(answer).unwrap();
    assert_eq!(
        alice.session_status(bob_contact).unwrap(),
        HydraSessionStatus::Active
    );
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Pending
    );

    bob.accept_handshake_finish(finish).unwrap();
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Active
    );
}

#[test]
fn duplicate_init_returns_identical_cached_resp_and_never_rekeys() {
    let mut alice = fresh("target/hydra-msg-test-handshake-replay-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-replay-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);

    let offer = alice.init_handshake(bob_contact).unwrap();
    let parsed_offer = crate::codec::decode_handshake_offer(offer.as_bytes()).unwrap();
    let answer_one = bob.reply_handshake(offer.clone()).unwrap();
    let answer_two = bob.reply_handshake(offer.clone()).unwrap();
    assert_eq!(answer_one, answer_two);
    assert_eq!(bob.accepted_inits.len(), 1);
    let cache_key = bob.accepted_inits.keys().next().copied().unwrap();
    assert_eq!(
        cache_key.initiator_fingerprint,
        parsed_offer.initiator_fingerprint
    );
    assert_eq!(cache_key.init_nonce, parsed_offer.nonce);
    assert_eq!(cache_key.init_hash, parsed_offer.init_hash);
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Pending
    );

    let finish = alice.finish_handshake(answer_one.clone()).unwrap();
    bob.accept_handshake_finish(finish.clone()).unwrap();
    bob.accept_handshake_finish(finish).unwrap();

    let replay_answer = bob.reply_handshake(offer).unwrap();
    assert_eq!(replay_answer, answer_one);
    assert_eq!(bob.accepted_inits.len(), 1);

    let packet = alice
        .send(bob_contact, HydraMessage::text("same session"))
        .unwrap()
        .remove(0);
    let received = bob.receive(packet).unwrap().unwrap();
    assert_eq!(received.text().unwrap(), "same session");
}

#[test]
fn tampered_resp_and_finish_fail_without_responder_install() {
    let mut alice = fresh("target/hydra-msg-test-handshake-tamper-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-tamper-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);

    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    let mut tampered_answer = answer.clone().into_bytes();
    tampered_answer[hydra_core::OUTER_HEADER_SIZE + 20] ^= 1;
    assert!(alice
        .finish_handshake(HandshakeAnswer::from_bytes(tampered_answer))
        .is_err());
    assert_eq!(
        alice.session_status(bob_contact).unwrap(),
        HydraSessionStatus::Pending
    );

    let finish = alice.finish_handshake(answer).unwrap();
    let mut tampered_finish = finish.into_bytes();
    let last = tampered_finish.len() - 1;
    tampered_finish[last] ^= 1;
    assert!(bob
        .accept_handshake_finish(HandshakeFinish::from_bytes(tampered_finish))
        .is_err());
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Pending
    );
}

#[test]
fn handshake_is_bound_to_the_local_identity_for_its_full_lifetime() {
    let mut alice = fresh("target/hydra-msg-test-handshake-local-id-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-local-id-bob");
    let alice_original = alice.active_id().unwrap();
    let bob_original = bob.active_id().unwrap();
    let alice_other = alice.generate_id("other-pw").unwrap();
    let bob_other = bob.generate_id("other-pw").unwrap();
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);

    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();

    // Both alternate identities were generated and unlocked before the handshake.
    // Switch the test-only facade state directly so sanitizer/KDF runtime cannot
    // accidentally turn this identity-binding test into a handshake-expiry test.
    alice.active_id = Some(alice_other);
    assert_eq!(
        alice.finish_handshake(answer.clone()),
        Err(HydraMsgError::InvalidInput(
            "active identity changed during handshake"
        ))
    );
    alice.active_id = Some(alice_original);
    let finish = alice.finish_handshake(answer).unwrap();

    bob.active_id = Some(bob_other);
    assert_eq!(
        bob.accept_handshake_finish(finish.clone()),
        Err(HydraMsgError::InvalidInput(
            "active identity changed during handshake"
        ))
    );
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Pending
    );
    bob.active_id = Some(bob_original);
    bob.accept_handshake_finish(finish).unwrap();
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Active
    );
}

#[test]
fn expired_pending_handshake_is_rejected_deterministically() {
    let mut alice = fresh("target/hydra-msg-test-handshake-expiry-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-expiry-bob");
    let (_alice_contact, bob_contact) = contacts(&mut alice, &mut bob);

    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    alice.pending_offers.values_mut().next().unwrap().created_at =
        crate::time::HydraInstant::now_minus(std::time::Duration::from_secs(
            crate::limits::MAX_PENDING_HANDSHAKE_AGE_SECS + 1,
        ));

    assert_eq!(
        alice.finish_handshake(answer),
        Err(HydraMsgError::InvalidInput("unknown handshake answer"))
    );
    assert!(alice.pending_offers.is_empty());
}

#[test]
fn finish_outer_mode_and_counter_are_independent_requirements() {
    let mut alice = fresh("target/hydra-msg-test-finish-header-alice");
    let mut bob = fresh("target/hydra-msg-test-finish-header-bob");
    let (_alice_contact, bob_contact) = contacts(&mut alice, &mut bob);

    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    let finish = alice.finish_handshake(answer).unwrap();
    let original = finish.as_bytes().to_vec();
    let header = hydra_envelope::decode_outer_header(&original).unwrap();

    for replacement in [
        hydra_envelope::OuterHeader::new(
            hydra_core::types::OuterMode::BootstrapResp,
            hydra_core::types::EnvelopeClass::Lite,
            header.route_tag,
            0,
        ),
        hydra_envelope::OuterHeader::new(
            hydra_core::types::OuterMode::Protected,
            hydra_core::types::EnvelopeClass::Lite,
            header.route_tag,
            1,
        ),
    ] {
        let mut malformed = original.clone();
        let encoded = hydra_envelope::encode_outer_header(&replacement).unwrap();
        malformed[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            bob.accept_handshake_finish(HandshakeFinish::from_bytes(malformed)),
            Err(HydraMsgError::InvalidEncoding("FINISH outer header"))
        );
    }

    bob.accept_handshake_finish(finish).unwrap();
}
