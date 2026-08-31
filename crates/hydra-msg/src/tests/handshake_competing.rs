use super::*;
#[test]
fn repeated_initiator_retry_reuses_identical_init_and_pending_state() {
    let mut alice = fresh("target/hydra-msg-test-handshake-init-retry-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-init-retry-bob");
    let (_alice_contact, bob_contact) = contacts(&mut alice, &mut bob);

    let first = alice.init_handshake(bob_contact).unwrap();
    let first_hash = crate::codec::decode_handshake_offer(first.as_bytes())
        .unwrap()
        .init_hash;
    let second = alice.init_handshake(bob_contact).unwrap();

    assert_eq!(second, first);
    assert_eq!(alice.pending_offers.len(), 1);
    assert!(alice.pending_offers.contains_key(&first_hash));
}

#[test]
fn simultaneous_cross_init_uses_identity_order_and_converges_on_one_session() {
    let mut alice = fresh("target/hydra-msg-test-handshake-cross-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-cross-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let alice_fingerprint =
        crate::codec::identity_fingerprint(&alice.active_record().unwrap().public_key);
    let bob_fingerprint =
        crate::codec::identity_fingerprint(&bob.active_record().unwrap().public_key);
    assert_ne!(alice_fingerprint, bob_fingerprint);

    let alice_offer = alice.init_handshake(bob_contact).unwrap();
    let bob_offer = bob.init_handshake(alice_contact).unwrap();

    if alice_fingerprint < bob_fingerprint {
        assert_eq!(
            alice.reply_handshake(bob_offer),
            Err(HydraMsgError::InvalidInput(
                "competing local initiator handshake takes precedence"
            ))
        );
        let answer = bob.reply_handshake(alice_offer).unwrap();
        assert!(bob.pending_offers.is_empty());
        let finish = alice.finish_handshake(answer).unwrap();
        bob.accept_handshake_finish(finish).unwrap();
    } else {
        assert_eq!(
            bob.reply_handshake(alice_offer),
            Err(HydraMsgError::InvalidInput(
                "competing local initiator handshake takes precedence"
            ))
        );
        let answer = alice.reply_handshake(bob_offer).unwrap();
        assert!(alice.pending_offers.is_empty());
        let finish = bob.finish_handshake(answer).unwrap();
        alice.accept_handshake_finish(finish).unwrap();
    }

    assert_eq!(
        alice.session_status(bob_contact).unwrap(),
        HydraSessionStatus::Active
    );
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Active
    );
    let packet = alice
        .send(bob_contact, HydraMessage::text("cross-init winner"))
        .unwrap()
        .remove(0);
    assert_eq!(
        bob.receive(packet).unwrap().unwrap().text().unwrap(),
        "cross-init winner"
    );
}

#[test]
fn stale_resp_from_losing_cross_init_cannot_replace_winner() {
    let mut alice = fresh("target/hydra-msg-test-handshake-stale-resp-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-stale-resp-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let alice_fingerprint =
        crate::codec::identity_fingerprint(&alice.active_record().unwrap().public_key);
    let bob_fingerprint =
        crate::codec::identity_fingerprint(&bob.active_record().unwrap().public_key);

    let (lower, higher, higher_contact_on_lower, lower_contact_on_higher) =
        if alice_fingerprint < bob_fingerprint {
            (&mut alice, &mut bob, bob_contact, alice_contact)
        } else {
            (&mut bob, &mut alice, alice_contact, bob_contact)
        };

    let losing_offer = higher.init_handshake(lower_contact_on_higher).unwrap();
    let stale_answer = lower.reply_handshake(losing_offer).unwrap();
    let winning_offer = lower.init_handshake(higher_contact_on_lower).unwrap();
    let winning_answer = higher.reply_handshake(winning_offer).unwrap();

    assert_eq!(
        higher.finish_handshake(stale_answer),
        Err(HydraMsgError::InvalidInput("unknown handshake answer"))
    );
    let winning_finish = lower.finish_handshake(winning_answer).unwrap();
    higher.accept_handshake_finish(winning_finish).unwrap();

    let packet = lower
        .send(
            higher_contact_on_lower,
            HydraMessage::text("winner survives stale RESP"),
        )
        .unwrap()
        .remove(0);
    assert_eq!(
        higher.receive(packet).unwrap().unwrap().text().unwrap(),
        "winner survives stale RESP"
    );
}

#[test]
fn stale_finish_from_superseded_cross_init_cannot_replace_winner() {
    let mut alice = fresh("target/hydra-msg-test-handshake-stale-finish-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-stale-finish-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let alice_fingerprint =
        crate::codec::identity_fingerprint(&alice.active_record().unwrap().public_key);
    let bob_fingerprint =
        crate::codec::identity_fingerprint(&bob.active_record().unwrap().public_key);

    let (lower, higher, higher_contact_on_lower, lower_contact_on_higher) =
        if alice_fingerprint < bob_fingerprint {
            (&mut alice, &mut bob, bob_contact, alice_contact)
        } else {
            (&mut bob, &mut alice, alice_contact, bob_contact)
        };

    let losing_offer = higher.init_handshake(lower_contact_on_higher).unwrap();
    let losing_answer = lower.reply_handshake(losing_offer).unwrap();
    let stale_finish = higher.finish_handshake(losing_answer).unwrap();

    let winning_offer = lower.init_handshake(higher_contact_on_lower).unwrap();
    let winning_answer = higher.reply_handshake(winning_offer).unwrap();
    let winning_finish = lower.finish_handshake(winning_answer).unwrap();
    higher.accept_handshake_finish(winning_finish).unwrap();

    assert_eq!(
        lower.accept_handshake_finish(stale_finish),
        Err(HydraMsgError::InvalidInput(
            "handshake FINISH has no provisional state"
        ))
    );
    let packet = higher
        .send(
            lower_contact_on_higher,
            HydraMessage::text("winner survives stale FINISH"),
        )
        .unwrap()
        .remove(0);
    assert_eq!(
        lower.receive(packet).unwrap().unwrap().text().unwrap(),
        "winner survives stale FINISH"
    );
}
