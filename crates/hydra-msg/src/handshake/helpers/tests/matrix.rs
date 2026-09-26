use super::*;

#[test]
fn competing_helper_selectors_require_every_contact_purpose_identity_and_candidate_dimension() {
    let mut alice = fresh("target/hydra-msg-test-helper-matrix-alice");
    let mut bob = fresh("target/hydra-msg-test-helper-matrix-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let other_contact = ContactId::from_bytes([0xE1; 32]);
    let other_identity = IdentityId::from_bytes([0xE2; 32]);

    // A pending retry only conflicts when contact + purpose match and identity differs.
    alice.init_handshake(bob_contact).unwrap();
    let pending_key = *alice.pending_offers.keys().next().unwrap();
    let local_identity = alice.pending_offers[&pending_key].local_identity_id;
    assert_eq!(
        reject_other_pending_attempt(
            &alice,
            bob_contact,
            local_identity,
            HandshakePurpose::Standard,
        ),
        Ok(())
    );
    assert_eq!(
        reject_other_pending_attempt(
            &alice,
            bob_contact,
            other_identity,
            HandshakePurpose::Standard,
        ),
        Err(HydraMsgError::InvalidInput(
            "competing handshake already pending for another local identity"
        ))
    );
    alice
        .pending_offers
        .get_mut(&pending_key)
        .unwrap()
        .contact_id = other_contact;
    assert_eq!(
        reject_other_pending_attempt(
            &alice,
            bob_contact,
            other_identity,
            HandshakePurpose::Standard,
        ),
        Ok(())
    );
    alice
        .pending_offers
        .get_mut(&pending_key)
        .unwrap()
        .contact_id = bob_contact;
    alice.pending_offers.get_mut(&pending_key).unwrap().purpose = HandshakePurpose::SessionRefresh;
    assert_eq!(
        reject_other_pending_attempt(
            &alice,
            bob_contact,
            other_identity,
            HandshakePurpose::Standard,
        ),
        Ok(())
    );
    alice.pending_offers.clear();

    // Build one provisional inbound candidate on Alice.
    let inbound_offer = bob.init_handshake(alice_contact).unwrap();
    alice.reply_handshake(inbound_offer).unwrap();
    let accepted_key = *alice.accepted_inits.keys().next().unwrap();
    let local_public = alice.active_record().unwrap().public_key;
    let peer_public = bob.active_record().unwrap().public_key;

    assert_eq!(
        prepare_local_initiator_attempt(
            &alice,
            other_contact,
            &local_public,
            &peer_public,
            HandshakePurpose::Standard,
        ),
        Ok(false)
    );
    assert_eq!(
        prepare_local_initiator_attempt(
            &alice,
            bob_contact,
            &local_public,
            &peer_public,
            HandshakePurpose::SessionRefresh,
        ),
        Ok(false)
    );
    let candidate = alice
        .accepted_inits
        .get_mut(&accepted_key)
        .unwrap()
        .candidate
        .take()
        .unwrap();
    assert_eq!(
        prepare_local_initiator_attempt(
            &alice,
            bob_contact,
            &local_public,
            &peer_public,
            HandshakePurpose::Standard,
        ),
        Ok(false)
    );
    alice
        .accepted_inits
        .get_mut(&accepted_key)
        .unwrap()
        .candidate = Some(candidate);

    let expected =
        match identity_fingerprint(&local_public).cmp(&identity_fingerprint(&peer_public)) {
            Ordering::Less => Ok(true),
            Ordering::Greater => Err(HydraMsgError::InvalidInput(
                "competing responder handshake takes precedence",
            )),
            Ordering::Equal => Err(HydraMsgError::InvalidInput(
                "competing handshake identity collision",
            )),
        };
    assert_eq!(
        prepare_local_initiator_attempt(
            &alice,
            bob_contact,
            &local_public,
            &peer_public,
            HandshakePurpose::Standard,
        ),
        expected
    );

    // An existing provisional responder conflicts only on matching contact + purpose.
    assert_eq!(
        prepare_inbound_responder_attempt(
            &alice,
            other_contact,
            &local_public,
            [0; 32],
            HandshakePurpose::Standard,
        ),
        Ok(false)
    );
    assert_eq!(
        prepare_inbound_responder_attempt(
            &alice,
            bob_contact,
            &local_public,
            [0; 32],
            HandshakePurpose::SessionRefresh,
        ),
        Ok(false)
    );
    assert_eq!(
        prepare_inbound_responder_attempt(
            &alice,
            bob_contact,
            &local_public,
            [0; 32],
            HandshakePurpose::Standard,
        ),
        Err(HydraMsgError::InvalidInput(
            "competing INIT already has provisional responder state"
        ))
    );

    // Retirement must ignore other contacts and the explicitly kept candidate.
    alice
        .accepted_inits
        .get_mut(&accepted_key)
        .unwrap()
        .contact_id = other_contact;
    retire_competing_handshakes(&mut alice, bob_contact, None);
    assert!(alice.accepted_inits[&accepted_key].candidate.is_some());
    alice
        .accepted_inits
        .get_mut(&accepted_key)
        .unwrap()
        .contact_id = bob_contact;
    retire_competing_handshakes(&mut alice, bob_contact, Some(accepted_key));
    assert!(alice.accepted_inits[&accepted_key].candidate.is_some());
    retire_competing_handshakes(&mut alice, bob_contact, None);
    assert!(alice.accepted_inits[&accepted_key].candidate.is_none());

    // Rebuild a candidate and prove superseding uses both contact and purpose.
    alice.accepted_inits.clear();
    bob.pending_offers.clear();
    let inbound_offer = bob.init_handshake(alice_contact).unwrap();
    alice.reply_handshake(inbound_offer).unwrap();
    let accepted_key = *alice.accepted_inits.keys().next().unwrap();
    supersede_inbound_candidates(&mut alice, other_contact, HandshakePurpose::Standard);
    assert!(alice.accepted_inits[&accepted_key].candidate.is_some());
    supersede_inbound_candidates(&mut alice, bob_contact, HandshakePurpose::SessionRefresh);
    assert!(alice.accepted_inits[&accepted_key].candidate.is_some());
    supersede_inbound_candidates(&mut alice, bob_contact, HandshakePurpose::Standard);
    assert!(alice.accepted_inits[&accepted_key].candidate.is_none());

    // An outbound attempt is selected by contact + purpose, then identity ordering decides.
    alice.accepted_inits.clear();
    alice.pending_offers.clear();
    alice.init_handshake(bob_contact).unwrap();
    let local_fingerprint = identity_fingerprint(&local_public);
    let lower = predecessor(local_fingerprint);
    let higher = successor(local_fingerprint);
    assert_eq!(
        prepare_inbound_responder_attempt(
            &alice,
            other_contact,
            &local_public,
            lower,
            HandshakePurpose::Standard,
        ),
        Ok(false)
    );
    assert_eq!(
        prepare_inbound_responder_attempt(
            &alice,
            bob_contact,
            &local_public,
            lower,
            HandshakePurpose::SessionRefresh,
        ),
        Ok(false)
    );
    assert_eq!(
        prepare_inbound_responder_attempt(
            &alice,
            bob_contact,
            &local_public,
            lower,
            HandshakePurpose::Standard,
        ),
        Ok(true)
    );
    assert_eq!(
        prepare_inbound_responder_attempt(
            &alice,
            bob_contact,
            &local_public,
            higher,
            HandshakePurpose::Standard,
        ),
        Err(HydraMsgError::InvalidInput(
            "competing local initiator handshake takes precedence"
        ))
    );
    assert_eq!(
        prepare_inbound_responder_attempt(
            &alice,
            bob_contact,
            &local_public,
            local_fingerprint,
            HandshakePurpose::Standard,
        ),
        Err(HydraMsgError::InvalidInput(
            "competing handshake identity collision"
        ))
    );

    assert_eq!(alice.pending_offers.len(), 1);
    supersede_outbound_attempts(&mut alice, other_contact, HandshakePurpose::Standard);
    assert_eq!(alice.pending_offers.len(), 1);
    supersede_outbound_attempts(&mut alice, bob_contact, HandshakePurpose::SessionRefresh);
    assert_eq!(alice.pending_offers.len(), 1);
    supersede_outbound_attempts(&mut alice, bob_contact, HandshakePurpose::Standard);
    assert!(alice.pending_offers.is_empty());
}
