use super::*;

#[test]
fn ordered_send_receive_is_atomic_and_uses_smallest_class() {
    let (mut initiator, mut responder) = pair();
    let outbound = initiator.send_data(b"hello").unwrap();
    assert_eq!(outbound.index, 0);
    assert_eq!(initiator.next_send_index(), 1);
    assert_eq!(
        decode_outer_header(&outbound.envelope)
            .unwrap()
            .envelope_class,
        EnvelopeClass::Lite
    );

    let received = responder.receive(&outbound.envelope).unwrap();
    assert_eq!(received.content_kind, ContentKind::Data);
    assert_eq!(received.content, b"hello");
    assert_eq!(responder.next_receive_index(), 1);
    assert_eq!(
        responder.receive(&outbound.envelope),
        Err(SessionError::ReplayDetected)
    );
}

#[test]
fn authentication_failure_preserves_receive_state() {
    let (mut initiator, mut responder) = pair();
    let mut outbound = initiator.send_data(b"auth").unwrap();
    outbound.envelope[100] ^= 1;
    assert_eq!(
        responder.receive(&outbound.envelope),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(responder.next_receive_index(), 0);
    assert_eq!(responder.skipped_key_count(), 0);
}

#[test]
fn authenticated_inner_binding_failure_preserves_receive_state() {
    let (mut initiator, mut responder) = pair();
    let malformed = initiator.send_invalid_binding_for_test().unwrap();
    assert_eq!(
        responder.receive(&malformed.envelope),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(responder.next_receive_index(), 0);
    assert_eq!(responder.skipped_key_count(), 0);
}

#[test]
fn bounded_out_of_order_and_skipped_keys_are_one_use() {
    let (mut initiator, mut responder) = pair();
    let first = initiator.send_data(b"zero").unwrap();
    let second = initiator.send_data(b"one").unwrap();
    let third = initiator.send_data(b"two").unwrap();

    assert_eq!(responder.receive(&third.envelope).unwrap().content, b"two");
    assert_eq!(responder.next_receive_index(), 3);
    assert_eq!(responder.skipped_key_count(), 2);

    let mut damaged_first = first.envelope.clone();
    damaged_first[100] ^= 1;
    assert_eq!(
        responder.receive(&damaged_first),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(responder.skipped_key_count(), 2);

    assert_eq!(responder.receive(&first.envelope).unwrap().content, b"zero");
    assert_eq!(responder.skipped_key_count(), 1);
    assert_eq!(
        responder.receive(&first.envelope),
        Err(SessionError::ReplayDetected)
    );
    assert_eq!(responder.receive(&second.envelope).unwrap().content, b"one");
    assert_eq!(responder.skipped_key_count(), 0);
}

#[test]
fn excessive_gap_rejects_without_derivation_or_commit() {
    let (mut initiator, mut responder) = pair();
    let mut last = None;
    for _ in 0..=MAX_SKIP + 1 {
        last = Some(initiator.send_data(b"x").unwrap());
    }
    let last = last.unwrap();
    assert_eq!(last.index, (MAX_SKIP + 1) as u64);
    assert_eq!(
        responder.receive(&last.envelope),
        Err(SessionError::MessageTooFarAhead)
    );
    assert_eq!(responder.next_receive_index(), 0);
    assert_eq!(responder.skipped_key_count(), 0);
}

#[test]
fn forward_gap_255_succeeds() {
    let (mut initiator, mut responder) = pair();
    let mut at_255 = None;
    for index in 0..=255 {
        let outbound = initiator.send_data(b"boundary").unwrap();
        if index == 255 {
            at_255 = Some(outbound);
        }
    }
    let received = responder.receive(&at_255.unwrap().envelope).unwrap();
    assert_eq!(received.index, 255);
    assert_eq!(responder.next_receive_index(), 256);
    assert_eq!(responder.skipped_key_count(), 255);
}

#[test]
fn forward_gap_256_preserves_oldest_skipped_key_for_one_delivery() {
    let (mut initiator, mut responder) = pair();
    let mut at_zero = None;
    let mut at_256 = None;
    for index in 0..=MAX_SKIP {
        let outbound = initiator.send_data(b"boundary").unwrap();
        if index == 0 {
            at_zero = Some(outbound);
        } else if index == MAX_SKIP {
            at_256 = Some(outbound);
        }
    }
    let at_zero = at_zero.unwrap();
    let received = responder.receive(&at_256.unwrap().envelope).unwrap();
    assert_eq!(received.index, MAX_SKIP as u64);
    assert_eq!(responder.skipped_key_count(), MAX_SKIP);

    assert_eq!(responder.receive(&at_zero.envelope).unwrap().index, 0);
    assert_eq!(
        responder.receive(&at_zero.envelope),
        Err(SessionError::ReplayDetected)
    );
}

#[test]
fn failed_send_and_counter_exhaustion_do_not_advance() {
    let (mut initiator, _) = pair();
    assert_eq!(
        initiator.send_data(&vec![0; FULL_MAX_CONTENT_SIZE + 1]),
        Err(SessionError::InvalidPayload)
    );
    assert_eq!(initiator.next_send_index(), 0);
    initiator.set_test_send_index(u64::MAX);
    assert_eq!(
        initiator.send_data(b"x"),
        Err(SessionError::CounterExhausted)
    );
    assert_eq!(initiator.next_send_index(), u64::MAX);
}

#[test]
fn class_capacity_boundaries_select_or_reject_exactly() {
    let boundaries = [
        (hydra_core::LITE_MAX_CONTENT_SIZE, EnvelopeClass::Lite),
        (
            hydra_core::STANDARD_MAX_CONTENT_SIZE,
            EnvelopeClass::Standard,
        ),
        (hydra_core::FULL_MAX_CONTENT_SIZE, EnvelopeClass::Full),
    ];
    for (maximum, expected_class) in boundaries {
        for length in [maximum - 1, maximum] {
            let (mut sender, _) = pair();
            let outbound = sender.send_data(&vec![0x5a; length]).unwrap();
            assert_eq!(
                decode_outer_header(&outbound.envelope)
                    .unwrap()
                    .envelope_class,
                expected_class
            );
        }
    }

    let (mut lite_overflow, _) = pair();
    assert_eq!(
        decode_outer_header(
            &lite_overflow
                .send_data(&vec![0; hydra_core::LITE_MAX_CONTENT_SIZE + 1])
                .unwrap()
                .envelope
        )
        .unwrap()
        .envelope_class,
        EnvelopeClass::Standard
    );
    let (mut standard_overflow, _) = pair();
    assert_eq!(
        decode_outer_header(
            &standard_overflow
                .send_data(&vec![0; hydra_core::STANDARD_MAX_CONTENT_SIZE + 1])
                .unwrap()
                .envelope
        )
        .unwrap()
        .envelope_class,
        EnvelopeClass::Full
    );
    let (mut full_overflow, _) = pair();
    let before = full_overflow.test_state_hash();
    assert_eq!(
        full_overflow.send_data(&vec![0; hydra_core::FULL_MAX_CONTENT_SIZE + 1]),
        Err(SessionError::InvalidPayload)
    );
    assert_eq!(full_overflow.test_state_hash(), before);
}

#[test]
fn final_representable_send_index_succeeds_once() {
    let (mut sender, _) = pair();
    sender.set_test_send_index(u64::MAX - 1);
    assert_eq!(sender.send_data(b"last").unwrap().index, u64::MAX - 1);
    assert_eq!(sender.next_send_index(), u64::MAX);
    let before = sender.test_state_hash();
    assert_eq!(
        sender.send_data(b"overflow"),
        Err(SessionError::CounterExhausted)
    );
    assert_eq!(sender.test_state_hash(), before);
}

#[test]
fn each_send_consumes_a_distinct_key_index() {
    let (mut initiator, _) = pair();
    let first = initiator.send_data(b"same").unwrap();
    let second = initiator.send_data(b"same").unwrap();
    assert_eq!((first.index, second.index), (0, 1));
    assert_ne!(first.envelope, second.envelope);
    assert_ne!(
        decode_outer_header(&first.envelope).unwrap().route_tag,
        decode_outer_header(&second.envelope).unwrap().route_tag
    );
}

#[test]
fn authenticated_close_stops_both_sides() {
    let (mut initiator, mut responder) = pair();
    let late_in_flight = responder.send_data(b"in flight").unwrap();
    let close = initiator.send_close(7).unwrap();
    assert_eq!(initiator.phase(), SessionPhase::Closing);
    assert_eq!(
        initiator.send_data(b"late"),
        Err(SessionError::InvalidState)
    );
    assert_eq!(
        initiator.receive(&late_in_flight.envelope),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(initiator.next_receive_index(), 0);
    let received = responder.receive(&close.envelope).unwrap();
    assert_eq!(received.content_kind, ContentKind::Close);
    assert_eq!(received.content, 7_u16.to_be_bytes());
    assert_eq!(responder.phase(), SessionPhase::Closed);
    assert_eq!(
        responder.receive(&close.envelope),
        Err(SessionError::InvalidState)
    );
}

#[test]
fn close_reason_code_accepts_every_representable_boundary() {
    for reason_code in [0, u16::MAX - 1, u16::MAX] {
        let (mut sender, mut receiver) = pair();
        let close = sender.send_close(reason_code).unwrap();
        let received = receiver.receive(&close.envelope).unwrap();
        assert_eq!(received.content_kind, ContentKind::Close);
        assert_eq!(received.content, reason_code.to_be_bytes());
        assert_eq!(sender.phase(), SessionPhase::Closing);
        assert_eq!(receiver.phase(), SessionPhase::Closed);
    }
}

#[test]
fn candidate_receive_route_tags_are_bounded_and_cover_valid_packets() {
    let (mut initiator, responder) = pair();
    let outbound = initiator.send_data(b"route-index").unwrap();
    let route_tag = decode_outer_header(&outbound.envelope).unwrap().route_tag;
    let candidates = responder.candidate_receive_route_tags().unwrap();
    assert_eq!(candidates.len(), MAX_SKIP + 1);
    assert!(candidates.contains(&route_tag));
}

#[test]
fn skipped_key_snapshot_restore_rejects_oversize_and_duplicates() {
    let (_, responder) = pair();
    let mut snapshot = responder.export_snapshot();
    let skipped = crate::SkippedMessageKeySnapshot {
        session_id: *responder.session_id(),
        direction: Direction::InitiatorToResponder,
        index: 0,
        key: [7; 32],
    };

    snapshot.skipped_keys = vec![skipped.clone(); MAX_SKIP + 1];
    assert!(matches!(
        SessionState::from_snapshot(snapshot),
        Err(SessionError::SkippedKeyLimit)
    ));

    let mut duplicate_snapshot = responder.export_snapshot();
    duplicate_snapshot.skipped_keys = vec![skipped.clone(), skipped];
    assert!(matches!(
        SessionState::from_snapshot(duplicate_snapshot),
        Err(SessionError::InvalidState)
    ));
}
