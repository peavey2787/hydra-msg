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
