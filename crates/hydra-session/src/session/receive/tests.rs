use super::*;

fn record(kind: ContentKind, content_len: usize) -> ProtectedRecord {
    ProtectedRecord {
        content_kind: kind,
        session_or_group_id: [0; 32],
        sender_id: [0; 32],
        epoch: 0,
        state_version: 0,
        message_index: 0,
        content: vec![0; content_len],
    }
}

#[test]
fn valid_class_and_content_accepts_only_the_closed_session_matrix() {
    for class in [
        EnvelopeClass::Lite,
        EnvelopeClass::Standard,
        EnvelopeClass::Full,
    ] {
        assert!(valid_class_and_content(
            &record(ContentKind::Data, class.max_content_size()),
            class
        ));
        assert!(!valid_class_and_content(
            &record(ContentKind::Data, class.max_content_size() + 1),
            class
        ));
    }

    for kind in [ContentKind::RefreshInit, ContentKind::RefreshResp] {
        assert!(valid_class_and_content(
            &record(kind, 0),
            EnvelopeClass::Standard
        ));
        assert!(!valid_class_and_content(
            &record(kind, 0),
            EnvelopeClass::Lite
        ));
        assert!(!valid_class_and_content(
            &record(kind, 0),
            EnvelopeClass::Full
        ));
    }

    assert!(valid_class_and_content(
        &record(ContentKind::IdentityRotation, 0),
        EnvelopeClass::Standard
    ));
    assert!(!valid_class_and_content(
        &record(ContentKind::IdentityRotation, 0),
        EnvelopeClass::Lite
    ));
    assert!(!valid_class_and_content(
        &record(ContentKind::IdentityRotation, 0),
        EnvelopeClass::Full
    ));

    assert!(valid_class_and_content(
        &record(ContentKind::DeviceRevocation, 0),
        EnvelopeClass::Standard
    ));
    assert!(valid_class_and_content(
        &record(
            ContentKind::DeviceRevocation,
            EnvelopeClass::Standard.max_content_size() + 1,
        ),
        EnvelopeClass::Full
    ));
    assert!(!valid_class_and_content(
        &record(ContentKind::DeviceRevocation, 0),
        EnvelopeClass::Lite
    ));
    assert!(!valid_class_and_content(
        &record(ContentKind::DeviceRevocation, 0),
        EnvelopeClass::Full
    ));

    assert!(valid_class_and_content(
        &record(ContentKind::Close, 2),
        EnvelopeClass::Lite
    ));
    assert!(!valid_class_and_content(
        &record(ContentKind::Close, 1),
        EnvelopeClass::Lite
    ));
    assert!(!valid_class_and_content(
        &record(ContentKind::Close, 2),
        EnvelopeClass::Standard
    ));

    for kind in [
        ContentKind::HandshakeFinish,
        ContentKind::RefreshFinish,
        ContentKind::GroupCommit,
        ContentKind::GroupWelcome,
        ContentKind::GroupData,
    ] {
        assert!(!valid_class_and_content(
            &record(kind, 0),
            EnvelopeClass::Standard
        ));
    }
}

fn compact_pair() -> (SessionState, SessionState) {
    let transcript = [0x33; 64];
    let initiator_secrets = crate::derive_initial_secrets(
        &SecretBytes::from_array([0x44; 32]),
        &transcript,
    )
    .unwrap();
    let responder_secrets = crate::derive_initial_secrets(
        &SecretBytes::from_array([0x44; 32]),
        &transcript,
    )
    .unwrap();
    (
        SessionState::established(
            crate::SessionRole::Initiator,
            transcript,
            [0x11; 32],
            [0x22; 32],
            initiator_secrets,
        ),
        SessionState::established(
            crate::SessionRole::Responder,
            transcript,
            [0x22; 32],
            [0x11; 32],
            responder_secrets,
        ),
    )
}

#[test]
fn compact_encoding_requires_lite_data_and_bounded_content_independently() {
    assert!(valid_encoding_and_content(
        &record(ContentKind::Data, MAX_COMPACT_CONTENT_SIZE),
        EnvelopeClass::Lite,
        EnvelopeEncoding::Compact,
    ));
    assert!(!valid_encoding_and_content(
        &record(ContentKind::Data, 0),
        EnvelopeClass::Standard,
        EnvelopeEncoding::Compact,
    ));
    assert!(!valid_encoding_and_content(
        &record(ContentKind::Close, 2),
        EnvelopeClass::Lite,
        EnvelopeEncoding::Compact,
    ));
    assert!(!valid_encoding_and_content(
        &record(ContentKind::Data, MAX_COMPACT_CONTENT_SIZE + 1),
        EnvelopeClass::Lite,
        EnvelopeEncoding::Compact,
    ));
}

#[test]
fn compact_receive_enforces_exact_transport_bounds_and_lite_header() {
    let minimum = OUTER_HEADER_SIZE + AEAD_TAG_SIZE + INNER_HEADER_SIZE;

    let (mut sender, mut receiver) = compact_pair();
    let empty = sender.send_compact_data(&[]).unwrap();
    assert_eq!(empty.envelope.len(), minimum);
    assert!(receiver.receive_compact(&empty.envelope).unwrap().content.is_empty());

    let (mut sender, mut receiver) = compact_pair();
    let empty = sender.send_compact_data(&[]).unwrap();
    assert_eq!(
        receiver.receive_compact(&empty.envelope[..empty.envelope.len() - 1]),
        Err(SessionError::InvalidEnvelope)
    );

    let (mut sender, mut receiver) = compact_pair();
    let maximum = sender
        .send_compact_data(&vec![0xA5; MAX_COMPACT_CONTENT_SIZE])
        .unwrap();
    assert_eq!(maximum.envelope.len(), minimum + MAX_COMPACT_CONTENT_SIZE);
    assert_eq!(
        receiver.receive_compact(&maximum.envelope).unwrap().content.len(),
        MAX_COMPACT_CONTENT_SIZE
    );

    let (mut sender, mut receiver) = compact_pair();
    let mut oversized = sender
        .send_compact_data(&vec![0x5A; MAX_COMPACT_CONTENT_SIZE])
        .unwrap()
        .envelope;
    oversized.push(0);
    assert_eq!(
        receiver.receive_compact(&oversized),
        Err(SessionError::InvalidEnvelope)
    );

    let (mut sender, mut receiver) = compact_pair();
    let mut wrong_class = sender.send_compact_data(b"class").unwrap().envelope;
    let header = hydra_envelope::decode_outer_header_prefix(&wrong_class).unwrap();
    let replacement = hydra_envelope::OuterHeader::new(
        hydra_core::types::OuterMode::Protected,
        EnvelopeClass::Standard,
        header.route_tag,
        header.counter,
    );
    let encoded = hydra_envelope::encode_outer_header(&replacement).unwrap();
    wrong_class[..encoded.len()].copy_from_slice(&encoded);
    assert_eq!(
        receiver.receive_compact(&wrong_class),
        Err(SessionError::InvalidEnvelope)
    );
}
