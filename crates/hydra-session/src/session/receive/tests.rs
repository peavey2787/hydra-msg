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
