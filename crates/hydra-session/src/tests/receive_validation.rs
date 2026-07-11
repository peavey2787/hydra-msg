use super::*;
use hydra_core::types::OuterMode;
use hydra_envelope::{encode_outer_header, OuterHeader, ProtectedRecord};

fn data_record(sender: &SessionState, content: &[u8]) -> ProtectedRecord {
    ProtectedRecord {
        content_kind: ContentKind::Data,
        session_or_group_id: *sender.session_id(),
        sender_id: [0; 32],
        epoch: 0,
        state_version: 0,
        message_index: sender.next_send_index(),
        content: content.to_vec(),
    }
}

fn replace_header(envelope: &mut [u8], header: &OuterHeader) {
    let encoded = encode_outer_header(header).unwrap();
    envelope[..encoded.len()].copy_from_slice(&encoded);
}

#[test]
fn protected_mode_and_non_exhausted_counter_are_independent_header_requirements() {
    let (mut wrong_mode_sender, mut wrong_mode_receiver) = pair();
    let mut wrong_mode = wrong_mode_sender.send_data(b"wrong mode").unwrap();
    let decoded = decode_outer_header(&wrong_mode.envelope).unwrap();
    replace_header(
        &mut wrong_mode.envelope,
        &OuterHeader::new(
            OuterMode::BootstrapInit,
            decoded.envelope_class,
            decoded.route_tag,
            decoded.counter,
        ),
    );
    assert_eq!(
        wrong_mode_receiver.receive(&wrong_mode.envelope),
        Err(SessionError::InvalidEnvelope)
    );

    let (mut exhausted_sender, mut exhausted_receiver) = pair();
    let mut exhausted = exhausted_sender.send_data(b"exhausted counter").unwrap();
    let decoded = decode_outer_header(&exhausted.envelope).unwrap();
    replace_header(
        &mut exhausted.envelope,
        &OuterHeader::new(
            OuterMode::Protected,
            decoded.envelope_class,
            decoded.route_tag,
            u64::MAX,
        ),
    );
    assert_eq!(
        exhausted_receiver.receive(&exhausted.envelope),
        Err(SessionError::InvalidEnvelope)
    );
}

#[test]
fn authenticated_state_version_mismatch_is_rejected_without_state_change() {
    let (mut sender, mut receiver) = pair();
    let mut record = data_record(&sender, b"state version");
    record.state_version = 1;
    let envelope = sender
        .seal_record_for_test(EnvelopeClass::Lite, record)
        .unwrap();
    let before = receiver.test_state_hash();
    assert_eq!(
        receiver.receive_validated(&envelope.envelope, |_| Ok(())),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(receiver.test_state_hash(), before);
}

#[test]
fn authenticated_message_index_mismatch_is_rejected_without_state_change() {
    let (mut sender, mut receiver) = pair();
    let mut record = data_record(&sender, b"message index");
    record.message_index += 1;
    let envelope = sender
        .seal_record_for_test(EnvelopeClass::Lite, record)
        .unwrap();
    let before = receiver.test_state_hash();
    assert_eq!(
        receiver.receive_validated(&envelope.envelope, |_| Ok(())),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(receiver.test_state_hash(), before);
}

#[test]
fn authenticated_content_class_mismatch_is_rejected_before_custom_validation() {
    let (mut sender, mut receiver) = pair();
    let mut record = data_record(&sender, b"identity rotation");
    record.content_kind = ContentKind::IdentityRotation;
    let envelope = sender
        .seal_record_for_test(EnvelopeClass::Lite, record)
        .unwrap();
    let before = receiver.test_state_hash();
    assert_eq!(
        receiver.receive_validated(&envelope.envelope, |_| Ok(())),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(receiver.test_state_hash(), before);
}
