#[test]
fn signed_group_message_rejects_different_mode_or_envelope_class_context() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut sender = signed_lite_state(&keypair.verification_key);
    let mut receiver = signed_lite_state(&keypair.verification_key);
    let outbound = sender
        .seal_signed_group_data(member(1), &keypair.signing_key, b"context-bound")
        .unwrap();

    let mut wrong_class = outbound.envelope.clone();
    wrong_class[6] = EnvelopeClass::Standard as u8;
    assert!(receiver
        .open_signed_group_data(&wrong_class, |_| Some(keypair.verification_key.clone()))
        .is_err());

    let mut wrong_mode = signed_lite_state(&keypair.verification_key);
    wrong_mode.mode = GroupMode::Broadcast;
    assert!(wrong_mode
        .open_signed_group_data(&outbound.envelope, |_| Some(
            keypair.verification_key.clone()
        ))
        .is_err());
}

fn signed_record_fixture(
    state: &mut GroupState,
    signing_key: &MlDsaSigningKey,
    content: &[u8],
    class: EnvelopeClass,
) -> (OuterHeader, crate::SenderMessageStep, ProtectedRecord) {
    let step = state.next_sender_message_step(member(1)).unwrap();
    let digest = group_data_signature_digest(state, class, &step, content).unwrap();
    let signature = RustCryptoBackend::mldsa65_sign(signing_key, &digest).unwrap();
    let mut signed_content = Vec::with_capacity(4 + content.len() + ML_DSA_65_SIG_SIZE);
    signed_content.extend_from_slice(&u32::try_from(content.len()).unwrap().to_be_bytes());
    signed_content.extend_from_slice(content);
    signed_content.extend_from_slice(&signature);
    let record = ProtectedRecord {
        content_kind: hydra_core::types::ContentKind::GroupData,
        session_or_group_id: state.group_id.0,
        sender_id: step.sender.0,
        epoch: state.epoch.0,
        state_version: state.state_version.0,
        message_index: step.index,
        content: signed_content,
    };
    let header = OuterHeader::new(OuterMode::Protected, class, step.route_tag, step.index);
    (header, step, record)
}

#[test]
fn undersized_signed_group_data_fails_closed_before_length_parsing() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let step = state.next_sender_message_step(member(1)).unwrap();
    let header = OuterHeader::new(
        OuterMode::Protected,
        EnvelopeClass::Lite,
        step.route_tag,
        step.index,
    );
    for content in [Vec::new(), vec![0], vec![0; 3]] {
        let record = ProtectedRecord {
            content_kind: hydra_core::types::ContentKind::GroupData,
            session_or_group_id: state.group_id.0,
            sender_id: step.sender.0,
            epoch: state.epoch.0,
            state_version: state.state_version.0,
            message_index: step.index,
            content,
        };
        assert_eq!(
            verify_group_data_signature(&state, &header, &step, &record, |_| {
                Some(keypair.verification_key.clone())
            }),
            Err(GroupError::InvalidGroupSignature)
        );
    }
}

#[test]
fn empty_signed_group_data_is_valid_at_the_exact_signature_boundary() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let class = signed_group_data_class(state.mode, 0).unwrap();
    let (header, step, record) =
        signed_record_fixture(&mut state, &keypair.signing_key, b"", class);
    assert_eq!(record.content.len(), 4 + ML_DSA_65_SIG_SIZE);
    assert_eq!(
        verify_group_data_signature(&state, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Ok(Vec::new())
    );
}

#[test]
fn signed_group_data_rejects_a_cryptographically_valid_wrong_class() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    assert_eq!(
        signed_group_data_class(state.mode, 1),
        Some(EnvelopeClass::Lite)
    );
    let (header, step, record) = signed_record_fixture(
        &mut state,
        &keypair.signing_key,
        b"x",
        EnvelopeClass::Standard,
    );
    assert_eq!(
        verify_group_data_signature(&state, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );
}

mod signature_edges;
mod signature_guards;
