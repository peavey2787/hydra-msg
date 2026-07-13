use super::*;

#[test]
fn signature_verifier_exercises_every_explicit_guard() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let wrong_keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let class = signed_group_data_class(state.mode, 5).unwrap();
    let (header, step, record) =
        signed_record_fixture(&mut state, &keypair.signing_key, b"guard", class);

    assert_eq!(
        verify_group_data_signature_with_key(
            &state,
            &header,
            &step,
            &record,
            Some(keypair.verification_key.clone()),
        ),
        Ok(b"guard".to_vec())
    );

    let mut undersized = record.clone();
    undersized.content.truncate(4 + ML_DSA_65_SIG_SIZE - 1);
    assert_eq!(
        verify_group_data_signature_with_key(
            &state,
            &header,
            &step,
            &undersized,
            Some(keypair.verification_key.clone()),
        ),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut wrong_length = record.clone();
    wrong_length.content[..4].copy_from_slice(&6_u32.to_be_bytes());
    assert_eq!(
        verify_group_data_signature_with_key(
            &state,
            &header,
            &step,
            &wrong_length,
            Some(keypair.verification_key.clone()),
        ),
        Err(GroupError::InvalidGroupSignature)
    );

    let wrong_class = OuterHeader::new(
        OuterMode::Protected,
        EnvelopeClass::Standard,
        step.route_tag,
        step.index,
    );
    assert_eq!(
        verify_group_data_signature_with_key(
            &state,
            &wrong_class,
            &step,
            &record,
            Some(keypair.verification_key.clone()),
        ),
        Err(GroupError::InvalidGroupSignature)
    );

    assert_eq!(
        verify_group_data_signature_with_key(&state, &header, &step, &record, None),
        Err(GroupError::InvalidGroupSignature)
    );
    assert_eq!(
        verify_group_data_signature_with_key(
            &state,
            &header,
            &step,
            &record,
            Some(wrong_keypair.verification_key),
        ),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut missing_sender = signed_lite_state(&keypair.verification_key);
    missing_sender
        .roster
        .retain(|entry| entry.member_id != step.sender);
    assert_eq!(
        verify_group_data_signature_with_key(
            &missing_sender,
            &header,
            &step,
            &record,
            Some(keypair.verification_key),
        ),
        Err(GroupError::InvalidGroupSignature)
    );
}
