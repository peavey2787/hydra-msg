use super::*;

#[test]
fn signed_group_data_rejects_declared_length_mismatch() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let class = signed_group_data_class(state.mode, 1).unwrap();
    let (header, step, mut record) =
        signed_record_fixture(&mut state, &keypair.signing_key, b"x", class);
    record.content[..4].copy_from_slice(&2_u32.to_be_bytes());

    assert_eq!(
        verify_group_data_signature(&state, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );
}

#[test]
fn signed_group_data_rejects_missing_roster_key_and_mutated_signature() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();

    let mut missing_key_state = signed_lite_state(&keypair.verification_key);
    let class = signed_group_data_class(missing_key_state.mode, 6).unwrap();
    let (header, step, record) = signed_record_fixture(
        &mut missing_key_state,
        &keypair.signing_key,
        b"signed",
        class,
    );
    assert_eq!(
        verify_group_data_signature(&missing_key_state, &header, &step, &record, |_| None),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut missing_roster_state = signed_lite_state(&keypair.verification_key);
    let class = signed_group_data_class(missing_roster_state.mode, 6).unwrap();
    let (header, step, record) = signed_record_fixture(
        &mut missing_roster_state,
        &keypair.signing_key,
        b"signed",
        class,
    );
    missing_roster_state
        .roster
        .retain(|entry| entry.member_id != member(1));
    assert_eq!(
        verify_group_data_signature(
            &missing_roster_state,
            &header,
            &step,
            &record,
            |_| Some(keypair.verification_key.clone()),
        ),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut mutated_signature_state = signed_lite_state(&keypair.verification_key);
    let class = signed_group_data_class(mutated_signature_state.mode, 6).unwrap();
    let (header, step, mut record) = signed_record_fixture(
        &mut mutated_signature_state,
        &keypair.signing_key,
        b"signed",
        class,
    );
    *record.content.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify_group_data_signature(
            &mutated_signature_state,
            &header,
            &step,
            &record,
            |_| Some(keypair.verification_key.clone()),
        ),
        Err(GroupError::InvalidGroupSignature)
    );
}

#[test]
fn group_signature_cannot_replay_across_authenticated_contexts() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut baseline = signed_lite_state(&keypair.verification_key);
    let class = signed_group_data_class(baseline.mode, 7).unwrap();
    let (header, step, record) = signed_record_fixture(
        &mut baseline,
        &keypair.signing_key,
        b"context",
        class,
    );

    let mut changed_group = signed_lite_state(&keypair.verification_key);
    changed_group.group_id.0[0] ^= 1;
    assert_eq!(
        verify_group_data_signature(&changed_group, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut changed_epoch = signed_lite_state(&keypair.verification_key);
    changed_epoch.epoch.0 += 1;
    assert_eq!(
        verify_group_data_signature(&changed_epoch, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut changed_version = signed_lite_state(&keypair.verification_key);
    changed_version.state_version.0 += 1;
    assert_eq!(
        verify_group_data_signature(&changed_version, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut changed_roster_hash = signed_lite_state(&keypair.verification_key);
    changed_roster_hash.roster_hash[0] ^= 1;
    assert_eq!(
        verify_group_data_signature(&changed_roster_hash, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut changed_tree_hash = signed_lite_state(&keypair.verification_key);
    changed_tree_hash.tree_hash[0] ^= 1;
    assert_eq!(
        verify_group_data_signature(&changed_tree_hash, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut changed_commit_hash = signed_lite_state(&keypair.verification_key);
    changed_commit_hash.last_commit_hash[0] ^= 1;
    assert_eq!(
        verify_group_data_signature(&changed_commit_hash, &header, &step, &record, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );

    let mut changed_content = record.clone();
    changed_content.content[4] ^= 1;
    assert_eq!(
        verify_group_data_signature(&baseline, &header, &step, &changed_content, |_| {
            Some(keypair.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );
}

#[test]
fn signature_digest_binds_sender_index_route_and_identity_key() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let step = state.next_sender_message_step(member(1)).unwrap();
    let baseline =
        group_data_signature_digest(&state, EnvelopeClass::Lite, &step, b"payload").unwrap();

    let mut changed_sender = crate::SenderMessageStep {
        sender: member(2),
        index: step.index,
        message_key: Secret32::new([1; 32]),
        next_chain_key: Secret32::new([2; 32]),
        route_tag: step.route_tag,
    };
    let sender_digest = group_data_signature_digest(
        &state,
        EnvelopeClass::Lite,
        &changed_sender,
        b"payload",
    )
    .unwrap();
    assert_ne!(baseline, sender_digest);
    changed_sender.clear();

    let changed_index = crate::SenderMessageStep {
        sender: step.sender,
        index: step.index + 1,
        message_key: Secret32::new([3; 32]),
        next_chain_key: Secret32::new([4; 32]),
        route_tag: step.route_tag,
    };
    assert_ne!(
        baseline,
        group_data_signature_digest(
            &state,
            EnvelopeClass::Lite,
            &changed_index,
            b"payload"
        )
        .unwrap()
    );

    let mut route_tag = step.route_tag;
    route_tag[0] ^= 1;
    let changed_route = crate::SenderMessageStep {
        sender: step.sender,
        index: step.index,
        message_key: Secret32::new([5; 32]),
        next_chain_key: Secret32::new([6; 32]),
        route_tag,
    };
    assert_ne!(
        baseline,
        group_data_signature_digest(
            &state,
            EnvelopeClass::Lite,
            &changed_route,
            b"payload"
        )
        .unwrap()
    );

    let other_keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    assert_ne!(
        identity_fingerprint(&keypair.verification_key),
        identity_fingerprint(&other_keypair.verification_key)
    );
}

#[test]
fn group_record_rejects_wrong_kind_and_authenticated_metadata() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let class = signed_group_data_class(state.mode, 4).unwrap();
    let (header, step, record) =
        signed_record_fixture(&mut state, &keypair.signing_key, b"kind", class);
    assert_eq!(
        super::super::open::validate_group_data_record_for_test(&state, &header, &step, &record),
        Ok(())
    );

    let mut malformed = Vec::new();
    let mut wrong_kind = record.clone();
    wrong_kind.content_kind = hydra_core::types::ContentKind::Data;
    malformed.push(wrong_kind);
    let mut wrong_group = record.clone();
    wrong_group.session_or_group_id[0] ^= 1;
    malformed.push(wrong_group);
    let mut wrong_sender = record.clone();
    wrong_sender.sender_id[0] ^= 1;
    malformed.push(wrong_sender);
    let mut wrong_epoch = record.clone();
    wrong_epoch.epoch += 1;
    malformed.push(wrong_epoch);
    let mut wrong_version = record.clone();
    wrong_version.state_version += 1;
    malformed.push(wrong_version);
    let mut wrong_index = record.clone();
    wrong_index.message_index += 1;
    malformed.push(wrong_index);

    for malformed_record in malformed {
        assert_eq!(
            super::super::open::validate_group_data_record_for_test(
                &state,
                &header,
                &step,
                &malformed_record,
            ),
            Err(GroupError::AuthenticationFailed)
        );
    }
}


#[test]
fn group_signature_rejects_cross_domain_replay() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let step = state.next_sender_message_step(member(1)).unwrap();
    let content = b"cross-domain";
    let group_digest =
        group_data_signature_digest(&state, EnvelopeClass::Lite, &step, content).unwrap();
    let signature = RustCryptoBackend::mldsa65_sign(&keypair.signing_key, &group_digest).unwrap();
    assert!(RustCryptoBackend::mldsa65_verify(
        &keypair.verification_key,
        &group_digest,
        &signature,
    )
    .is_ok());

    let mut fingerprint_domain = b"HYDRA-MSG/v1/fingerprint".to_vec();
    fingerprint_domain.extend_from_slice(&hydra_core::SUITE_ID);
    fingerprint_domain.extend_from_slice(&crate::lp(content).unwrap());
    let wrong_domain_digest = RustCryptoBackend::sha3_512(&fingerprint_domain);
    assert!(RustCryptoBackend::mldsa65_verify(
        &keypair.verification_key,
        &wrong_domain_digest,
        &signature,
    )
    .is_err());
}

#[test]
fn signature_domain_labels_match_protocol_literals() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let step = state.next_sender_message_step(member(1)).unwrap();
    let content = b"domain-vector";

    let mut core = Vec::new();
    core.extend_from_slice(&state.group_id.0);
    core.push(state.mode as u8);
    core.push(EnvelopeClass::Lite as u8);
    core.extend_from_slice(&crate::u64_be(state.epoch.0));
    core.extend_from_slice(&crate::u64_be(state.state_version.0));
    core.extend_from_slice(&state.roster_hash);
    core.extend_from_slice(&state.tree_hash);
    core.extend_from_slice(&state.last_commit_hash);
    core.extend_from_slice(&step.sender.0);
    core.extend_from_slice(&crate::u64_be(step.index));
    core.extend_from_slice(&step.route_tag);
    core.extend_from_slice(&RustCryptoBackend::sha3_512(content));

    let mut signature_input = b"HYDRA-MSG/v1/group/message/signature".to_vec();
    signature_input.extend_from_slice(&hydra_core::SUITE_ID);
    signature_input.extend_from_slice(&crate::lp(&core).unwrap());
    assert_eq!(
        group_data_signature_digest(&state, EnvelopeClass::Lite, &step, content).unwrap(),
        RustCryptoBackend::sha3_512(&signature_input)
    );

    let mut fingerprint_input = b"HYDRA-MSG/v1/fingerprint".to_vec();
    fingerprint_input.extend_from_slice(&hydra_core::SUITE_ID);
    fingerprint_input.extend_from_slice(&keypair.verification_key.to_bytes());
    assert_eq!(
        identity_fingerprint(&keypair.verification_key),
        IdentityFingerprint(RustCryptoBackend::sha3_256(&fingerprint_input))
    );
}
