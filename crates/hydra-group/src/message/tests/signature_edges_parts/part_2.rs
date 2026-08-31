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
