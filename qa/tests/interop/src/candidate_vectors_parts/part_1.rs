use std::{fs, path::PathBuf};

use hydra_core::{
    types::{EnvelopeClass, OuterMode},
    SUITE_ID,
};
use hydra_crypto::{
    CryptoBackend, MlDsaKeyPair, MlDsaVerificationKey, RustCryptoBackend, SecretBytes,
};
use hydra_envelope::decode_outer_header;
use hydra_session::{derive_initial_secrets, SessionRole, SessionState};

fn vector_path(category: &str, vector_id: &str, artifact: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/candidate")
        .join(category)
        .join(vector_id)
        .join(artifact)
}

fn artifact(category: &str, vector_id: &str, artifact: &str) -> Vec<u8> {
    fs::read(vector_path(category, vector_id, artifact)).unwrap()
}

fn exact<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    bytes.try_into().unwrap()
}

fn responder(vector_id: &str) -> SessionState {
    let transcript = exact::<64>(artifact("ratchet", vector_id, "transcript_hash.bin"));
    let handshake_secret = exact::<32>(artifact("ratchet", vector_id, "handshake_secret.bin"));
    let secrets =
        derive_initial_secrets(&SecretBytes::from_array(handshake_secret), &transcript).unwrap();
    SessionState::established(
        SessionRole::Responder,
        transcript,
        [0x22; 32],
        [0x11; 32],
        secrets,
    )
}

fn length_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(4 + bytes.len());
    output.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    output.extend_from_slice(bytes);
    output
}

#[test]
fn candidate_handshake_signatures_and_envelope_modes_verify() {
    for (vector_id, expected_mode) in [
        ("TV-HS-INIT-000", OuterMode::BootstrapInit),
        ("TV-HS-RESP-000", OuterMode::BootstrapResp),
    ] {
        let key = MlDsaVerificationKey::from_bytes(&artifact(
            "handshake",
            vector_id,
            "identity_verification_key.bin",
        ))
        .unwrap();
        key.verify_digest(
            &artifact("handshake", vector_id, "signature_digest.bin"),
            &artifact("handshake", vector_id, "signature.bin"),
        )
        .unwrap();
        let envelope = artifact("handshake", vector_id, "envelope.bin");
        let header = decode_outer_header(&envelope).unwrap();
        assert_eq!(header.mode, expected_mode);
        assert_eq!(header.envelope_class, EnvelopeClass::Standard);
        assert_eq!(envelope.len(), EnvelopeClass::Standard.envelope_size());
    }

    let finish = artifact("handshake", "TV-HS-CONF-000", "finish_envelope.bin");
    let finish_header = decode_outer_header(&finish).unwrap();
    assert_eq!(finish_header.mode, OuterMode::Protected);
    assert_eq!(finish_header.envelope_class, EnvelopeClass::Lite);
    assert_eq!(finish.len(), EnvelopeClass::Lite.envelope_size());
}

#[test]
fn candidate_negative_handshake_vectors_fail_closed() {
    let initiator = MlDsaVerificationKey::from_bytes(&artifact(
        "handshake",
        "TV-HS-TAMPER-000",
        "initiator_verification_key.bin",
    ))
    .unwrap();
    assert!(initiator
        .verify_digest(
            &artifact("handshake", "TV-HS-TAMPER-000", "init_signature_digest.bin",),
            &artifact(
                "handshake",
                "TV-HS-TAMPER-000",
                "tampered_init_signature.bin",
            ),
        )
        .is_err());

    let responder = MlDsaVerificationKey::from_bytes(&artifact(
        "handshake",
        "TV-HS-TAMPER-000",
        "responder_verification_key.bin",
    ))
    .unwrap();
    assert!(responder
        .verify_digest(
            &artifact("handshake", "TV-HS-TAMPER-000", "resp_signature_digest.bin",),
            &artifact(
                "handshake",
                "TV-HS-TAMPER-000",
                "tampered_resp_signature.bin",
            ),
        )
        .is_err());

    let confirm_key = SecretBytes::from_array(exact::<32>(artifact(
        "handshake",
        "TV-HS-TAMPER-000",
        "confirm_key.bin",
    )));
    assert!(RustCryptoBackend::verify_hmac_sha3_256(
        &confirm_key,
        &artifact("handshake", "TV-HS-TAMPER-000", "confirm_input.bin"),
        &artifact("handshake", "TV-HS-TAMPER-000", "tampered_resp_confirm.bin",),
    )
    .is_err());

    let finish_key = SecretBytes::from_array(exact::<32>(artifact(
        "handshake",
        "TV-HS-TAMPER-000",
        "finish_key.bin",
    )));
    assert!(RustCryptoBackend::aead_open(
        &finish_key,
        &[0_u8; 12],
        &artifact("handshake", "TV-HS-TAMPER-000", "finish_outer_header.bin",),
        &artifact(
            "handshake",
            "TV-HS-TAMPER-000",
            "tampered_finish_ciphertext_and_tag.bin",
        ),
    )
    .is_err());
}

#[test]
fn candidate_refresh_signatures_verify_and_mutation_fails() {
    let initiator = MlDsaKeyPair::from_seed(exact::<32>(artifact(
        "refresh",
        "TV-REFRESH-000",
        "initiator_identity_xi.bin",
    )))
    .unwrap();
    initiator
        .verification_key
        .verify_digest(
            &artifact("refresh", "TV-REFRESH-000", "refresh_init_digest.bin"),
            &artifact("refresh", "TV-REFRESH-000", "refresh_init_signature.bin"),
        )
        .unwrap();

    let responder = MlDsaKeyPair::from_seed(exact::<32>(artifact(
        "refresh",
        "TV-REFRESH-000",
        "responder_identity_xi.bin",
    )))
    .unwrap();
    responder
        .verification_key
        .verify_digest(
            &artifact("refresh", "TV-REFRESH-000", "refresh_resp_digest.bin"),
            &artifact("refresh", "TV-REFRESH-000", "refresh_resp_signature.bin"),
        )
        .unwrap();

    let bad_core = artifact("refresh", "TV-REFRESH-001", "refresh_init_core.bin");
    let bad_core_lp = length_prefixed(&bad_core);
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(b"HYDRA-MSG/v1/refresh-init-signature");
    digest_input.extend_from_slice(&SUITE_ID);
    digest_input.extend_from_slice(&bad_core_lp);
    let digest = RustCryptoBackend::sha3_512(&digest_input);
    let bad_key = MlDsaKeyPair::from_seed(exact::<32>(artifact(
        "refresh",
        "TV-REFRESH-001",
        "identity_xi.bin",
    )))
    .unwrap();
    assert!(bad_key
        .verification_key
        .verify_digest(
            &digest,
            &artifact("refresh", "TV-REFRESH-001", "mutated_signature.bin"),
        )
        .is_err());
    assert_eq!(
        artifact("refresh", "TV-REFRESH-001", "state_before.bin"),
        artifact("refresh", "TV-REFRESH-001", "state_after.bin")
    );
}

#[test]
fn candidate_identity_rotation_signatures_and_rejections_verify() {
    for seed_name in ["old_identity_xi.bin", "new_identity_xi.bin"] {
        let key = MlDsaKeyPair::from_seed(exact::<32>(artifact(
            "identity",
            "TV-ID-ROT-000",
            seed_name,
        )))
        .unwrap();
        let signature_name = if seed_name.starts_with("old") {
            "old_signature.bin"
        } else {
            "new_signature.bin"
        };
        key.verification_key
            .verify_digest(
                &artifact("identity", "TV-ID-ROT-000", "rotation_digest.bin"),
                &artifact("identity", "TV-ID-ROT-000", signature_name),
            )
            .unwrap();
    }

    assert_eq!(
        artifact("identity", "TV-ID-ROT-001", "state_before.bin"),
        artifact("identity", "TV-ID-ROT-001", "state_after.bin")
    );
    assert_eq!(
        artifact("identity", "TV-ID-ROT-002", "state_before.bin"),
        artifact("identity", "TV-ID-ROT-002", "state_after.bin")
    );
}

