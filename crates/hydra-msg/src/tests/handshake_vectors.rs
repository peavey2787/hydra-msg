use super::*;
use hydra_core::{types::EnvelopeClass, OUTER_HEADER_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use hydra_envelope::{decode_protected_record, encode_protected_record};

fn exact<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

fn canonical_offer_answer_material() -> (
    crate::codec::ParsedHandshakeOffer,
    crate::codec::ParsedHandshakeAnswer,
    crate::codec::HandshakeMaterial,
) {
    use crate::codec::{decode_handshake_answer, decode_handshake_offer, verify_answer_and_derive};

    let init =
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-INIT-000/envelope.bin");
    let resp =
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-RESP-000/envelope.bin");
    let offer = decode_handshake_offer(init).unwrap();
    let answer = decode_handshake_answer(resp).unwrap();
    let x25519 = SecretBytes::from_array(exact::<32>(include_bytes!(
        "../../../../qa/vectors/candidate/handshake/TV-HS-KDF-000/x25519_shared_secret.bin"
    )));
    let mlkem = SecretBytes::from_array(exact::<32>(include_bytes!(
        "../../../../qa/vectors/candidate/handshake/TV-HS-KDF-000/mlkem_shared_secret.bin"
    )));
    let material = verify_answer_and_derive(&answer, &offer, &x25519, &mlkem).unwrap();
    (offer, answer, material)
}

#[test]
fn public_handshake_parser_consumes_the_canonical_committed_vectors() {
    use crate::codec::{decode_handshake_answer, decode_handshake_offer};

    let init =
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-INIT-000/envelope.bin");
    let expected_responder = include_bytes!(
        "../../../../qa/vectors/candidate/handshake/TV-HS-INIT-000/responder_fingerprint.bin"
    );
    let expected_init_hash =
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-INIT-000/init_hash.bin");
    let parsed_init = decode_handshake_offer(init).unwrap();
    assert_eq!(
        parsed_init.expected_responder_fingerprint.as_slice(),
        expected_responder
    );
    assert_eq!(parsed_init.init_hash.as_slice(), expected_init_hash);

    let resp =
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-RESP-000/envelope.bin");
    let parsed_resp = decode_handshake_answer(resp).unwrap();
    assert_eq!(parsed_resp.init_hash.as_slice(), expected_init_hash);
    assert_eq!(
        parsed_resp.initiator_fingerprint,
        parsed_init.initiator_fingerprint
    );
}

#[test]
fn canonical_handshake_vectors_cover_kdf_confirmation_and_finish() {
    use crate::codec::verify_handshake_finish;

    let (_offer, _answer, material) = canonical_offer_answer_material();
    let finish = include_bytes!(
        "../../../../qa/vectors/candidate/handshake/TV-HS-CONF-000/finish_envelope.bin"
    );

    assert_eq!(
        material.handshake_secret.expose_secret(),
        include_bytes!(
            "../../../../qa/vectors/candidate/handshake/TV-HS-KDF-000/handshake_secret.bin"
        )
    );
    assert_eq!(
        material.transcript_hash.as_slice(),
        include_bytes!(
            "../../../../qa/vectors/candidate/handshake/TV-HS-RESP-000/transcript_hash.bin"
        )
    );
    assert_eq!(
        material.session_id.as_slice(),
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-KDF-000/session_id.bin")
    );
    assert_eq!(
        material.finish_key.expose_secret(),
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-KDF-000/finish_key.bin")
    );
    verify_handshake_finish(finish, &material).unwrap();
}

#[test]
fn response_verification_rejects_each_authenticated_binding_failure() {
    use crate::codec::verify_answer_and_derive;

    let (offer, answer, _material) = canonical_offer_answer_material();
    let x25519 = SecretBytes::from_array(exact::<32>(include_bytes!(
        "../../../../qa/vectors/candidate/handshake/TV-HS-KDF-000/x25519_shared_secret.bin"
    )));
    let mlkem = SecretBytes::from_array(exact::<32>(include_bytes!(
        "../../../../qa/vectors/candidate/handshake/TV-HS-KDF-000/mlkem_shared_secret.bin"
    )));

    let mut wrong_init = answer.clone();
    wrong_init.init_hash[0] ^= 1;
    assert_eq!(
        verify_answer_and_derive(&wrong_init, &offer, &x25519, &mlkem).err(),
        Some(HydraMsgError::InvalidEncoding("RESP does not match INIT"))
    );

    let mut wrong_initiator = answer.clone();
    wrong_initiator.initiator_fingerprint[0] ^= 1;
    assert_eq!(
        verify_answer_and_derive(&wrong_initiator, &offer, &x25519, &mlkem).err(),
        Some(HydraMsgError::InvalidEncoding(
            "RESP initiator fingerprint mismatch"
        ))
    );

    let mut wrong_responder = answer.clone();
    wrong_responder.responder_fingerprint[0] ^= 1;
    assert_eq!(
        verify_answer_and_derive(&wrong_responder, &offer, &x25519, &mlkem).err(),
        Some(HydraMsgError::InvalidEncoding(
            "RESP responder fingerprint mismatch"
        ))
    );

    let mut bad_signature = answer.clone();
    bad_signature.signature[0] ^= 1;
    assert!(matches!(
        verify_answer_and_derive(&bad_signature, &offer, &x25519, &mlkem),
        Err(HydraMsgError::Crypto(_))
    ));

    let mut bad_confirmation = answer;
    bad_confirmation.confirmation_tag[0] ^= 1;
    assert_eq!(
        verify_answer_and_derive(&bad_confirmation, &offer, &x25519, &mlkem).err(),
        Some(HydraMsgError::Crypto("authentication failed".to_owned()))
    );
}

#[test]
fn finish_verification_rejects_size_header_and_authenticated_record_mismatch() {
    use crate::codec::{encode_handshake_finish, verify_handshake_finish};

    let (_offer, _answer, material) = canonical_offer_answer_material();
    let finish = encode_handshake_finish(&material).unwrap();

    let short = &finish[..finish.len() - 1];
    assert_eq!(
        verify_handshake_finish(short, &material),
        Err(HydraMsgError::InvalidEncoding("FINISH envelope size"))
    );

    let mut long = finish.clone();
    long.push(0);
    assert_eq!(
        verify_handshake_finish(&long, &material),
        Err(HydraMsgError::InvalidEncoding("handshake FINISH size"))
    );

    let mut wrong_header = finish.clone();
    wrong_header[24] ^= 1;
    assert_eq!(
        verify_handshake_finish(&wrong_header, &material),
        Err(HydraMsgError::InvalidEncoding("FINISH header mismatch"))
    );

    let header = &finish[..OUTER_HEADER_SIZE];
    let plaintext = RustCryptoBackend::aead_open(
        &material.finish_key,
        &[0; 12],
        header,
        &finish[OUTER_HEADER_SIZE..],
    )
    .unwrap();
    let mut record = decode_protected_record(EnvelopeClass::Lite, &plaintext).unwrap();
    record.session_or_group_id[0] ^= 1;
    let altered_plaintext = encode_protected_record(EnvelopeClass::Lite, &record).unwrap();
    let altered_body =
        RustCryptoBackend::aead_seal(&material.finish_key, &[0; 12], header, &altered_plaintext)
            .unwrap();
    let mut altered = header.to_vec();
    altered.extend_from_slice(&altered_body);
    assert_eq!(
        verify_handshake_finish(&altered, &material),
        Err(HydraMsgError::InvalidEncoding(
            "FINISH transcript/session mismatch"
        ))
    );
}

#[test]
fn bootstrap_and_finish_envelopes_require_canonical_fixed_lengths() {
    use crate::codec::{decode_handshake_answer, decode_handshake_offer};

    let init =
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-INIT-000/envelope.bin");
    let resp =
        include_bytes!("../../../../qa/vectors/candidate/handshake/TV-HS-RESP-000/envelope.bin");
    assert!(decode_handshake_offer(&init[..init.len() - 1]).is_err());
    assert!(decode_handshake_answer(&resp[..resp.len() - 1]).is_err());
    let mut long_init = init.to_vec();
    long_init.push(0);
    let mut long_resp = resp.to_vec();
    long_resp.push(0);
    assert!(decode_handshake_offer(&long_init).is_err());
    assert!(decode_handshake_answer(&long_resp).is_err());

    let mut alice = fresh("target/hydra-msg-test-handshake-fixed-finish-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-fixed-finish-bob");
    let (alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let answer = bob
        .reply_handshake(alice.init_handshake(bob_contact).unwrap())
        .unwrap();
    let finish = alice.finish_handshake(answer).unwrap();
    let bytes = finish.clone().into_bytes();
    let mut long_finish = bytes.clone();
    long_finish.push(0);
    assert!(bob
        .accept_handshake_finish(HandshakeFinish::from_bytes(
            bytes[..bytes.len() - 1].to_vec()
        ))
        .is_err());
    assert!(bob
        .accept_handshake_finish(HandshakeFinish::from_bytes(long_finish))
        .is_err());
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Pending
    );
    bob.accept_handshake_finish(finish).unwrap();
    assert_eq!(
        bob.session_status(alice_contact).unwrap(),
        HydraSessionStatus::Active
    );
}
