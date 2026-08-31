use super::*;
use hydra_core::{ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE};
use hydra_crypto::{MlKemEncapsulationKey, SecretBytes};

#[test]
fn all_zero_x25519_and_invalid_mlkem_init_fail_before_cache_install() {
    let alice = fresh("target/hydra-msg-test-hostile-weak-init-alice");
    let mut bob = fresh("target/hydra-msg-test-hostile-weak-init-bob");
    let kem = RustCryptoBackend::mlkem768_generate().unwrap();
    let weak_x25519 =
        signed_offer_with_keys(&alice, &bob, [0; 32], &kem.encapsulation_key.to_bytes());
    assert_eq!(
        bob.reply_handshake(weak_x25519),
        Err(HydraMsgError::Crypto("rejected weak public key".to_owned()))
    );
    assert!(bob.accepted_inits.is_empty());

    let x25519 = RustCryptoBackend::x25519_generate().unwrap().public_key();
    let malformed_kem = signed_offer_with_keys(&alice, &bob, x25519, &[0xff; ML_KEM_768_EK_SIZE]);
    assert_eq!(
        bob.reply_handshake(malformed_kem),
        Err(HydraMsgError::Crypto(
            "invalid ML-KEM-768 encapsulation key encoding".to_owned()
        ))
    );
    assert!(bob.accepted_inits.is_empty());
}

#[test]
fn mlkem_implicit_rejection_cannot_authenticate_a_synthetic_response() {
    let mut alice = fresh("target/hydra-msg-test-hostile-kem-reject-alice");
    let mut bob = fresh("target/hydra-msg-test-hostile-kem-reject-bob");
    let (_alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let offer = alice.init_handshake(bob_contact).unwrap();
    let parsed = crate::codec::decode_handshake_offer(offer.as_bytes()).unwrap();
    let responder_x25519 = RustCryptoBackend::x25519_generate().unwrap();
    let x25519_shared =
        RustCryptoBackend::x25519_diffie_hellman(&responder_x25519, &parsed.x25519_public).unwrap();
    let forged_ciphertext = [0xa5; ML_KEM_768_CT_SIZE];
    let wrong_implicit_secret = SecretBytes::from_array([0x5a; 32]);
    let bob_record = bob.active_record().unwrap();
    let (answer, _) = crate::codec::encode_handshake_answer(
        crate::codec::HandshakeAnswerParts {
            public_key: &bob_record.public_key,
            nonce: [0x51; 32],
            x25519_public: responder_x25519.public_key(),
            kem_ciphertext: &forged_ciphertext,
            offer: &parsed,
            signing_key: &signing_key(&bob),
            x25519_secret: &x25519_shared,
            kem_secret: &wrong_implicit_secret,
        },
        [0x61; 16],
    )
    .unwrap();

    assert_eq!(
        alice.finish_handshake(HandshakeAnswer::from_bytes(answer)),
        Err(HydraMsgError::Crypto("authentication failed".to_owned()))
    );
    assert_eq!(
        alice.session_status(bob_contact).unwrap(),
        HydraSessionStatus::Pending
    );
}

#[test]
fn validly_signed_transcript_substitution_is_rejected() {
    let mut alice = fresh("target/hydra-msg-test-hostile-transcript-alice");
    let mut bob = fresh("target/hydra-msg-test-hostile-transcript-bob");
    let (_alice_contact, bob_contact) = contacts(&mut alice, &mut bob);
    let offer = alice.init_handshake(bob_contact).unwrap();
    let parsed = crate::codec::decode_handshake_offer(offer.as_bytes()).unwrap();
    let mut substituted = parsed.clone();
    substituted.init_hash[0] ^= 1;
    let responder_x25519 = RustCryptoBackend::x25519_generate().unwrap();
    let x25519_shared =
        RustCryptoBackend::x25519_diffie_hellman(&responder_x25519, &substituted.x25519_public)
            .unwrap();
    let kem_key = MlKemEncapsulationKey::from_bytes(&substituted.kem_public_key).unwrap();
    let (kem_ciphertext, kem_secret) = RustCryptoBackend::mlkem768_encapsulate(&kem_key).unwrap();
    let bob_record = bob.active_record().unwrap();
    let (answer, _) = crate::codec::encode_handshake_answer(
        crate::codec::HandshakeAnswerParts {
            public_key: &bob_record.public_key,
            nonce: [0x71; 32],
            x25519_public: responder_x25519.public_key(),
            kem_ciphertext: &kem_ciphertext,
            offer: &substituted,
            signing_key: &signing_key(&bob),
            x25519_secret: &x25519_shared,
            kem_secret: &kem_secret,
        },
        [0x81; 16],
    )
    .unwrap();

    assert_eq!(
        alice.finish_handshake(HandshakeAnswer::from_bytes(answer)),
        Err(HydraMsgError::InvalidInput("unknown handshake answer"))
    );
    assert_eq!(
        alice.session_status(bob_contact).unwrap(),
        HydraSessionStatus::Pending
    );
}
