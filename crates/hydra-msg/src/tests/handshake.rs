use super::*;
use hydra_core::{ML_DSA_65_SIG_SIZE, OUTER_HEADER_SIZE, SUITE_ID};
use hydra_crypto::{CryptoBackend, MlDsaKeyPair, RustCryptoBackend};

fn signing_key(hydra: &Hydra) -> hydra_crypto::MlDsaSigningKey {
    let seed = hydra.active_record().unwrap().seed.unwrap();
    MlDsaKeyPair::from_seed(seed).unwrap().signing_key
}

fn signed_offer_with_keys(
    initiator: &Hydra,
    responder: &Hydra,
    x25519_public: [u8; 32],
    kem_public_key: &[u8; hydra_core::ML_KEM_768_EK_SIZE],
) -> HandshakeOffer {
    let initiator_record = initiator.active_record().unwrap();
    let responder_record = responder.active_record().unwrap();
    HandshakeOffer::from_bytes(
        crate::codec::encode_handshake_offer(
            &initiator_record.public_key,
            [0x31; 32],
            crate::codec::identity_fingerprint(&responder_record.public_key),
            x25519_public,
            kem_public_key,
            &signing_key(initiator),
            [0x41; 16],
        )
        .unwrap(),
    )
}

fn resign_init_core(bytes: &mut [u8], signer: &hydra_crypto::MlDsaSigningKey) {
    let body = OUTER_HEADER_SIZE;
    let control_len = u32::from_be_bytes(bytes[body..body + 4].try_into().unwrap()) as usize;
    let core_start = body + 4;
    let core_end = core_start + control_len;
    let core = &bytes[core_start..core_end];
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(b"HYDRA-MSG/v1/init-signature");
    digest_input.extend_from_slice(&SUITE_ID);
    digest_input.extend_from_slice(&(core.len() as u32).to_be_bytes());
    digest_input.extend_from_slice(core);
    let digest = RustCryptoBackend::sha3_512(&digest_input);
    let signature = RustCryptoBackend::mldsa65_sign(signer, &digest).unwrap();
    bytes[core_end..core_end + ML_DSA_65_SIG_SIZE].copy_from_slice(&signature);
}

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    let mut hydra = Hydra::open(path, "state-pw").unwrap();
    let id = hydra.generate_id("pw").unwrap();
    hydra.set_active_id(id, "pw").unwrap();
    hydra
}

fn contacts(alice: &mut Hydra, bob: &mut Hydra) -> (ContactId, ContactId) {
    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    (alice_contact.id(), bob_contact.id())
}

#[path = "handshake_competing.rs"]
mod competing;
#[path = "handshake_hostile.rs"]
mod hostile;
#[path = "handshake_hostile_crypto.rs"]
mod hostile_crypto;
#[path = "handshake_lifecycle.rs"]
mod lifecycle;
#[path = "handshake_vectors.rs"]
mod vectors;
