use crate::{codec::*, Hydra, HydraMessage, HydraResult, IdentityId};
use hydra_crypto::{CryptoBackend, MlKemEncapsulationKey, RustCryptoBackend};
use hydra_session::{derive_initial_secrets, SessionRole, SessionState};
use std::time::Instant;

/// Simple benchmark report.
#[derive(Clone, Debug, PartialEq)]
pub struct HydraBenchmarkReport {
    pub suite: &'static str,
    pub iterations: u32,
    pub handshake_avg_ms: f64,
    pub send_receive_avg_ms: f64,
}

impl Hydra {
    pub fn benchmark(&self) -> HydraResult<HydraBenchmarkReport> {
        const ITERATIONS: u32 = 30;
        let mut handshake_total = 0.0;
        let mut send_receive_total = 0.0;
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let (mut left_session, mut right_session) = benchmark_session_pair()?;
            handshake_total += start.elapsed().as_secs_f64() * 1_000.0;

            let payload = pack_message(&HydraMessage::text("benchmark"))?;
            let start = Instant::now();
            let envelope = left_session.send_data(&payload)?;
            let _ = right_session.receive(&envelope.envelope)?;
            send_receive_total += start.elapsed().as_secs_f64() * 1_000.0;
        }
        Ok(HydraBenchmarkReport {
            suite: "HYDRA1-MK768-M65",
            iterations: ITERATIONS,
            handshake_avg_ms: handshake_total / f64::from(ITERATIONS),
            send_receive_avg_ms: send_receive_total / f64::from(ITERATIONS),
        })
    }
}

fn benchmark_session_pair() -> HydraResult<(SessionState, SessionState)> {
    let left_keypair = RustCryptoBackend::mldsa65_generate()?;
    let right_keypair = RustCryptoBackend::mldsa65_generate()?;
    let left_public_key = left_keypair.verification_key.to_bytes();
    let right_public_key = right_keypair.verification_key.to_bytes();
    let left = IdentityId(RustCryptoBackend::sha3_256(&left_public_key));
    let right = IdentityId(RustCryptoBackend::sha3_256(&right_public_key));

    let offer_nonce = random_array::<32>()?;
    let left_x25519 = RustCryptoBackend::x25519_generate()?;
    let left_kem = RustCryptoBackend::mlkem768_generate()?;
    let left_kem_public = left_kem.encapsulation_key.to_bytes();
    let offer = encode_handshake_offer(
        left,
        &left_public_key,
        offer_nonce,
        left_x25519.public_key(),
        &left_kem_public,
        &left_keypair.signing_key,
    )?;
    let parsed_offer = decode_handshake_offer(&offer)?;

    let right_x25519 = RustCryptoBackend::x25519_generate()?;
    let right_x25519_secret =
        RustCryptoBackend::x25519_diffie_hellman(&right_x25519, &parsed_offer.x25519_public)?;
    let kem_public_key = MlKemEncapsulationKey::from_bytes(&parsed_offer.kem_public_key)?;
    let (kem_ciphertext, right_kem_secret) =
        RustCryptoBackend::mlkem768_encapsulate(&kem_public_key)?;
    let answer = encode_handshake_answer(
        right,
        &right_public_key,
        parsed_offer.nonce,
        random_array::<32>()?,
        right_x25519.public_key(),
        &kem_ciphertext,
        &parsed_offer,
        &right_keypair.signing_key,
        &right_x25519_secret,
        &right_kem_secret,
    )?;
    let parsed_answer = decode_handshake_answer(&answer)?;
    verify_answer_signature(&parsed_answer, &parsed_offer)?;

    let left_x25519_secret =
        RustCryptoBackend::x25519_diffie_hellman(&left_x25519, &parsed_answer.x25519_public)?;
    let left_kem_secret = RustCryptoBackend::mlkem768_decapsulate(
        &left_kem.decapsulation_key,
        &parsed_answer.kem_ciphertext,
    )?;
    let (left_secret, transcript_hash) = verify_answer_confirmation(
        &parsed_answer,
        &parsed_offer,
        &left_x25519_secret,
        &left_kem_secret,
    )?;
    let (right_secret, _) = verify_answer_confirmation(
        &parsed_answer,
        &parsed_offer,
        &right_x25519_secret,
        &right_kem_secret,
    )?;
    Ok((
        SessionState::established(
            SessionRole::Initiator,
            transcript_hash,
            left.0,
            right.0,
            derive_initial_secrets(&left_secret, &transcript_hash)?,
        ),
        SessionState::established(
            SessionRole::Responder,
            transcript_hash,
            right.0,
            left.0,
            derive_initial_secrets(&right_secret, &transcript_hash)?,
        ),
    ))
}
