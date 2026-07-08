use crate::{codec::*, Hydra, HydraMessage, HydraResult, IdentityId};
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
            let nonce = random_array::<32>()?;
            let left = IdentityId(random_array::<32>()?);
            let right = IdentityId(random_array::<32>()?);
            let start = Instant::now();
            let (secret, transcript_hash) = derive_facade_handshake_material(nonce, left, right);
            let left_secrets = derive_initial_secrets(&secret, &transcript_hash)?;
            let right_secrets = derive_initial_secrets(&secret, &transcript_hash)?;
            let mut left_session = SessionState::established(
                SessionRole::Initiator,
                transcript_hash,
                left.0,
                right.0,
                left_secrets,
            );
            let mut right_session = SessionState::established(
                SessionRole::Responder,
                transcript_hash,
                right.0,
                left.0,
                right_secrets,
            );
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
