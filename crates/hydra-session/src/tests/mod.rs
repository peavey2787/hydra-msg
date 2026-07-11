use hydra_core::{
    types::{ContentKind, EnvelopeClass},
    FULL_MAX_CONTENT_SIZE, MAX_SKIP,
};
use hydra_crypto::SecretBytes;
use hydra_envelope::decode_outer_header;

use super::*;

fn pair() -> (SessionState, SessionState) {
    let transcript = [0x33; 64];
    let initiator_secrets =
        derive_initial_secrets(&SecretBytes::from_array([0x44; 32]), &transcript).unwrap();
    let responder_secrets =
        derive_initial_secrets(&SecretBytes::from_array([0x44; 32]), &transcript).unwrap();
    (
        SessionState::established(
            SessionRole::Initiator,
            transcript,
            [0x11; 32],
            [0x22; 32],
            initiator_secrets,
        ),
        SessionState::established(
            SessionRole::Responder,
            transcript,
            [0x22; 32],
            [0x11; 32],
            responder_secrets,
        ),
    )
}

mod refresh;
mod send_receive;
