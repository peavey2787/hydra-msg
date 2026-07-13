#![no_main]

use hydra_core::types::EnvelopeClass;
use hydra_crypto::SecretBytes;
use hydra_session::{derive_initial_secrets, SessionRole, SessionState};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let secret = SecretBytes::from_array([0x42; 32]);
    let transcript = [0x24; 64];
    let Ok(secrets_a) = derive_initial_secrets(&secret, &transcript) else {
        return;
    };
    let Ok(secrets_b) = derive_initial_secrets(&secret, &transcript) else {
        return;
    };
    let mut sender = SessionState::established(
        SessionRole::Initiator,
        transcript,
        [0x11; 32],
        [0x22; 32],
        secrets_a,
    );
    let mut receiver = SessionState::established(
        SessionRole::Responder,
        transcript,
        [0x22; 32],
        [0x11; 32],
        secrets_b,
    );

    let bounded_content = &data[..data.len().min(EnvelopeClass::Lite.max_content_size())];
    if let Ok(outbound) = sender.send_data(bounded_content) {
        let _ = receiver.receive(&outbound.envelope);
        let mut tampered = outbound.envelope;
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        let _ = receiver.receive(&tampered);
    }

    let _ = sender.begin_refresh([0x77; 32]);
    let _ = sender.abort_refresh();
    let _ = sender.send_close(0);
    let _ = receiver.receive(data);
});
