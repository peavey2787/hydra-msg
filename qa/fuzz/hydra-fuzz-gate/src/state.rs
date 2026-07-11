use hydra_core::types::EnvelopeClass;
use hydra_crypto::SecretBytes;
use hydra_msg::{Hydra, HydraMessage};
use hydra_session::{derive_initial_secrets, SessionRole, SessionState};

use crate::{corpus::FuzzInput, util};

pub fn run(inputs: &[FuzzInput]) -> util::FuzzResult<usize> {
    let mut cases = 0;
    for (index, input) in inputs.iter().enumerate() {
        util::no_panic(
            "hydra-state-transitions",
            &input.name,
            input.bytes.len(),
            || {
                exercise_hydra_state_transitions(index, &input.bytes);
            },
        )?;
        util::no_panic(
            "session-state-transitions",
            &input.name,
            input.bytes.len(),
            || {
                exercise_session_state_transitions(&input.bytes);
            },
        )?;
        cases += 2;
    }
    Ok(cases)
}

fn exercise_hydra_state_transitions(index: usize, bytes: &[u8]) {
    let base = util::temp_case_dir("state", index);
    let alice_dir = base.join("alice");
    let bob_dir = base.join("bob");
    let _ = std::fs::remove_dir_all(&base);

    let Some((mut alice, mut bob, bob_contact)) = paired_hydra(&alice_dir, &bob_dir) else {
        let _ = std::fs::remove_dir_all(&base);
        return;
    };

    let packet_size = if bytes.len().is_multiple_of(2) {
        56 * 1024
    } else {
        hydra_core::STANDARD_ENVELOPE_SIZE
    };
    let _ = alice.set_packet_size(packet_size);
    let _ = bob.set_packet_size(packet_size);

    let message = HydraMessage::bytes(bytes.to_vec());
    if let Ok(packets) = alice.send(bob_contact, message) {
        for packet in packets {
            let _ = bob.receive(packet.clone());
            let mut tampered = packet.into_bytes();
            if let Some(first) = tampered.first_mut() {
                *first ^= 0x80;
            }
            let _ = bob.receive(tampered);
        }
    }

    let _ = alice.rekey_session(bob_contact);
    let _ = alice.close_session(bob_contact);
    let _ = std::fs::remove_dir_all(&base);
}

fn paired_hydra(
    alice_dir: &std::path::Path,
    bob_dir: &std::path::Path,
) -> Option<(Hydra, Hydra, hydra_msg::ContactId)> {
    let mut alice = Hydra::open(alice_dir, "state-pw").ok()?;
    let mut bob = Hydra::open(bob_dir, "state-pw").ok()?;
    let alice_id = alice.generate_id("pw").ok()?;
    let bob_id = bob.generate_id("pw").ok()?;
    alice.set_active_id(alice_id, "pw").ok()?;
    bob.set_active_id(bob_id, "pw").ok()?;
    let _alice_contact = bob.add_contact(alice.create_contact_card().ok()?).ok()?;
    let bob_contact = alice.add_contact(bob.create_contact_card().ok()?).ok()?;
    let offer = alice.init_handshake(bob_contact.id()).ok()?;
    let answer = bob.reply_handshake(offer).ok()?;
    alice.finish_handshake(answer).ok()?;
    Some((alice, bob, bob_contact.id()))
}

fn exercise_session_state_transitions(bytes: &[u8]) {
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

    let bounded_content = &bytes[..bytes.len().min(EnvelopeClass::Lite.max_content_size())];
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
    let _ = receiver.receive(bytes);
}
