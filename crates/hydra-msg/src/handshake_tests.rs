use super::*;

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    Hydra::open(path).unwrap()
}

fn field_hex(bytes: &[u8], name: &str) -> String {
    let text = std::str::from_utf8(bytes).unwrap();
    let prefix = format!("{name}:");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing field {name}"))
        .to_owned()
}

fn replace_field(bytes: Vec<u8>, name: &str, value: &str) -> Vec<u8> {
    let text = String::from_utf8(bytes).unwrap();
    let prefix = format!("{name}:");
    let mut replaced = false;
    let lines = text
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                replaced = true;
                format!("{prefix}{value}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>();
    assert!(replaced, "missing field {name}");
    let mut out = lines.join("\n").into_bytes();
    out.push(b'\n');
    out
}

#[test]
fn authenticated_hybrid_handshake_rejects_swapped_identity_answer() {
    let mut alice = fresh("target/hydra-msg-test-handshake-swap-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-swap-bob");
    let mut mallory = fresh("target/hydra-msg-test-handshake-swap-mallory");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    let mallory_id = mallory.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();
    mallory.set_active_id(mallory_id, "pw").unwrap();

    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    let offer = alice.init_handshake(bob_contact.id()).unwrap();
    let mallory_answer = mallory.reply_handshake(offer).unwrap();

    assert_eq!(
        alice.finish_handshake(mallory_answer),
        Err(HydraMsgError::InvalidInput(
            "handshake answer does not match pending contact"
        ))
    );
    assert_eq!(
        alice.session_status(bob_contact.id()).unwrap(),
        HydraSessionStatus::Missing
    );
}

#[test]
fn authenticated_hybrid_handshake_rejects_mismatched_answer_transcript() {
    let mut alice = fresh("target/hydra-msg-test-handshake-transcript-alice");
    let mut bob = fresh("target/hydra-msg-test-handshake-transcript-bob");
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();

    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    let first_offer = alice.init_handshake(bob_contact.id()).unwrap();
    let second_offer = alice.init_handshake(bob_contact.id()).unwrap();
    let second_offer_nonce = field_hex(second_offer.as_bytes(), "nonce");

    let answer = bob.reply_handshake(first_offer).unwrap();
    let transcript_swapped_answer = replace_field(
        answer.into_bytes(),
        "offer_nonce",
        &second_offer_nonce,
    );

    assert!(alice
        .finish_handshake(HandshakeAnswer::from_bytes(transcript_swapped_answer))
        .is_err());
    assert_eq!(
        alice.session_status(bob_contact.id()).unwrap(),
        HydraSessionStatus::Missing
    );
}
