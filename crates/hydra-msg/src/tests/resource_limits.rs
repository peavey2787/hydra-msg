use super::*;
use crate::{codec::*, limits::*};
use std::{fs, fs::File, path::Path};

fn fresh(path: impl AsRef<Path>) -> Hydra {
    let path = path.as_ref();
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn established_pair(prefix: &str) -> (Hydra, Hydra, ContactId, ContactId) {
    let mut alice = fresh(format!("target/{prefix}-alice"));
    let mut bob = fresh(format!("target/{prefix}-bob"));
    let alice_id = alice.generate_id("pw").unwrap();
    let bob_id = bob.generate_id("pw").unwrap();
    alice.set_active_id(alice_id, "pw").unwrap();
    bob.set_active_id(bob_id, "pw").unwrap();
    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    let answer = bob
        .reply_handshake(alice.init_handshake(bob_contact.id()).unwrap())
        .unwrap();
    alice.finish_handshake(answer).unwrap();
    (alice, bob, alice_contact.id(), bob_contact.id())
}

#[test]
fn declared_oversized_attachment_is_rejected_before_payload_read() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(PAYLOAD_MAGIC);
    write_u64(&mut encoded, 0);
    write_u32(&mut encoded, 1);
    encoded.push(2);
    write_u32(&mut encoded, 1);
    encoded.push(b'a');
    write_u64(&mut encoded, (MAX_ATTACHMENT_BYTES + 1) as u64);

    assert_eq!(
        unpack_message(
            &encoded,
            ContactId::from_bytes([0; hydra_core::HASH_SIZE]),
            MessageId::from_u64(1),
            None,
        ),
        Err(HydraMsgError::InvalidEncoding("attachment size"))
    );
}

#[test]
fn oversized_handshake_and_auth_token_are_rejected_at_parser_entry() {
    let oversized_offer = vec![0; MAX_HANDSHAKE_OFFER_BYTES + 1];
    let oversized_answer = vec![0; MAX_HANDSHAKE_ANSWER_BYTES + 1];
    let oversized_token = vec![0; MAX_ANONYMOUS_AUTH_TOKEN_BYTES + 1];
    assert!(decode_handshake_offer(&oversized_offer).is_err());
    assert!(decode_handshake_answer(&oversized_answer).is_err());
    assert!(decode_anonymous_auth_token(&oversized_token).is_err());
}

#[test]
fn oversized_attachment_file_is_rejected_without_reading_it() {
    let path = Path::new("target/hydra-msg-resource-limit-attachment.bin");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let file = File::create(path).unwrap();
    file.set_len((MAX_ATTACHMENT_BYTES + 1) as u64).unwrap();
    drop(file);

    assert_eq!(
        HydraAttachment::from_file(path),
        Err(HydraMsgError::InvalidInput("attachment size"))
    );
    let _ = fs::remove_file(path);
}

#[test]
fn oversized_native_state_is_rejected_from_metadata_before_reading() {
    let data_dir = Path::new("target/hydra-msg-resource-limit-state");
    let _ = fs::remove_dir_all(data_dir);
    fs::create_dir_all(data_dir).unwrap();
    let file = File::create(data_dir.join(STATE_FILE_NAME)).unwrap();
    file.set_len((MAX_ENCRYPTED_STATE_BYTES + 1) as u64)
        .unwrap();
    drop(file);

    assert!(Hydra::open(data_dir, "state-pw").is_err());
    let _ = fs::remove_dir_all(data_dir);
}

#[test]
fn encrypted_state_and_backup_reject_trailing_records_before_crypto_work() {
    let state_dir = Path::new("target/hydra-msg-resource-limit-state-trailing-record");
    let mut state_owner = fresh(state_dir);
    state_owner.generate_id("id-pw").unwrap();
    drop(state_owner);

    let encrypted_state_path = state_dir.join(STATE_FILE_NAME);
    let mut state = fs::read(&encrypted_state_path).unwrap();
    state.extend_from_slice(b"unexpected\tfield\n");
    fs::write(&encrypted_state_path, state).unwrap();
    assert!(Hydra::open(state_dir, "state-pw").is_err());

    let mut backup_owner = fresh("target/hydra-msg-resource-limit-backup-trailing-record");
    backup_owner.generate_id("id-pw").unwrap();
    let mut backup = backup_owner.export_backup("backup-pw").unwrap();
    backup.extend_from_slice(b"unexpected\tfield\n");
    assert!(backup_owner.verify_backup(&backup, "backup-pw").is_err());
}

#[test]
fn route_index_dispatches_to_one_session_and_refreshes_after_receive() {
    let (mut alice, mut bob, alice_contact, bob_contact) =
        established_pair("hydra-msg-resource-route-index");
    let first = alice
        .send(bob_contact, "first")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let first_tag = hydra_envelope::decode_outer_header(first.as_bytes())
        .unwrap()
        .route_tag;
    assert_eq!(
        bob.receive_routes.get(&first_tag).map(Vec::as_slice),
        Some(&[alice_contact][..])
    );

    bob.receive(first).unwrap().unwrap();
    assert!(!bob.receive_routes.contains_key(&first_tag));

    let second = alice
        .send(bob_contact, "second")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let second_tag = hydra_envelope::decode_outer_header(second.as_bytes())
        .unwrap()
        .route_tag;
    assert_eq!(
        bob.receive_routes.get(&second_tag).map(Vec::as_slice),
        Some(&[alice_contact][..])
    );
}

#[test]
fn incomplete_fragments_do_not_force_full_state_persistence() {
    let (mut alice, mut bob, _, bob_contact) =
        established_pair("hydra-msg-resource-fragment-persist");
    alice
        .set_packet_size(hydra_core::STANDARD_ENVELOPE_SIZE)
        .unwrap();
    bob.set_packet_size(hydra_core::STANDARD_ENVELOPE_SIZE)
        .unwrap();
    let payload = vec![b'x'; hydra_core::STANDARD_MAX_CONTENT_SIZE + 1];
    let packets = alice.send(bob_contact, payload).unwrap();
    assert!(packets.len() > 1);

    let generation_before = bob.storage_debug_status().state_generation;
    assert!(bob.receive(packets[0].clone()).unwrap().is_none());
    assert_eq!(
        bob.storage_debug_status().state_generation,
        generation_before
    );
    assert_eq!(bob.pending_fragments.len(), 1);
}
