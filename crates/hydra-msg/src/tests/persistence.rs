use super::*;
use std::fs;

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

#[test]
fn platform_encrypted_snapshot_round_trips_without_adapter_parsing() {
    let mut hydra = fresh("target/hydra-msg-test-platform-snapshot-source");
    let id = hydra.generate_id("id-pw").unwrap();
    hydra.set_active_id(id, "id-pw").unwrap();
    let contact = hydra
        .add_contact(hydra.create_contact_card().unwrap())
        .unwrap();
    hydra
        .rename_contact(contact.id(), "browser-contact")
        .unwrap();
    hydra
        .store_message(contact.id(), true, b"browser message".to_vec(), Vec::new())
        .unwrap();

    let encrypted = hydra.flush_encrypted_state_snapshot().unwrap();
    let text = String::from_utf8_lossy(&encrypted);
    assert!(text.starts_with("HYDRA-MSG-STATE"));
    assert!(!text.contains("browser-contact"));
    assert!(!text.contains("browser message"));

    assert!(Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-platform-snapshot-wrong-password",
        "wrong-pw",
        Some(&encrypted),
    )
    .is_err());

    let reopened = Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-platform-snapshot-restored",
        "state-pw",
        Some(&encrypted),
    )
    .unwrap();
    assert_eq!(reopened.list_ids().len(), 1);
    assert_eq!(reopened.list_contacts().len(), 1);
    assert_eq!(
        reopened.get_contact(contact.id()).unwrap().label(),
        "browser-contact"
    );
    assert_eq!(reopened.list_messages(contact.id()).len(), 1);
}

#[test]
fn persistence_parser_stress_vectors_reject_malformed_containers() {
    const BAD_STATE_MAGIC: &[u8] = include_bytes!(
        "../../../../qa/vectors/persistence/parser-stress/TV-PERSISTENCE-STATE-BAD-MAGIC/encrypted_state.bin"
    );
    const EMPTY_STATE_CIPHERTEXT: &[u8] = include_bytes!(
        "../../../../qa/vectors/persistence/parser-stress/TV-PERSISTENCE-STATE-EMPTY-CIPHERTEXT/encrypted_state.bin"
    );
    const BAD_BACKUP_KDF: &[u8] = include_bytes!(
        "../../../../qa/vectors/persistence/parser-stress/TV-PERSISTENCE-BACKUP-BAD-KDF/backup.bin"
    );
    const BAD_BACKUP_NONCE: &[u8] = include_bytes!(
        "../../../../qa/vectors/persistence/parser-stress/TV-PERSISTENCE-BACKUP-BAD-NONCE/backup.bin"
    );
    const DUPLICATE_SNAPSHOT_SCALAR: &[u8] = include_bytes!(
        "../../../../qa/vectors/persistence/parser-stress/TV-PERSISTENCE-SNAPSHOT-DUPLICATE-SCALAR/snapshot.bin"
    );

    assert!(Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-parser-stress-bad-magic",
        "state-pw",
        Some(BAD_STATE_MAGIC),
    )
    .is_err());
    assert!(Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-parser-stress-empty-ciphertext",
        "state-pw",
        Some(EMPTY_STATE_CIPHERTEXT),
    )
    .is_err());

    let verifier = fresh("target/hydra-msg-test-parser-stress-backup-verifier");
    assert!(verifier.verify_backup(BAD_BACKUP_KDF, "backup-pw").is_err());
    assert!(verifier
        .verify_backup(BAD_BACKUP_NONCE, "backup-pw")
        .is_err());
    assert!(Hydra::verify_state_snapshot(DUPLICATE_SNAPSHOT_SCALAR).is_err());
}

#[test]
fn state_snapshot_validation_rejects_duplicates_unknowns_and_collection_replays() {
    let mut hydra = fresh("target/hydra-msg-test-snapshot-parser-stress");
    let id = hydra.generate_id("id-pw").unwrap();
    hydra.set_active_id(id, "id-pw").unwrap();
    let contact = hydra
        .add_contact(hydra.create_contact_card().unwrap())
        .unwrap();
    hydra
        .store_message(contact.id(), true, b"dedupe".to_vec(), Vec::new())
        .unwrap();
    let snapshot = String::from_utf8(hydra.encode_state_snapshot().unwrap()).unwrap();

    let mut duplicate_scalar = snapshot.clone();
    duplicate_scalar.push_str("state_generation\t999\n");
    assert!(Hydra::verify_state_snapshot(duplicate_scalar.as_bytes()).is_err());

    let mut unknown_record = snapshot.clone();
    unknown_record.push_str("unknown_snapshot_record\tbad\n");
    assert!(Hydra::verify_state_snapshot(unknown_record.as_bytes()).is_err());

    let identity_line = snapshot
        .lines()
        .find(|line| line.starts_with("identity\t"))
        .expect("snapshot contains identity line");
    let mut duplicate_identity = snapshot.clone();
    duplicate_identity.push_str(identity_line);
    duplicate_identity.push('\n');
    assert!(Hydra::verify_state_snapshot(duplicate_identity.as_bytes()).is_err());

    let contact_line = snapshot
        .lines()
        .find(|line| line.starts_with("contact\t"))
        .expect("snapshot contains contact line");
    let mut duplicate_contact = snapshot.clone();
    duplicate_contact.push_str(contact_line);
    duplicate_contact.push('\n');
    assert!(Hydra::verify_state_snapshot(duplicate_contact.as_bytes()).is_err());

    let message_line = snapshot
        .lines()
        .find(|line| line.starts_with("message\t"))
        .expect("snapshot contains message line")
        .to_owned();
    let mut duplicate_message = snapshot;
    duplicate_message.push_str(&message_line);
    duplicate_message.push('\n');
    assert!(Hydra::verify_state_snapshot(duplicate_message.as_bytes()).is_err());
}

const PERSIST_EMPTY_SNAPSHOT: &[u8] =
    include_bytes!("../../../../qa/vectors/persistence/positive/TV-PERSIST-EMPTY-000/snapshot.bin");
const OLD_FORMAT_EMPTY_STATE: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/positive/TV-PERSIST-EMPTY-000/state_envelope.bin"
);
const OLD_FORMAT_EMPTY_BACKUP: &[u8] =
    include_bytes!("../../../../qa/vectors/persistence/positive/TV-PERSIST-EMPTY-000/backup.bin");
const PERSIST_FULL_SNAPSHOT: &[u8] =
    include_bytes!("../../../../qa/vectors/persistence/positive/TV-PERSIST-FULL-000/snapshot.bin");
const OLD_FORMAT_FULL_STATE: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/positive/TV-PERSIST-FULL-000/state_envelope.bin"
);
const OLD_FORMAT_FULL_BACKUP: &[u8] =
    include_bytes!("../../../../qa/vectors/persistence/positive/TV-PERSIST-FULL-000/backup.bin");
const PERSIST_WRONG_PASSWORD_STATE: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/negative/TV-PERSIST-WRONG-PASSWORD-000/state_envelope.bin"
);
const PERSIST_WRONG_PASSWORD_BACKUP: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/negative/TV-PERSIST-WRONG-PASSWORD-000/backup.bin"
);
const PERSIST_BAD_KDF_PARAMS_STATE: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/negative/TV-PERSIST-BAD-KDF-PARAMS-000/state_envelope.bin"
);
const PERSIST_CIPHERTEXT_FLIP_STATE: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/negative/TV-PERSIST-CIPHERTEXT-FLIP-000/state_envelope.bin"
);
const PERSIST_TRUNCATED_STATE: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/negative/TV-PERSIST-TRUNCATED-000/state_envelope.bin"
);
const PERSIST_BAD_SNAPSHOT_BACKUP: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/negative/TV-PERSIST-BAD-SNAPSHOT-000/backup.bin"
);
const PERSIST_STALE_GENERATION_STATE: &[u8] = include_bytes!(
    "../../../../qa/vectors/persistence/negative/TV-PERSIST-STALE-GENERATION-000/state_envelope.bin"
);

fn current_fixture(path: &str) -> Hydra {
    let mut hydra = fresh(path);
    let id = hydra.generate_id("id-pw").unwrap();
    hydra.set_active_id(id, "id-pw").unwrap();
    let contact = hydra
        .add_contact(hydra.create_contact_card().unwrap())
        .unwrap();
    hydra
        .rename_contact(contact.id(), "vector-contact")
        .unwrap();
    hydra
        .store_message(contact.id(), true, b"vector message".to_vec(), Vec::new())
        .unwrap();
    hydra
}

#[test]
fn current_persistence_vectors_use_chunked_storage_and_round_trip() {
    Hydra::verify_state_snapshot(PERSIST_EMPTY_SNAPSHOT).unwrap();
    Hydra::verify_state_snapshot(PERSIST_FULL_SNAPSHOT).unwrap();

    let mut hydra = current_fixture("target/hydra-msg-test-current-persistence-source");
    let encrypted = hydra.flush_encrypted_state_snapshot().unwrap();
    let encrypted_text = String::from_utf8_lossy(&encrypted);
    assert!(encrypted_text.contains("format_version\t1"));
    assert!(encrypted_text.contains("chunk_size\t65536"));
    assert!(encrypted_text.contains("chunk_count\t"));
    assert!(!encrypted_text.contains("vector-contact"));
    assert!(!encrypted_text.contains("vector message"));

    let reopened = Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-current-persistence-state-open",
        "state-pw",
        Some(&encrypted),
    )
    .unwrap();
    assert_eq!(reopened.list_ids().len(), 1);
    assert_eq!(reopened.list_contacts().len(), 1);
    let contact_id = reopened.list_contacts()[0].id();
    assert_eq!(
        reopened.get_contact(contact_id).unwrap().label(),
        "vector-contact"
    );
    let messages = reopened.list_messages(contact_id);
    assert_eq!(messages.len(), 1);
    assert_eq!(
        reopened.get_message(messages[0]).unwrap().text().unwrap(),
        "vector message"
    );

    let backup = hydra.export_backup("backup-pw").unwrap();
    let backup_text = String::from_utf8_lossy(&backup);
    assert!(backup_text.contains("format_version\t1"));
    assert!(backup_text.contains("chunk_size\t65536"));
    assert!(backup_text.contains("chunk_count\t"));
    assert!(!backup_text.contains("vector-contact"));
    assert!(!backup_text.contains("vector message"));
    hydra.verify_backup(&backup, "backup-pw").unwrap();

    let mut imported = fresh("target/hydra-msg-test-current-persistence-backup-import");
    imported.import_backup(&backup, "backup-pw").unwrap();
    assert_eq!(imported.list_ids().len(), 1);
    assert_eq!(imported.list_contacts().len(), 1);
}

#[test]
fn old_format_persistence_envelopes_fail_closed() {
    for (path, bytes) in [
        (
            "target/hydra-msg-test-old-format-empty-state",
            OLD_FORMAT_EMPTY_STATE,
        ),
        (
            "target/hydra-msg-test-old-format-full-state",
            OLD_FORMAT_FULL_STATE,
        ),
    ] {
        assert!(Hydra::open_with_encrypted_state_snapshot(path, "state-pw", Some(bytes)).is_err());
    }

    let verifier = fresh("target/hydra-msg-test-old-format-backup-verifier");
    assert!(verifier
        .verify_backup(OLD_FORMAT_EMPTY_BACKUP, "backup-pw")
        .is_err());
    assert!(verifier
        .verify_backup(OLD_FORMAT_FULL_BACKUP, "backup-pw")
        .is_err());
}

#[test]
fn frozen_persistence_negative_vectors_fail_closed() {
    assert!(Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-vector-wrong-state-password",
        "wrong-pw",
        Some(PERSIST_WRONG_PASSWORD_STATE),
    )
    .is_err());

    let verifier = fresh("target/hydra-msg-test-vector-negative-verifier");
    assert!(verifier
        .verify_backup(PERSIST_WRONG_PASSWORD_BACKUP, "wrong-pw")
        .is_err());
    assert!(Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-vector-bad-kdf-params",
        "state-pw",
        Some(PERSIST_BAD_KDF_PARAMS_STATE),
    )
    .is_err());
    assert!(Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-vector-ciphertext-flip",
        "state-pw",
        Some(PERSIST_CIPHERTEXT_FLIP_STATE),
    )
    .is_err());
    assert!(Hydra::open_with_encrypted_state_snapshot(
        "target/hydra-msg-test-vector-truncated-state",
        "state-pw",
        Some(PERSIST_TRUNCATED_STATE),
    )
    .is_err());
    assert!(verifier
        .verify_backup(PERSIST_BAD_SNAPSHOT_BACKUP, "backup-pw")
        .is_err());
}

#[test]
fn frozen_persistence_stale_generation_and_restore_floor_vectors_hold() {
    let stale_path = "target/hydra-msg-test-vector-stale-generation";
    let _ = fs::remove_dir_all(stale_path);
    fs::create_dir_all(stale_path).unwrap();
    fs::write(
        format!("{stale_path}/state.hydra"),
        PERSIST_STALE_GENERATION_STATE,
    )
    .unwrap();
    fs::write(format!("{stale_path}/state.hydra.rollback"), b"2\n").unwrap();
    assert!(Hydra::open(stale_path, "state-pw").is_err());

    let target_path = "target/hydra-msg-test-vector-restore-generation-floor";
    let mut target = fresh(target_path);
    for _ in 0..3 {
        target.generate_id("target-pw").unwrap();
        target.persist().unwrap();
    }
    let previous_generation = target.storage_debug_status().state_generation;
    assert!(previous_generation > 1);

    let source = current_fixture("target/hydra-msg-test-vector-current-backup-source");
    let backup = source.export_backup("backup-pw").unwrap();
    target.import_backup(&backup, "backup-pw").unwrap();
    assert!(target.storage_debug_status().state_generation > previous_generation);
}
