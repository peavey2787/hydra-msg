#![cfg(not(target_arch = "wasm32"))]

use super::*;
use crate::persistence::native_store::{set_test_failpoint, NativeStateStore};
use std::{fs, path::Path};

const STATE_PW: &str = "state-pw";
const ID_PW: &str = "id-pw";
const BACKUP_PW: &str = "backup-pw";

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, STATE_PW).unwrap()
}

fn state_path(path: &str) -> std::path::PathBuf {
    Path::new(path).join("state.hydra")
}

fn state_temp_path(path: &str) -> std::path::PathBuf {
    Path::new(path).join("state.hydra.tmp")
}

fn rollback_path(path: &str) -> std::path::PathBuf {
    Path::new(path).join("state.hydra.rollback")
}

fn rollback_generation(path: &str) -> u64 {
    fs::read_to_string(rollback_path(path))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn clear_failpoint() {
    set_test_failpoint(None);
}

fn inject_state_failure(stage: &'static str) {
    set_test_failpoint(Some(("state.hydra", stage)));
}

fn inject_rollback_failure(stage: &'static str) {
    set_test_failpoint(Some(("state.hydra.rollback", stage)));
}

fn make_state_with_contact_and_message(path: &str) -> (IdentityId, ContactId, MessageId) {
    let mut hydra = fresh(path);
    let id = hydra.generate_id(ID_PW).unwrap();
    hydra.set_active_id(id, ID_PW).unwrap();
    let contact = hydra
        .add_contact(hydra.create_contact_card().unwrap())
        .unwrap();
    hydra.rename_contact(contact.id(), "crash-contact").unwrap();
    let message = hydra
        .store_message(contact.id(), true, b"crash-message".to_vec(), Vec::new())
        .unwrap();
    hydra.persist().unwrap();
    (id, contact.id(), message)
}

#[test]
fn crash_before_state_rename_leaves_old_state_authoritative() {
    let path = "target/hydra-msg-test-crash-before-state-rename";
    let (_, contact_id, _) = make_state_with_contact_and_message(path);
    let old_state = fs::read(state_path(path)).unwrap();
    let old_generation = rollback_generation(path);
    let store = NativeStateStore::new(Path::new(path).to_path_buf());

    for stage in ["write temp file", "sync temp file", "rename/replace state"] {
        inject_state_failure(stage);
        assert!(store.write_encrypted_snapshot(&old_state).is_err());
        clear_failpoint();

        let reopened = Hydra::open(path, STATE_PW).unwrap();
        assert_eq!(
            reopened.storage_debug_status().state_generation,
            old_generation
        );
        assert_eq!(reopened.list_messages(contact_id).len(), 1);
    }
}

#[test]
fn crash_temp_file_is_ignored_and_removed_on_next_successful_write() {
    let path = "target/hydra-msg-test-crash-temp-ignored";
    let (_, contact_id, _) = make_state_with_contact_and_message(path);
    let alternate_path = "target/hydra-msg-test-crash-temp-alternate";
    let mut alternate = fresh(alternate_path);
    alternate.generate_id("alternate-pw").unwrap();
    let alternate_state = fs::read(state_path(alternate_path)).unwrap();

    fs::write(state_temp_path(path), alternate_state).unwrap();
    let mut reopened = Hydra::open(path, STATE_PW).unwrap();
    assert_eq!(reopened.list_messages(contact_id).len(), 1);
    assert!(state_temp_path(path).exists());

    reopened
        .rename_contact(contact_id, "after-temp-cleanup")
        .unwrap();
    assert!(!state_temp_path(path).exists());
    drop(reopened);
    let reopened = Hydra::open(path, STATE_PW).unwrap();
    assert_eq!(
        reopened.get_contact(contact_id).unwrap().label(),
        "after-temp-cleanup"
    );
}

#[test]
fn renamed_state_before_parent_sync_or_rollback_is_openable_and_repairs_guard() {
    let path = "target/hydra-msg-test-crash-after-state-rename";
    make_state_with_contact_and_message(path);
    let mut hydra = Hydra::open(path, STATE_PW).unwrap();
    let encrypted = hydra.flush_encrypted_state_snapshot().unwrap();
    let new_generation = hydra.storage_debug_status().state_generation;
    assert!(new_generation > rollback_generation(path));

    fs::write(state_path(path), encrypted).unwrap();
    fs::write(rollback_path(path), b"0\n").unwrap();
    drop(hydra);

    let reopened = Hydra::open(path, STATE_PW).unwrap();
    assert_eq!(
        reopened.storage_debug_status().state_generation,
        new_generation
    );
    assert_eq!(rollback_generation(path), new_generation);
}

#[test]
fn parent_dir_sync_failure_returns_error_but_leaves_openable_state() {
    let path = "target/hydra-msg-test-parent-sync-failure";
    make_state_with_contact_and_message(path);
    let mut hydra = Hydra::open(path, STATE_PW).unwrap();
    let encrypted = hydra.flush_encrypted_state_snapshot().unwrap();
    let new_generation = hydra.storage_debug_status().state_generation;
    let store = NativeStateStore::new(Path::new(path).to_path_buf());

    inject_state_failure("sync parent dir");
    assert!(store.write_encrypted_snapshot(&encrypted).is_err());
    clear_failpoint();
    drop(hydra);

    let reopened = Hydra::open(path, STATE_PW).unwrap();
    assert_eq!(
        reopened.storage_debug_status().state_generation,
        new_generation
    );
}

#[test]
fn rollback_evidence_write_failure_leaves_state_openable_and_repairable() {
    let path = "target/hydra-msg-test-rollback-evidence-failure";
    make_state_with_contact_and_message(path);
    let mut hydra = Hydra::open(path, STATE_PW).unwrap();
    let encrypted = hydra.flush_encrypted_state_snapshot().unwrap();
    let new_generation = hydra.storage_debug_status().state_generation;
    let store = NativeStateStore::new(Path::new(path).to_path_buf());
    store.write_encrypted_snapshot(&encrypted).unwrap();

    inject_rollback_failure("write temp file");
    assert!(store.write_rollback_guard(new_generation).is_err());
    clear_failpoint();
    drop(hydra);

    let reopened = Hydra::open(path, STATE_PW).unwrap();
    assert_eq!(
        reopened.storage_debug_status().state_generation,
        new_generation
    );
    assert_eq!(rollback_generation(path), new_generation);
}

#[test]
fn backup_import_failure_is_atomic_in_memory_and_on_disk() {
    let source_path = "target/hydra-msg-test-crash-backup-source";
    let mut source = fresh(source_path);
    source.generate_id("source-pw").unwrap();
    let backup = source.export_backup(BACKUP_PW).unwrap();

    let target_path = "target/hydra-msg-test-crash-backup-target";
    let (original_id, _, _) = make_state_with_contact_and_message(target_path);
    let mut target = Hydra::open(target_path, STATE_PW).unwrap();
    let original_generation = target.storage_debug_status().state_generation;

    inject_state_failure("write temp file");
    assert!(target.import_backup(&backup, BACKUP_PW).is_err());
    clear_failpoint();

    assert_eq!(
        target.storage_debug_status().state_generation,
        original_generation
    );
    assert!(target.get_id(original_id).is_ok());
    drop(target);
    let reopened = Hydra::open(target_path, STATE_PW).unwrap();
    assert!(reopened.get_id(original_id).is_ok());
}

#[test]
fn delete_identity_failure_restores_memory_and_disk() {
    let path = "target/hydra-msg-test-crash-delete-identity";
    let (identity_id, _, _) = make_state_with_contact_and_message(path);
    let mut hydra = Hydra::open(path, STATE_PW).unwrap();
    let generation = hydra.storage_debug_status().state_generation;

    inject_state_failure("write temp file");
    assert!(hydra.delete_id(identity_id, ID_PW).is_err());
    clear_failpoint();

    assert_eq!(hydra.storage_debug_status().state_generation, generation);
    assert!(hydra.get_id(identity_id).is_ok());
    drop(hydra);
    assert!(Hydra::open(path, STATE_PW)
        .unwrap()
        .get_id(identity_id)
        .is_ok());
}

#[test]
fn delete_contact_failure_restores_memory_and_disk() {
    let path = "target/hydra-msg-test-crash-delete-contact";
    let (_, contact_id, _) = make_state_with_contact_and_message(path);
    let mut hydra = Hydra::open(path, STATE_PW).unwrap();
    let generation = hydra.storage_debug_status().state_generation;

    inject_state_failure("write temp file");
    assert!(hydra.remove_contact(contact_id).is_err());
    clear_failpoint();

    assert_eq!(hydra.storage_debug_status().state_generation, generation);
    assert!(hydra.get_contact(contact_id).is_ok());
    drop(hydra);
    assert!(Hydra::open(path, STATE_PW)
        .unwrap()
        .get_contact(contact_id)
        .is_ok());
}

#[test]
fn delete_message_failure_restores_memory_and_disk() {
    let path = "target/hydra-msg-test-crash-delete-message";
    let (_, contact_id, message_id) = make_state_with_contact_and_message(path);
    let mut hydra = Hydra::open(path, STATE_PW).unwrap();
    let generation = hydra.storage_debug_status().state_generation;

    inject_state_failure("write temp file");
    assert!(hydra.delete_message(message_id).is_err());
    clear_failpoint();

    assert_eq!(hydra.storage_debug_status().state_generation, generation);
    assert!(hydra.get_message(message_id).is_ok());
    assert_eq!(hydra.list_messages(contact_id).len(), 1);
    drop(hydra);
    let reopened = Hydra::open(path, STATE_PW).unwrap();
    assert!(reopened.get_message(message_id).is_ok());
    assert_eq!(reopened.list_messages(contact_id).len(), 1);
}
