use super::*;
use std::fs;
use std::path::Path;

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn make_persisted_state(path: &str) -> (IdentityId, ContactId, MessageId, LobbyId) {
    let mut hydra = fresh(path);
    let id = hydra.generate_id("state-pw").unwrap();
    hydra.set_active_id(id, "state-pw").unwrap();
    let card = hydra.create_contact_card().unwrap();
    let contact = hydra.add_contact(card).unwrap();
    hydra.rename_contact(contact.id(), "self-contact").unwrap();
    let message_id = hydra.store_message(
        contact.id(),
        true,
        b"persisted".to_vec(),
        vec![
            HydraAttachment::from_named_bytes("persisted.bin", b"bytes".to_vec()).unwrap(),
        ],
    );
    let lobby = hydra
        .create_lobby(HydraLobbyPolicy::new("persisted lobby", 3))
        .unwrap();
    hydra.add_lobby_member(lobby.id(), contact.id()).unwrap();
    hydra.persist().unwrap();
    (id, contact.id(), message_id, lobby.id())
}

#[test]
fn encrypted_state_persists_without_plaintext_leakage() {
    let path = "target/hydra-msg-test-encrypted-persistence";
    let (id, contact_id, message_id, lobby_id) = make_persisted_state(path);
    let state = fs::read(Path::new(path).join("state.hydra")).unwrap();
    let text = String::from_utf8_lossy(&state);
    assert!(text.starts_with("HYDRA-MSG-STATE"));
    assert!(!text.contains("persisted"));
    assert!(!text.contains("self-contact"));
    assert!(!text.contains("persisted.bin"));

    let mut reopened = Hydra::open(path, "state-pw").unwrap();
    assert_eq!(reopened.list_ids().len(), 1);
    assert_eq!(reopened.active_id(), None);
    assert!(!reopened.get_id(id).unwrap().unlocked());
    reopened.set_active_id(id, "state-pw").unwrap();
    assert_eq!(reopened.list_contacts().len(), 1);
    assert_eq!(
        reopened.get_contact(contact_id).unwrap().label(),
        "self-contact"
    );
    let message = reopened.get_message(message_id).unwrap();
    assert_eq!(message.text().unwrap(), "persisted");
    assert_eq!(message.attachments()[0].filename(), "persisted.bin");
    assert_eq!(reopened.get_lobby(lobby_id).unwrap().id(), lobby_id);
    assert!(reopened.storage_status().encrypted_state);
}

#[test]
fn encrypted_state_rejects_wrong_password_corruption_and_truncation() {
    let path = "target/hydra-msg-test-encrypted-state-failures";
    make_persisted_state(path);
    assert!(Hydra::open(path, "wrong-pw").is_err());

    let state_path = Path::new(path).join("state.hydra");
    let original = fs::read(&state_path).unwrap();

    let mut corrupted = original.clone();
    let last = corrupted.len() - 2;
    corrupted[last] ^= 1;
    fs::write(&state_path, corrupted).unwrap();
    assert!(Hydra::open(path, "state-pw").is_err());

    fs::write(&state_path, &original[..original.len() / 2]).unwrap();
    assert!(Hydra::open(path, "state-pw").is_err());

    fs::write(&state_path, original).unwrap();
    assert!(Hydra::open(path, "state-pw").is_ok());
}

#[test]
fn encrypted_state_detects_local_replay_after_newer_commit() {
    let path = "target/hydra-msg-test-encrypted-state-replay";
    let (_, contact_id, _, _) = make_persisted_state(path);
    let state_path = Path::new(path).join("state.hydra");
    let old_state = fs::read(&state_path).unwrap();

    let mut hydra = Hydra::open(path, "state-pw").unwrap();
    hydra.store_message(contact_id, true, b"newer".to_vec(), Vec::new());
    hydra.persist().unwrap();
    assert!(Hydra::open(path, "state-pw").is_ok());

    fs::write(&state_path, old_state).unwrap();
    assert!(Hydra::open(path, "state-pw").is_err());
}

#[test]
fn encrypted_backup_requires_password_and_restores_state() {
    let mut hydra = fresh("target/hydra-msg-test-backup-source");
    let id = hydra.generate_id("id-pw").unwrap();
    hydra.set_active_id(id, "id-pw").unwrap();
    let contact = hydra
        .add_contact(hydra.create_contact_card().unwrap())
        .unwrap();
    hydra.store_message(
        contact.id(),
        true,
        b"backup-message".to_vec(),
        Vec::new(),
    );
    hydra.persist().unwrap();
    let backup = hydra.export_backup("backup-pw").unwrap();
    hydra.verify_backup(&backup).unwrap();

    let mut restored = fresh("target/hydra-msg-test-backup-restored");
    assert!(restored.import_backup(&backup, "wrong-pw").is_err());
    restored.import_backup(&backup, "backup-pw").unwrap();
    assert_eq!(restored.list_ids().len(), 1);
    assert_eq!(restored.list_contacts().len(), 1);
    assert_eq!(restored.list_messages(contact.id()).len(), 1);
    restored.set_active_id(id, "id-pw").unwrap();
}

#[test]
fn password_kdf_uses_random_salts_for_same_password() {
    let path_a = "target/hydra-msg-test-kdf-salt-a";
    let path_b = "target/hydra-msg-test-kdf-salt-b";
    let _ = fs::remove_dir_all(path_a);
    let _ = fs::remove_dir_all(path_b);

    let mut a = Hydra::open(path_a, "same-state-password").unwrap();
    let mut b = Hydra::open(path_b, "same-state-password").unwrap();
    let a_id = a.generate_id("same-id-password").unwrap();
    let b_id = b.generate_id("same-id-password").unwrap();
    a.persist().unwrap();
    b.persist().unwrap();

    assert_eq!(a.state_kdf.profile, "interactive");
    assert_eq!(b.state_kdf.profile, "interactive");
    assert_ne!(a.state_kdf.salt, b.state_kdf.salt);

    let a_record = a.identities.get(&a_id).unwrap();
    let b_record = b.identities.get(&b_id).unwrap();
    assert_eq!(a_record.password_kdf.profile, "interactive");
    assert_eq!(b_record.password_kdf.profile, "interactive");
    assert_ne!(a_record.password_kdf.salt, b_record.password_kdf.salt);
    assert_ne!(a_record.password_tag, b_record.password_tag);
}

#[test]
fn encrypted_state_and_backup_store_memory_hard_kdf_parameters() {
    let path = "target/hydra-msg-test-kdf-headers";
    let mut hydra = fresh(path);
    hydra.generate_id("id-pw").unwrap();
    hydra.persist().unwrap();

    let state = fs::read(Path::new(path).join("state.hydra")).unwrap();
    let text = String::from_utf8_lossy(&state);
    assert!(text.contains("kdf\tscrypt"));
    assert!(text.contains("kdf_profile\tinteractive"));
    assert!(text.contains("kdf_log_n\t14"));
    assert!(text.contains("kdf_r\t8"));
    assert!(text.contains("kdf_p\t1"));
    assert!(text.contains("kdf_salt\t"));

    let backup = hydra.export_backup("backup-pw").unwrap();
    let backup_text = String::from_utf8_lossy(&backup);
    assert!(backup_text.contains("kdf\tscrypt"));
    assert!(backup_text.contains("kdf_profile\tinteractive"));
    assert!(backup_text.contains("kdf_salt\t"));
}

#[test]
fn changed_kdf_parameters_are_rejected() {
    let path = "target/hydra-msg-test-kdf-parameter-change";
    make_persisted_state(path);
    let state_path = Path::new(path).join("state.hydra");
    let mut text = fs::read_to_string(&state_path).unwrap();
    text = text.replace("kdf_log_n\t14", "kdf_log_n\t15");
    fs::write(&state_path, text).unwrap();
    assert!(Hydra::open(path, "state-pw").is_err());
}
