use super::*;
use std::fs;
use std::path::Path;

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path).unwrap()
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
    let state = fs::read(Path::new(path).join("state-v2.hydra")).unwrap();
    let text = String::from_utf8_lossy(&state);
    assert!(text.starts_with("HYDRA-MSG-STATE-V2"));
    assert!(!text.contains("persisted"));
    assert!(!text.contains("self-contact"));
    assert!(!text.contains("persisted.bin"));
    assert!(!Path::new(path).join("state-v1.hydra").exists());
    assert!(Hydra::open(path).is_err());

    let mut reopened = Hydra::open_with_state_password(path, "state-pw").unwrap();
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
    assert!(Hydra::open_with_state_password(path, "wrong-pw").is_err());

    let state_path = Path::new(path).join("state-v2.hydra");
    let original = fs::read(&state_path).unwrap();

    let mut corrupted = original.clone();
    let last = corrupted.len() - 2;
    corrupted[last] ^= 1;
    fs::write(&state_path, corrupted).unwrap();
    assert!(Hydra::open_with_state_password(path, "state-pw").is_err());

    fs::write(&state_path, &original[..original.len() / 2]).unwrap();
    assert!(Hydra::open_with_state_password(path, "state-pw").is_err());

    fs::write(&state_path, original).unwrap();
    assert!(Hydra::open_with_state_password(path, "state-pw").is_ok());
}

#[test]
fn encrypted_state_detects_local_replay_after_newer_commit() {
    let path = "target/hydra-msg-test-encrypted-state-replay";
    let (_, contact_id, _, _) = make_persisted_state(path);
    let state_path = Path::new(path).join("state-v2.hydra");
    let old_state = fs::read(&state_path).unwrap();

    let mut hydra = Hydra::open_with_state_password(path, "state-pw").unwrap();
    hydra.store_message(contact_id, true, b"newer".to_vec(), Vec::new());
    hydra.persist().unwrap();
    assert!(Hydra::open_with_state_password(path, "state-pw").is_ok());

    fs::write(&state_path, old_state).unwrap();
    assert!(Hydra::open_with_state_password(path, "state-pw").is_err());
}

#[test]
fn legacy_plaintext_state_migrates_to_encrypted_state_after_password_open() {
    let path = "target/hydra-msg-test-legacy-state-migration";
    let _ = fs::remove_dir_all(path);
    fs::create_dir_all(path).unwrap();
    fs::write(
        Path::new(path).join("state-v1.hydra"),
        b"HYDRA-MSG-STATE-V1\nnext_message_id\t7\n",
    )
    .unwrap();

    let hydra = Hydra::open_with_state_password(path, "state-pw").unwrap();
    assert_eq!(hydra.storage_status().state_generation, 1);
    assert!(!Path::new(path).join("state-v1.hydra").exists());
    assert!(Path::new(path).join("state-v2.hydra").exists());
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
