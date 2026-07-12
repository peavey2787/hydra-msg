use super::*;
use std::fs;

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn unlocked(path: &str) -> (Hydra, IdentityId) {
    let mut hydra = fresh(path);
    let id = hydra.generate_id("pw").unwrap();
    hydra.set_active_id(id, "pw").unwrap();
    (hydra, id)
}

fn connected(prefix: &str) -> (Hydra, Hydra, ContactId, ContactId, IdentityId) {
    let (mut alice, alice_id) = unlocked(&format!("target/{prefix}-alice"));
    let (mut bob, _bob_id) = unlocked(&format!("target/{prefix}-bob"));
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
    (alice, bob, alice_contact.id(), bob_contact.id(), alice_id)
}

#[test]
fn send_requires_active_unlocked_identity_and_established_session() {
    let (mut alice, _alice_id) = unlocked("target/hydra-msg-test-api-misuse-no-session-alice");
    let (bob, _bob_id) = unlocked("target/hydra-msg-test-api-misuse-no-session-bob");
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    assert!(alice
        .send(bob_contact.id(), HydraMessage::text("before handshake"))
        .is_err());

    let (mut connected_alice, _connected_bob, _alice_contact, bob_contact, _alice_id) =
        connected("hydra-msg-test-api-misuse-locked-send");
    connected_alice.lock_active_id().unwrap();
    assert!(connected_alice
        .send(bob_contact, HydraMessage::text("locked"))
        .is_err());
}

#[test]
fn handshake_and_session_misuse_fails_closed() {
    let (mut alice, mut bob, _alice_contact, bob_contact, _alice_id) =
        connected("hydra-msg-test-api-misuse-handshake");
    assert!(bob.reply_handshake(b"not a real offer").is_err());
    assert!(alice
        .begin_session_refresh(ContactId::from_bytes([9; hydra_core::HASH_SIZE]))
        .is_err());
    assert!(alice
        .close_session(ContactId::from_bytes([8; hydra_core::HASH_SIZE]))
        .is_err());

    let offer = alice.init_handshake(bob_contact).unwrap();
    let answer = bob.reply_handshake(offer).unwrap();
    alice.finish_handshake(answer.clone()).unwrap();
    assert!(alice.finish_handshake(answer).is_err());
}

#[test]
fn delete_active_identity_and_wrong_password_rotation_fail_closed() {
    let (mut alice, _bob, _alice_contact, bob_contact, alice_id) =
        connected("hydra-msg-test-api-misuse-delete-active");
    assert!(alice.change_id_password(alice_id, "wrong", "new").is_err());
    assert!(alice.change_state_password("wrong", "new-state").is_err());
    assert_eq!(alice.active_id(), Some(alice_id));

    alice.delete_id(alice_id, "pw").unwrap();
    assert_eq!(alice.active_id(), None);
    assert!(alice
        .send(bob_contact, HydraMessage::text("deleted active"))
        .is_err());
}

#[test]
fn preview_apis_do_not_mutate_state_and_status_redaction_is_enforced() {
    let (mut alice, _alice_id) = unlocked("target/hydra-msg-test-api-misuse-preview-alice");
    let (bob, _bob_id) = unlocked("target/hydra-msg-test-api-misuse-preview-bob");
    let card = bob.create_labeled_contact_card("Bob Preview").unwrap();
    let preview = alice.preview_contact_card(&card).unwrap();
    assert_eq!(preview.label(), "Bob Preview");
    assert!(alice.list_contacts().is_empty());

    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("Preview Lobby", 4))
        .unwrap();
    let before_lobbies = alice.list_lobbies().len();
    let invite = alice.create_labeled_lobby_invite(lobby.id()).unwrap();
    let preview_lobby = bob.preview_lobby_invite(invite).unwrap();
    assert_eq!(preview_lobby.policy().label, "Preview Lobby");
    assert!(bob.list_lobbies().is_empty());
    assert_eq!(alice.list_lobbies().len(), before_lobbies);

    let status = format!("{:?}", alice.storage_status());
    assert!(!status.contains("identity_count"));
    assert!(!status.contains("message_count"));
    assert!(!status.contains("state_generation"));

    let debug_status = format!("{:?}", alice.storage_debug_status());
    assert!(debug_status.contains("identity_count"));
    assert!(debug_status.contains("message_count"));
    assert!(debug_status.contains("state_generation"));
}
