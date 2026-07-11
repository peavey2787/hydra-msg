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

fn connected(prefix: &str) -> (Hydra, Hydra, ContactId, ContactId, IdentityId, IdentityId) {
    let (mut alice, alice_id) = unlocked(&format!("target/{prefix}-alice"));
    let (mut bob, bob_id) = unlocked(&format!("target/{prefix}-bob"));
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
    (
        alice,
        bob,
        alice_contact.id(),
        bob_contact.id(),
        alice_id,
        bob_id,
    )
}

fn joined_lobby(prefix: &str) -> (Hydra, Hydra, ContactId, ContactId, LobbyId) {
    let (mut alice, mut bob, alice_contact, bob_contact, _, _) = connected(prefix);
    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("edge-lobby", 8))
        .unwrap();
    alice.add_lobby_member(lobby.id(), bob_contact).unwrap();
    let invite = alice.create_lobby_member_invite(lobby.id()).unwrap();
    let joined = bob.join_lobby(invite).unwrap();
    assert_eq!(joined.id(), lobby.id());
    assert!(bob
        .lobby_members(lobby.id())
        .unwrap()
        .contains(&alice_contact));
    (alice, bob, alice_contact, bob_contact, lobby.id())
}

#[test]
fn blocked_contact_cannot_complete_handshake_or_deliver_packet() {
    let (mut alice, mut bob, alice_contact, bob_contact, _, _) =
        connected("hydra-msg-test-edge-blocked");
    let packet = alice
        .send(bob_contact, HydraMessage::text("blocked packet"))
        .unwrap()
        .remove(0);

    bob.block_contact(alice_contact).unwrap();
    assert!(bob.receive(packet).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());

    let offer = alice.init_handshake(bob_contact).unwrap();
    assert!(bob.reply_handshake(offer).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());
}

#[test]
fn deleted_contact_drops_pending_fragments_and_rejects_old_packets() {
    let (mut alice, mut bob, alice_contact, bob_contact, _, _) =
        connected("hydra-msg-test-edge-deleted-contact");
    alice
        .set_packet_size(hydra_core::STANDARD_ENVELOPE_SIZE)
        .unwrap();
    bob.set_packet_size(hydra_core::STANDARD_ENVELOPE_SIZE)
        .unwrap();
    let packets = alice
        .send(
            bob_contact,
            HydraMessage::bytes(vec![b'x'; hydra_core::STANDARD_MAX_CONTENT_SIZE + 1]),
        )
        .unwrap();
    assert!(packets.len() > 1);
    assert!(bob.receive(packets[0].clone()).unwrap().is_none());
    assert_eq!(bob.pending_fragments.len(), 1);

    bob.remove_contact(alice_contact).unwrap();
    assert!(bob.pending_fragments.is_empty());
    assert!(bob.receive(packets[1].clone()).is_err());
}

#[test]
fn deleted_or_locked_active_identity_cannot_send_and_delete_clears_active_id() {
    let (mut alice, bob, _alice_contact, bob_contact, alice_id, _) =
        connected("hydra-msg-test-edge-deleted-identity");
    alice.lock_active_id().unwrap();
    assert_eq!(alice.active_id(), None);
    assert!(alice
        .send(bob_contact, HydraMessage::text("locked send"))
        .is_err());

    alice.set_active_id(alice_id, "pw").unwrap();
    alice.delete_id(alice_id, "pw").unwrap();
    assert_eq!(alice.active_id(), None);
    assert!(alice
        .send(bob_contact, HydraMessage::text("deleted send"))
        .is_err());
    assert!(bob.list_messages(_alice_contact).is_empty());
}

#[test]
fn closed_session_and_removed_contact_reject_old_packets() {
    let (mut alice, mut bob, alice_contact, bob_contact, _, _) =
        connected("hydra-msg-test-edge-closed-session");
    let packet = alice
        .send(bob_contact, HydraMessage::text("after close"))
        .unwrap()
        .remove(0);
    bob.close_session(alice_contact).unwrap();
    assert!(bob.receive(packet.clone()).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());

    bob.remove_contact(alice_contact).unwrap();
    assert!(bob.receive(packet).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());
}

#[test]
fn closed_lobby_removed_member_and_stale_member_state_reject_old_lobby_packets() {
    let (mut alice, mut bob, alice_contact, bob_contact, lobby_id) =
        joined_lobby("hydra-msg-test-edge-lobby");
    let packet_for_bob = alice
        .send_lobby(lobby_id, HydraMessage::text("old lobby packet"))
        .unwrap()
        .into_iter()
        .find(|copy| copy.recipient() == bob_contact)
        .unwrap()
        .into_envelope();

    bob.close_lobby(lobby_id).unwrap();
    assert!(bob.receive_lobby(packet_for_bob.clone()).is_err());
    assert!(bob.list_messages(alice_contact).is_empty());

    let (mut alice2, mut bob2, alice_contact2, bob_contact2, lobby_id2) =
        joined_lobby("hydra-msg-test-edge-lobby-removed-local");
    let removed_member_packet = alice2
        .send_lobby(lobby_id2, HydraMessage::text("removed local member"))
        .unwrap()
        .into_iter()
        .find(|copy| copy.recipient() == bob_contact2)
        .unwrap()
        .into_envelope();
    bob2.remove_lobby_member(lobby_id2, alice_contact2).unwrap();
    assert!(bob2.receive_lobby(removed_member_packet).is_err());

    let (mut alice3, mut bob3, alice_contact3, bob_contact3, lobby_id3) =
        joined_lobby("hydra-msg-test-edge-lobby-stale-state");
    alice3.remove_lobby_member(lobby_id3, bob_contact3).unwrap();
    let stale_packet_for_alice = bob3
        .send_lobby(lobby_id3, HydraMessage::text("stale member state"))
        .unwrap()
        .into_iter()
        .find(|copy| copy.recipient() == alice_contact3)
        .unwrap()
        .into_envelope();
    assert!(alice3.receive_lobby(stale_packet_for_alice).is_err());
    assert!(alice3.list_messages(bob_contact3).is_empty());
}
