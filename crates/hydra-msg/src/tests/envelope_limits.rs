use super::*;

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn connected_pair(suffix: &str) -> (Hydra, Hydra, ContactId, ContactId) {
    let alice_path = format!("target/hydra-msg-test-envelope-limit-{suffix}-alice");
    let bob_path = format!("target/hydra-msg-test-envelope-limit-{suffix}-bob");
    let mut alice = fresh(&alice_path);
    let mut bob = fresh(&bob_path);
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
fn packet_size_56kb_prevents_oversized_app_packets() {
    let (mut alice, mut bob, alice_contact, bob_contact) = connected_pair("packet-56k");
    alice.set_packet_size(56 * 1024).unwrap();
    bob.set_packet_size(56 * 1024).unwrap();

    let standard_text = "x".repeat(hydra_core::LITE_MAX_CONTENT_SIZE + 1024);
    let packets = alice
        .send(bob_contact, HydraMessage::text(&standard_text))
        .unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(
        packets[0].as_bytes().len(),
        hydra_core::STANDARD_ENVELOPE_SIZE
    );
    assert!(packets
        .iter()
        .all(|packet| packet.as_bytes().len() <= 56 * 1024));

    let received = bob.receive(packets[0].clone()).unwrap().unwrap();
    assert_eq!(received.from(), alice_contact);
    assert_eq!(received.text().unwrap(), standard_text);

    let too_large_for_standard = "x".repeat(hydra_core::STANDARD_MAX_CONTENT_SIZE + 1);
    let packets = alice
        .send(bob_contact, HydraMessage::text(&too_large_for_standard))
        .unwrap();
    assert!(packets.len() > 1);
    assert!(packets
        .iter()
        .all(|packet| packet.as_bytes().len() <= 56 * 1024));

    let mut completed = None;
    for packet in packets {
        completed = bob.receive(packet).unwrap().or(completed);
    }
    assert_eq!(completed.unwrap().text().unwrap(), too_large_for_standard);
}

#[test]
fn packet_size_forces_stable_padding_class() {
    let (mut alice, mut bob, alice_contact, bob_contact) = connected_pair("packet-standard");
    alice
        .set_packet_size(hydra_core::STANDARD_ENVELOPE_SIZE)
        .unwrap();
    bob.set_packet_size(hydra_core::STANDARD_ENVELOPE_SIZE)
        .unwrap();

    let packets = alice.send(bob_contact, HydraMessage::text("hi")).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(
        packets[0].as_bytes().len(),
        hydra_core::STANDARD_ENVELOPE_SIZE
    );

    let received = bob.receive(packets[0].clone()).unwrap().unwrap();
    assert_eq!(received.from(), alice_contact);
    assert_eq!(received.text().unwrap(), "hi");
}

#[test]
fn packet_size_rejects_values_smaller_than_lite() {
    let mut hydra = fresh("target/hydra-msg-test-envelope-limit-small");
    assert!(hydra
        .set_packet_size(hydra_core::LITE_ENVELOPE_SIZE - 1)
        .is_err());
}

#[test]
fn lobby_send_respects_small_transport_limit() {
    let (mut alice, mut bob, alice_contact, bob_contact) = connected_pair("lobby-packet-56k");

    let lobby = alice
        .create_lobby(HydraLobbyPolicy::new("small carrier lobby", 4))
        .unwrap();
    alice.add_lobby_member(lobby.id(), bob_contact).unwrap();
    let invite = alice.create_lobby_invite(lobby.id()).unwrap();
    let joined = bob.join_lobby(invite).unwrap();
    bob.add_lobby_member(joined.id(), alice_contact).unwrap();

    alice.set_packet_size(56 * 1024).unwrap();
    bob.set_packet_size(56 * 1024).unwrap();
    let large_text = "l".repeat(hydra_core::STANDARD_MAX_CONTENT_SIZE + 1024);
    let outbound = alice
        .send_lobby(lobby.id(), HydraMessage::text(&large_text))
        .unwrap();
    assert!(outbound.len() > 1);
    assert!(outbound.iter().all(|copy| copy.recipient() == bob_contact));
    assert!(outbound
        .iter()
        .all(|copy| copy.envelope().as_bytes().len() <= 56 * 1024));

    let mut completed = None;
    for copy in outbound {
        completed = bob
            .receive_lobby(copy.into_envelope())
            .unwrap()
            .or(completed);
    }
    let received = completed.unwrap();
    assert_eq!(received.from(), alice_contact);
    assert_eq!(received.lobby_id(), Some(joined.id()));
    assert_eq!(received.text().unwrap(), large_text);
}
