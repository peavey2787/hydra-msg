#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use hydra_msg::{ContactId, Hydra, HydraLobbyPolicy, HydraMessage};

    const PRE_V1_STATE: &[u8] = include_bytes!(
        "../../../vectors/persistence/positive/TV-PERSIST-FULL-000/state_envelope.bin"
    );
    const PRE_V1_BACKUP: &[u8] =
        include_bytes!("../../../vectors/persistence/positive/TV-PERSIST-FULL-000/backup.bin");
    const PRE_V1_STALE_GENERATION_STATE: &[u8] = include_bytes!(
        "../../../vectors/persistence/negative/TV-PERSIST-STALE-GENERATION-000/state_envelope.bin"
    );
    const UNKNOWN_FUTURE_STATE: &[u8] = include_bytes!(
        "../../../vectors/cross-version/TV-COMPAT-UNKNOWN-FUTURE-SNAPSHOT-000/state_envelope.bin"
    );
    const UNKNOWN_FUTURE_BACKUP: &[u8] = include_bytes!(
        "../../../vectors/cross-version/TV-COMPAT-UNKNOWN-FUTURE-SNAPSHOT-000/backup.bin"
    );

    fn temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "hydra-cross-version-compat-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn fresh(name: &str) -> Hydra {
        Hydra::open(temp_dir(name), "state-pw").unwrap()
    }

    fn state_bytes(hydra: &Hydra) -> Vec<u8> {
        fs::read(hydra.data_dir().join("state.hydra")).unwrap()
    }

    fn open_from_state_bytes(name: &str, bytes: &[u8]) -> hydra_msg::HydraResult<Hydra> {
        let path = temp_dir(name);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("state.hydra"), bytes).unwrap();
        Hydra::open(&path, "state-pw")
    }

    fn fixture_state(name: &str) -> Hydra {
        let (mut hydra, _peer, _peer_contact, contact_id) = connected_pair(name);
        hydra.rename_contact(contact_id, "vector-contact").unwrap();
        hydra
            .send(contact_id, HydraMessage::text("hello fixture"))
            .unwrap();
        let lobby = hydra
            .create_lobby(HydraLobbyPolicy::new("vector-lobby", 4))
            .unwrap();
        hydra.add_lobby_member(lobby.id(), contact_id).unwrap();
        hydra
    }

    fn connected_pair(name: &str) -> (Hydra, Hydra, ContactId, ContactId) {
        let mut alice = fresh(&format!("{name}-alice"));
        let mut bob = fresh(&format!("{name}-bob"));
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
    fn current_v1_candidate_state_opens_in_current_runtime() {
        let source = fixture_state("current-state-source");
        let state = state_bytes(&source);
        let hydra = open_from_state_bytes("current-state-open", &state).unwrap();

        assert!(hydra.storage_debug_status().state_generation >= 1);
        assert_eq!(hydra.list_ids().len(), 1);
        assert_eq!(hydra.list_contacts().len(), 1);
        let contact_id = hydra.list_contacts()[0].id();
        assert_eq!(
            hydra.get_contact(contact_id).unwrap().label(),
            "vector-contact"
        );
        assert_eq!(hydra.list_messages(contact_id).len(), 1);
        assert_eq!(hydra.list_lobbies().len(), 1);
    }

    #[test]
    fn current_v1_candidate_backup_imports_in_current_runtime() {
        let source = fixture_state("current-backup-source");
        let backup = source.export_backup("backup-pw").unwrap();
        let mut hydra = fresh("current-backup-import");
        hydra.import_backup(&backup, "backup-pw").unwrap();

        assert_eq!(hydra.list_ids().len(), 1);
        assert_eq!(hydra.list_contacts().len(), 1);
        assert_eq!(hydra.list_lobbies().len(), 1);
        hydra.verify_backup(&backup, "backup-pw").unwrap();
    }

    #[test]
    fn pre_v1_unpadded_persistence_fixtures_fail_closed() {
        assert!(open_from_state_bytes("pre-v1-state", PRE_V1_STATE).is_err());

        let verifier = fresh("pre-v1-backup");
        assert!(verifier.verify_backup(PRE_V1_BACKUP, "backup-pw").is_err());
    }

    #[test]
    fn unknown_future_snapshot_records_fail_closed() {
        assert!(open_from_state_bytes("unknown-future-state", UNKNOWN_FUTURE_STATE).is_err());

        let mut verifier = fresh("unknown-future-backup");
        assert!(verifier
            .verify_backup(UNKNOWN_FUTURE_BACKUP, "backup-pw")
            .is_err());
        assert!(verifier
            .import_backup(UNKNOWN_FUTURE_BACKUP, "backup-pw")
            .is_err());
        assert_eq!(verifier.list_ids().len(), 0);
        assert_eq!(verifier.list_contacts().len(), 0);
    }

    #[test]
    fn pre_v1_rollback_generation_evidence_still_rejects_stale_state() {
        let path = temp_dir("rollback-generation");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("state.hydra"), PRE_V1_STALE_GENERATION_STATE).unwrap();
        fs::write(path.join("state.hydra.rollback"), b"2\n").unwrap();

        assert!(Hydra::open(&path, "state-pw").is_err());
    }

    #[test]
    fn restore_from_current_backup_preserves_newer_generation_floor() {
        let source = fixture_state("restore-source");
        let backup = source.export_backup("backup-pw").unwrap();
        let mut target = fresh("restore-generation-floor");
        for index in 0..3 {
            let id = target.generate_id(format!("target-pw-{index}")).unwrap();
            target
                .rename_id(id, format!("newer-local-id-{index}"))
                .unwrap();
        }
        let previous_generation = target.storage_debug_status().state_generation;
        assert!(previous_generation > 1);

        target.import_backup(&backup, "backup-pw").unwrap();

        assert!(target.storage_debug_status().state_generation > previous_generation);
        assert_eq!(target.list_ids().len(), 1);
    }

    #[test]
    fn current_fragmented_packets_reassemble_through_public_receive_contract() {
        let (mut alice, mut bob, alice_contact, bob_contact) = connected_pair("fragments");
        alice.set_packet_size(56 * 1024).unwrap();
        bob.set_packet_size(56 * 1024).unwrap();

        let text = "fragment-compat-".repeat(hydra_core::STANDARD_MAX_CONTENT_SIZE / 8);
        let packets = alice.send(bob_contact, HydraMessage::text(&text)).unwrap();
        assert!(packets.len() > 1);
        assert!(packets
            .iter()
            .all(|packet| packet.as_bytes().len() <= 56 * 1024));

        let mut completed = None;
        for packet in packets {
            completed = bob.receive(packet).unwrap().or(completed);
        }
        let received = completed.unwrap();
        assert_eq!(received.from(), alice_contact);
        assert_eq!(received.text().unwrap(), text);
    }
}
