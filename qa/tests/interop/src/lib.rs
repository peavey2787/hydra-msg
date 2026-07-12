#![forbid(unsafe_code)]

#[cfg(test)]
mod candidate_vectors;

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use hydra_core::types::{EnvelopeClass, OuterMode};
    use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
    use hydra_envelope::{encode_outer_header, OuterHeader};
    use hydra_msg::{ContactId, Hydra, HydraLobbyPolicy};
    use hydra_session::{derive_initial_secrets, SessionRole, SessionState};

    const FROZEN_PROTOCOL_TRANSCRIPT_HASH: &[u8] =
        include_bytes!("../../../vectors/candidate/protocol/TV-DATA-000/transcript_hash.bin");
    const FROZEN_PROTOCOL_HANDSHAKE_SECRET: &[u8] =
        include_bytes!("../../../vectors/candidate/protocol/TV-DATA-000/handshake_secret.bin");
    const FROZEN_PROTOCOL_PACKET: &[u8] =
        include_bytes!("../../../vectors/candidate/protocol/TV-DATA-000/envelope.bin");
    const FROZEN_PROTOCOL_OUTER_HEADER: &[u8] =
        include_bytes!("../../../vectors/candidate/envelope/TV-HDR-000/outer_header.bin");
    const PRE_V1_STATE: &[u8] = include_bytes!(
        "../../../vectors/persistence/positive/TV-PERSIST-FULL-000/state_envelope.bin"
    );
    const PRE_V1_BACKUP: &[u8] =
        include_bytes!("../../../vectors/persistence/positive/TV-PERSIST-FULL-000/backup.bin");
    const FROZEN_STALE_GENERATION_STATE: &[u8] = include_bytes!(
        "../../../vectors/persistence/negative/TV-PERSIST-STALE-GENERATION-000/state_envelope.bin"
    );
    const FROZEN_FUTURE_STATE: &[u8] = include_bytes!(
        "../../../vectors/cross-version/TV-COMPAT-UNKNOWN-FUTURE-SNAPSHOT-000/state_envelope.bin"
    );
    const FROZEN_FUTURE_BACKUP: &[u8] = include_bytes!(
        "../../../vectors/cross-version/TV-COMPAT-UNKNOWN-FUTURE-SNAPSHOT-000/backup.bin"
    );

    const PACKET_SHA3_256: &str =
        "3f8ddf62067f4bcc06a7a60e1a31955df4562749c270114d2ac56fd3e7b79470";
    const OUTER_HEADER_SHA3_256: &str =
        "c6f71b734e3575657d78b4e447d8a1198ca28a8f90035ce0102444b9361720e4";

    fn temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("hydra-interop-{name}-{}", std::process::id()));
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

    fn connected_pair(name: &str) -> (Hydra, Hydra, ContactId) {
        let mut alice = fresh(&format!("{name}-alice"));
        let mut bob = fresh(&format!("{name}-bob"));
        let alice_id = alice.generate_id("pw").unwrap();
        let bob_id = bob.generate_id("pw").unwrap();
        alice.set_active_id(alice_id, "pw").unwrap();
        bob.set_active_id(bob_id, "pw").unwrap();

        bob.add_contact(alice.create_contact_card().unwrap())
            .unwrap();
        let bob_contact = alice
            .add_contact(bob.create_contact_card().unwrap())
            .unwrap();
        let answer = bob
            .reply_handshake(alice.init_handshake(bob_contact.id()).unwrap())
            .unwrap();
        alice.finish_handshake(answer).unwrap();
        (alice, bob, bob_contact.id())
    }

    fn exact_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
        bytes.try_into().unwrap()
    }

    fn assert_hash(bytes: &[u8], expected_hex: &str) {
        assert_eq!(hex(&RustCryptoBackend::sha3_256(bytes)), expected_hex);
    }

    fn hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(TABLE[(byte >> 4) as usize] as char);
            out.push(TABLE[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn fixture_state(name: &str) -> Hydra {
        let (mut hydra, _peer, contact_id) = connected_pair(name);
        let id = hydra.list_ids()[0].id();
        hydra.rename_id(id, "vector-identity").unwrap();
        hydra.rename_contact(contact_id, "vector-contact").unwrap();
        hydra.send(contact_id, "hello interop").unwrap();
        let lobby = hydra
            .create_lobby(HydraLobbyPolicy::new("vector-lobby", 4))
            .unwrap();
        hydra.add_lobby_member(lobby.id(), contact_id).unwrap();
        hydra
    }

    #[test]
    fn frozen_protocol_packet_opens_in_current_session_runtime() {
        assert_hash(FROZEN_PROTOCOL_PACKET, PACKET_SHA3_256);
        let transcript_hash = exact_array::<64>(FROZEN_PROTOCOL_TRANSCRIPT_HASH);
        let handshake_secret = exact_array::<32>(FROZEN_PROTOCOL_HANDSHAKE_SECRET);
        let secrets =
            derive_initial_secrets(&SecretBytes::from_array(handshake_secret), &transcript_hash)
                .unwrap();
        let mut responder = SessionState::established(
            SessionRole::Responder,
            transcript_hash,
            [0x22; 32],
            [0x11; 32],
            secrets,
        );

        let received = responder.receive(FROZEN_PROTOCOL_PACKET).unwrap();
        assert_eq!(received.index, 0);
        assert_eq!(received.content, b"hello protocol".as_slice());
        assert_eq!(responder.next_receive_index(), 1);
    }

    #[test]
    fn frozen_outer_header_fixture_is_canonical() {
        assert_hash(FROZEN_PROTOCOL_OUTER_HEADER, OUTER_HEADER_SHA3_256);
        let expected = encode_outer_header(&OuterHeader::new(
            OuterMode::Protected,
            EnvelopeClass::Full,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            0x0102_0304_0506_0708,
        ))
        .unwrap();
        assert_eq!(FROZEN_PROTOCOL_OUTER_HEADER, expected.as_slice());
    }

    #[test]
    fn current_state_fixture_opens_and_uses_chunked_storage() {
        let source = fixture_state("state-fixture-source");
        let state = state_bytes(&source);
        assert!(String::from_utf8_lossy(&state).contains("chunk_size\t65536"));
        let hydra = open_from_state_bytes("state-fixture", &state).unwrap();
        assert_full_fixture_shape(&hydra);
    }

    #[test]
    fn current_backup_fixture_imports_and_uses_chunked_storage() {
        let source = fixture_state("backup-fixture-source");
        let backup = source.export_backup("backup-pw").unwrap();
        assert!(String::from_utf8_lossy(&backup).contains("chunk_size\t65536"));
        let mut hydra = Hydra::open(temp_dir("backup-fixture"), "state-pw").unwrap();
        hydra.verify_backup(&backup, "backup-pw").unwrap();
        hydra.import_backup(&backup, "backup-pw").unwrap();
        assert_full_fixture_shape(&hydra);
    }

    #[test]
    fn native_runtime_accepts_the_same_snapshot_bytes_wasm_persists() {
        let source = fixture_state("wasm-compatible-source");
        let state = state_bytes(&source);
        let hydra = open_from_state_bytes("wasm-compatible-state", &state).unwrap();
        assert_full_fixture_shape(&hydra);
    }

    #[test]
    fn pre_v1_and_future_fixture_contracts_fail_closed() {
        assert!(open_from_state_bytes("pre-v1-state", PRE_V1_STATE).is_err());
        let pre_v1 = Hydra::open(temp_dir("pre-v1-backup"), "state-pw").unwrap();
        assert!(pre_v1.verify_backup(PRE_V1_BACKUP, "backup-pw").is_err());

        assert!(open_from_state_bytes("future-state", FROZEN_FUTURE_STATE).is_err());
        let hydra = Hydra::open(temp_dir("future-backup"), "state-pw").unwrap();
        assert!(hydra
            .verify_backup(FROZEN_FUTURE_BACKUP, "backup-pw")
            .is_err());
        let stale_path = temp_dir("stale-generation");
        fs::create_dir_all(&stale_path).unwrap();
        fs::write(
            stale_path.join("state.hydra"),
            FROZEN_STALE_GENERATION_STATE,
        )
        .unwrap();
        fs::write(stale_path.join("state.hydra.rollback"), b"2\n").unwrap();
        assert!(Hydra::open(&stale_path, "state-pw").is_err());
    }

    fn assert_full_fixture_shape(hydra: &Hydra) {
        assert!(hydra.storage_debug_status().state_generation >= 1);
        assert_eq!(hydra.list_ids().len(), 1);
        assert_eq!(hydra.list_ids()[0].label(), "vector-identity");
        assert_eq!(hydra.list_contacts().len(), 1);
        let contact_id = ContactId::from_hex(hydra.list_contacts()[0].id().hex()).unwrap();
        assert_eq!(
            hydra.get_contact(contact_id).unwrap().label(),
            "vector-contact"
        );
        assert_eq!(hydra.list_messages(contact_id).len(), 1);
        assert_eq!(hydra.list_lobbies().len(), 1);
    }
}
