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
