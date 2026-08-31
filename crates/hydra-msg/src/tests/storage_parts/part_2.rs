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
    assert!(text.contains("kdf_log_n\t17"));
    assert!(text.contains("kdf_r\t8"));
    assert!(text.contains("kdf_p\t1"));
    assert!(text.contains("kdf_salt\t"));

    let backup = hydra.export_backup("backup-pw").unwrap();
    let backup_text = String::from_utf8_lossy(&backup);
    assert!(backup_text.contains("kdf\tscrypt"));
    assert!(backup_text.contains("kdf_profile\tinteractive"));
    assert!(backup_text.contains("kdf_log_n\t17"));
    assert!(backup_text.contains("kdf_r\t8"));
    assert!(backup_text.contains("kdf_p\t1"));
    assert!(backup_text.contains("kdf_salt\t"));
}

#[test]
fn current_scrypt_profiles_meet_the_hardened_cost_floor() {
    let salt = [0x90; 32];
    let mobile = crate::codec::PasswordKdfRecord::with_salt("mobile", salt).unwrap();
    let interactive = crate::codec::PasswordKdfRecord::with_salt("interactive", salt).unwrap();
    let high = crate::codec::PasswordKdfRecord::with_salt("high-security", salt).unwrap();
    assert_eq!((mobile.log_n, mobile.r, mobile.p), (17, 8, 1));
    assert_eq!((interactive.log_n, interactive.r, interactive.p), (17, 8, 1));
    assert_eq!((high.log_n, high.r, high.p), (18, 8, 1));
}

#[test]
fn changed_kdf_parameters_are_rejected() {
    let path = "target/hydra-msg-test-kdf-parameter-change";
    make_persisted_state(path);
    let state_path = Path::new(path).join("state.hydra");
    let mut text = fs::read_to_string(&state_path).unwrap();
    text = text.replace("kdf_log_n\t17", "kdf_log_n\t16");
    fs::write(&state_path, text).unwrap();
    assert_eq!(
        Hydra::open(path, "state-pw").err(),
        Some(HydraMsgError::InvalidEncoding("kdf parameters"))
    );
}

#[test]
fn legacy_scrypt_state_is_transparently_upgraded_on_open() {
    let path = "target/hydra-msg-test-kdf-transparent-upgrade";
    let mut hydra = fresh(path);
    let id = hydra.generate_id("id-pw").unwrap();
    hydra.persist().unwrap();
    let generation_before = hydra.state_generation;
    let snapshot = hydra.encode_state_snapshot().unwrap();
    drop(hydra);

    let legacy_kdf = crate::codec::PasswordKdfRecord {
        profile: "interactive".to_owned(),
        log_n: 14,
        r: 8,
        p: 1,
        salt: [0x91; 32],
    };
    assert!(legacy_kdf.needs_upgrade().unwrap());
    let legacy_key = encrypted_snapshot::derive_state_key("state-pw", &legacy_kdf).unwrap();
    let legacy_state =
        encrypted_snapshot::seal_state_snapshot(&snapshot, &legacy_key, &legacy_kdf).unwrap();
    let state_path = Path::new(path).join("state.hydra");
    fs::write(&state_path, legacy_state).unwrap();

    let reopened = Hydra::open(path, "state-pw").unwrap();
    assert!(reopened.get_id(id).is_ok());
    assert!(reopened.state_generation > generation_before);
    assert_eq!(reopened.state_kdf.log_n, 17);
    assert!(!reopened.state_kdf.needs_upgrade().unwrap());
    let migrated = fs::read_to_string(state_path).unwrap();
    assert!(migrated.contains("kdf_log_n\t17"));
}

#[test]
fn legacy_identity_kdf_is_transparently_upgraded_on_unlock() {
    let path = "target/hydra-msg-test-identity-kdf-transparent-upgrade";
    let mut hydra = fresh(path);
    let id = hydra.generate_id("id-pw").unwrap();
    let legacy_kdf = crate::codec::PasswordKdfRecord {
        profile: "interactive".to_owned(),
        log_n: 14,
        r: 8,
        p: 1,
        salt: [0x92; 32],
    };
    crate::codec::rewrap_identity_record_with_kdf_for_test(
        hydra.identities.get_mut(&id).unwrap(),
        "id-pw",
        legacy_kdf,
    )
    .unwrap();
    hydra.lock_id(id).unwrap();
    hydra.persist().unwrap();
    assert!(hydra.identities[&id].password_kdf.needs_upgrade().unwrap());

    hydra.unlock_id(id, "id-pw").unwrap();

    assert!(hydra.get_id(id).unwrap().unlocked());
    assert_eq!(hydra.identities[&id].password_kdf.log_n, 17);
    assert!(!hydra.identities[&id].password_kdf.needs_upgrade().unwrap());
    drop(hydra);

    let reopened = Hydra::open(path, "state-pw").unwrap();
    assert_eq!(reopened.identities[&id].password_kdf.log_n, 17);
    assert!(!reopened.identities[&id].password_kdf.needs_upgrade().unwrap());
}

#[test]
fn encrypted_state_missing_file_opens_empty_without_fallback() {
    let path = "target/hydra-msg-test-missing-state-file";
    let _ = fs::remove_dir_all(path);

    let hydra = Hydra::open(path, "state-pw").unwrap();

    assert_eq!(hydra.list_ids().len(), 0);
    assert_eq!(hydra.storage_debug_status().state_generation, 0);
    assert!(!Path::new(path).join("state.hydra").exists());
}

#[test]
fn encrypted_state_rejects_corrupt_header_without_empty_fallback() {
    let path = "target/hydra-msg-test-corrupt-state-header";
    make_persisted_state(path);
    let state_path = Path::new(path).join("state.hydra");

    fs::write(&state_path, b"HYDRA-MSG-NOT-STATE\n").unwrap();

    assert!(Hydra::open(path, "state-pw").is_err());
}

#[test]
fn encrypted_state_stale_temp_file_is_not_loaded_and_is_cleaned() {
    let path = "target/hydra-msg-test-stale-temp-file";
    let _ = fs::remove_dir_all(path);
    let mut hydra = Hydra::open(path, "state-pw").unwrap();
    let temp_path = Path::new(path).join("state.hydra.tmp");

    fs::write(&temp_path, b"stale interrupted write").unwrap();
    let id = hydra.generate_id("id-pw").unwrap();
    hydra.set_active_id(id, "id-pw").unwrap();
    hydra.persist().unwrap();

    assert!(!temp_path.exists());
    drop(hydra);
    assert!(Hydra::open(path, "state-pw").is_ok());
}

#[test]
fn encrypted_state_failed_write_restores_in_memory_generation() {
    let path = "target/hydra-msg-test-failed-write-generation";
    let _ = fs::remove_dir_all(path);
    let mut hydra = Hydra::open(path, "state-pw").unwrap();
    let previous_generation = hydra.state_generation;

    fs::remove_dir_all(path).unwrap();
    fs::write(path, b"not a directory").unwrap();

    assert!(hydra.persist().is_err());
    assert_eq!(hydra.state_generation, previous_generation);

    fs::remove_file(path).unwrap();
}

#[test]
fn malformed_plaintext_snapshot_is_rejected_before_apply() {
    let snapshot = b"HYDRA-MSG-STATE-SNAPSHOT\nnext_message_id\t1\nanonymous_auth_secret\t00\n";

    assert!(Hydra::verify_state_snapshot(snapshot).is_err());
}
