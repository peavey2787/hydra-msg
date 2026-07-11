use super::*;
use std::fs;
use std::path::Path;

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

#[test]
fn native_same_profile_second_open_fails_closed_until_first_handle_drops() {
    let path = "target/hydra-msg-test-native-profile-lock";
    let mut first = fresh(path);
    first.generate_id("id-pw").unwrap();
    assert!(Path::new(path).join("state.hydra.lock").exists());

    assert!(matches!(
        Hydra::open(path, "state-pw"),
        Err(HydraMsgError::InvalidInput(
            "native profile is already open"
        ))
    ));

    drop(first);
    let reopened = Hydra::open(path, "state-pw").unwrap();
    assert_eq!(reopened.list_ids().len(), 1);
}

#[test]
fn native_profile_lock_prevents_stale_last_writer_and_preserves_rollback_guard() {
    let path = "target/hydra-msg-test-native-profile-lock-rollback";
    let mut first = fresh(path);
    let first_id = first.generate_id("id-pw").unwrap();
    let first_generation = first.storage_debug_status().state_generation;

    assert!(Hydra::open(path, "state-pw").is_err());
    first.rename_id(first_id, "first writer").unwrap();
    let newer_generation = first.storage_debug_status().state_generation;
    assert!(newer_generation > first_generation);
    drop(first);

    let reopened = Hydra::open(path, "state-pw").unwrap();
    assert_eq!(
        reopened.storage_debug_status().state_generation,
        newer_generation
    );
    assert_eq!(reopened.get_id(first_id).unwrap().label(), "first writer");
}
