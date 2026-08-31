#[test]
fn candidate_ratchet_vectors_execute_current_session_runtime() {
    let mut ordered = responder("TV-RATCHET-001");
    assert_eq!(
        ordered.test_state_hash(),
        exact::<32>(artifact("ratchet", "TV-RATCHET-001", "state_before.bin",))
    );
    let received = ordered
        .receive(&artifact("ratchet", "TV-RATCHET-001", "envelope.bin"))
        .unwrap();
    assert_eq!(
        received.content,
        artifact("ratchet", "TV-RATCHET-001", "received.bin")
    );
    assert_eq!(
        ordered.test_state_hash(),
        exact::<32>(artifact("ratchet", "TV-RATCHET-001", "state_after.bin",))
    );

    let mut damaged = responder("TV-RATCHET-002");
    let before = damaged.test_state_hash();
    assert!(damaged
        .receive(&artifact(
            "ratchet",
            "TV-RATCHET-002",
            "mutated_envelope.bin",
        ))
        .is_err());
    assert_eq!(damaged.test_state_hash(), before);

    let mut boundary = responder("TV-RATCHET-003");
    boundary
        .receive(&artifact(
            "ratchet",
            "TV-RATCHET-003",
            "boundary_envelope.bin",
        ))
        .unwrap();
    assert_eq!(
        boundary.test_state_hash(),
        exact::<32>(artifact(
            "ratchet",
            "TV-RATCHET-003",
            "state_after_boundary.bin",
        ))
    );
    let delayed = artifact("ratchet", "TV-RATCHET-003", "delayed_zero_envelope.bin");
    boundary.receive(&delayed).unwrap();
    assert_eq!(
        boundary.test_state_hash(),
        exact::<32>(artifact(
            "ratchet",
            "TV-RATCHET-003",
            "state_after_delayed.bin",
        ))
    );
    assert!(boundary.receive(&delayed).is_err());
    assert_eq!(
        boundary.test_state_hash(),
        exact::<32>(artifact(
            "ratchet",
            "TV-RATCHET-003",
            "state_after_replay.bin",
        ))
    );

    let mut too_far = responder("TV-RATCHET-004");
    let before = too_far.test_state_hash();
    assert!(too_far
        .receive(&artifact(
            "ratchet",
            "TV-RATCHET-004",
            "future_envelope.bin",
        ))
        .is_err());
    assert_eq!(too_far.test_state_hash(), before);
}

#[test]
fn candidate_group_rejection_vectors_preserve_parent_state() {
    let root = vector_path("group", "TV-GROUP-NEG-DUP-MEMBER-ID-000", "metadata.json")
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf();
    let mut checked = 0;
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("TV-GROUP-NEG-") || name == "TV-GROUP-NEG-FORK-CONFLICT-000" {
            continue;
        }
        assert_eq!(
            fs::read(path.join("state_hash_before.bin")).unwrap(),
            fs::read(path.join("state_hash_after.bin")).unwrap(),
            "negative vector mutated state: {name}"
        );
        checked += 1;
    }
    assert_eq!(checked, 22);
}
