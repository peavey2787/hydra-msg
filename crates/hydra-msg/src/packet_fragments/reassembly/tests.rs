use super::*;
use crate::limits::{
    MAX_FRAGMENTS_PER_MESSAGE, MAX_INCOMPLETE_MESSAGES_PER_CONTACT,
    MAX_INCOMPLETE_MESSAGES_PER_LOBBY,
};

fn direct_part(fragment_id: [u8; 32], total: usize, index: usize, byte: u8) -> FragmentRecord {
    FragmentRecord {
        kind: FragmentKind::Direct,
        lobby_id: None,
        fragment_id,
        total,
        index,
        bytes: vec![byte],
    }
}

fn lobby_part(
    lobby_id: LobbyId,
    fragment_id: [u8; 32],
    total: usize,
    index: usize,
    byte: u8,
) -> FragmentRecord {
    FragmentRecord {
        kind: FragmentKind::Lobby,
        lobby_id: Some(lobby_id),
        fragment_id,
        total,
        index,
        bytes: vec![byte],
    }
}

#[test]
fn sparse_reassembly_does_not_allocate_declared_part_count() {
    let mut pending = HashMap::new();
    let from = ContactId([1; 32]);
    let part = direct_part([2; 32], MAX_FRAGMENTS_PER_MESSAGE, 0, 7);
    assert!(
        apply_fragment_record(&mut pending, from, FragmentKind::Direct, part)
            .unwrap()
            .is_none()
    );
    let entry = pending.values().next().unwrap();
    assert_eq!(entry.total, MAX_FRAGMENTS_PER_MESSAGE);
    assert_eq!(entry.parts.len(), 1);
    assert_eq!(entry.received_bytes, 1);
}

#[test]
fn conflicting_duplicate_fragment_discards_incomplete_message() {
    let mut pending = HashMap::new();
    let from = ContactId([3; 32]);
    let id = [4; 32];
    apply_fragment_record(
        &mut pending,
        from,
        FragmentKind::Direct,
        direct_part(id, 2, 0, 1),
    )
    .unwrap();
    assert!(apply_fragment_record(
        &mut pending,
        from,
        FragmentKind::Direct,
        direct_part(id, 2, 0, 2),
    )
    .is_err());
    assert!(pending.is_empty());
}

#[test]
fn per_contact_incomplete_message_limit_is_enforced() {
    let mut pending = HashMap::new();
    let from = ContactId([5; 32]);
    for index in 0..MAX_INCOMPLETE_MESSAGES_PER_CONTACT {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
        apply_fragment_record(
            &mut pending,
            from,
            FragmentKind::Direct,
            direct_part(id, 2, 0, 1),
        )
        .unwrap();
    }
    assert_eq!(pending.len(), MAX_INCOMPLETE_MESSAGES_PER_CONTACT);
    assert!(apply_fragment_record(
        &mut pending,
        from,
        FragmentKind::Direct,
        direct_part([0xff; 32], 2, 0, 1),
    )
    .is_err());
    assert_eq!(pending.len(), MAX_INCOMPLETE_MESSAGES_PER_CONTACT);
}

#[test]
fn expired_fragments_are_removed_before_accepting_new_work() {
    let mut pending = HashMap::new();
    let from = ContactId([6; 32]);
    apply_fragment_record(
        &mut pending,
        from,
        FragmentKind::Direct,
        direct_part([7; 32], 2, 0, 1),
    )
    .unwrap();
    pending.values_mut().next().unwrap().created_at =
        HydraInstant::now_minus(Duration::from_secs(MAX_FRAGMENT_AGE_SECS + 1));
    apply_fragment_record(
        &mut pending,
        from,
        FragmentKind::Direct,
        direct_part([8; 32], 2, 0, 1),
    )
    .unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending.keys().all(|key| key.fragment_id == [8; 32]));
}

#[test]
fn identical_duplicate_fragment_is_idempotent_and_remains_incomplete() {
    let mut pending = HashMap::new();
    let from = ContactId([9; 32]);
    let id = [10; 32];
    let part = direct_part(id, 2, 0, 7);
    assert!(apply_fragment_record(
        &mut pending,
        from,
        FragmentKind::Direct,
        direct_part(id, 2, 0, 7),
    )
    .unwrap()
    .is_none());
    assert!(
        apply_fragment_record(&mut pending, from, FragmentKind::Direct, part)
            .unwrap()
            .is_none()
    );
    let entry = pending.values().next().unwrap();
    assert_eq!(entry.parts.len(), 1);
    assert_eq!(entry.total, 2);
    assert_eq!(entry.received_bytes, 1);
}

#[test]
fn per_lobby_incomplete_message_limit_spans_distinct_contacts() {
    let mut pending = HashMap::new();
    let lobby_id = LobbyId([11; 32]);
    for index in 0..MAX_INCOMPLETE_MESSAGES_PER_LOBBY {
        let byte = u8::try_from(index + 1).unwrap();
        assert!(apply_fragment_record(
            &mut pending,
            ContactId([byte; 32]),
            FragmentKind::Lobby,
            lobby_part(lobby_id, [byte; 32], 2, 0, byte),
        )
        .unwrap()
        .is_none());
    }
    assert_eq!(pending.len(), MAX_INCOMPLETE_MESSAGES_PER_LOBBY);
    let next = u8::try_from(MAX_INCOMPLETE_MESSAGES_PER_LOBBY + 1).unwrap();
    assert!(matches!(
        apply_fragment_record(
            &mut pending,
            ContactId([next; 32]),
            FragmentKind::Lobby,
            lobby_part(lobby_id, [next; 32], 2, 0, next),
        ),
        Err(HydraMsgError::InvalidInput(
            "too many incomplete messages for fragment scope"
        ))
    ));
    assert_eq!(pending.len(), MAX_INCOMPLETE_MESSAGES_PER_LOBBY);
}

#[test]
fn fragmented_payload_limit_rejects_the_first_byte_over_the_boundary() {
    let mut pending = HashMap::new();
    let from = ContactId([12; 32]);
    let key = PendingFragmentKey {
        from,
        scope: FragmentScopeKey::Direct,
        kind: FragmentKind::Direct,
        fragment_id: [13; 32],
    };
    pending.insert(
        key,
        PendingInboundFragments {
            parts: HashMap::from([(0, Vec::new())]),
            total: 2,
            received_bytes: MAX_FRAGMENTED_PAYLOAD_BYTES,
            created_at: HydraInstant::now(),
        },
    );
    assert!(matches!(
        apply_fragment_record(
            &mut pending,
            from,
            FragmentKind::Direct,
            direct_part([13; 32], 2, 1, 1),
        ),
        Err(HydraMsgError::InvalidEncoding("fragmented payload size"))
    ));
    assert!(pending.is_empty());
}

#[test]
fn global_pending_byte_budget_allows_the_exact_boundary() {
    let mut pending = HashMap::new();
    pending.insert(
        PendingFragmentKey {
            from: ContactId([14; 32]),
            scope: FragmentScopeKey::Direct,
            kind: FragmentKind::Direct,
            fragment_id: [15; 32],
        },
        PendingInboundFragments {
            parts: HashMap::new(),
            total: 2,
            received_bytes: MAX_PENDING_FRAGMENT_BYTES - 1,
            created_at: HydraInstant::now(),
        },
    );
    let key = PendingFragmentKey {
        from: ContactId([16; 32]),
        scope: FragmentScopeKey::Direct,
        kind: FragmentKind::Direct,
        fragment_id: [17; 32],
    };
    assert!(reject_global_fragment_budget(
        &pending,
        &key,
        &direct_part([17; 32], 2, 0, 1),
    )
    .is_ok());
}

#[test]
fn global_pending_byte_budget_rejects_the_first_byte_over_the_boundary() {
    let mut pending = HashMap::new();
    pending.insert(
        PendingFragmentKey {
            from: ContactId([18; 32]),
            scope: FragmentScopeKey::Direct,
            kind: FragmentKind::Direct,
            fragment_id: [19; 32],
        },
        PendingInboundFragments {
            parts: HashMap::new(),
            total: 2,
            received_bytes: MAX_PENDING_FRAGMENT_BYTES,
            created_at: HydraInstant::now(),
        },
    );
    let key = PendingFragmentKey {
        from: ContactId([20; 32]),
        scope: FragmentScopeKey::Direct,
        kind: FragmentKind::Direct,
        fragment_id: [21; 32],
    };
    assert!(matches!(
        reject_global_fragment_budget(
            &pending,
            &key,
            &direct_part([21; 32], 2, 0, 1),
        ),
        Err(HydraMsgError::InvalidInput(
            "pending fragment byte budget exceeded"
        ))
    ));
}
