use super::*;
use crate::{
    AcceptedGroupMessage, GroupStateSnapshot, SenderChainCursorSnapshot,
    SkippedGroupMessageKeySnapshot,
};
use hydra_core::REPLAY_WINDOW_WIDTH;

fn snapshot() -> GroupStateSnapshot {
    interactive_state().export_snapshot().unwrap()
}

fn two_member_snapshot() -> GroupStateSnapshot {
    let mut state = interactive_state();
    state
        .replace_roster(vec![
            active_entry(1, 1, GroupRole::Member),
            active_entry(2, 2, GroupRole::Member),
        ])
        .unwrap();
    state.export_snapshot().unwrap()
}

#[test]
fn sender_chain_snapshot_rejects_unknown_and_duplicate_senders() {
    let mut unknown = snapshot();
    unknown.sender_chains.senders = vec![SenderChainCursorSnapshot {
        sender: member(2),
        next_index: 0,
        chain_key: [1; 32],
    }];
    assert_eq!(
        GroupState::from_snapshot(unknown).err(),
        Some(GroupError::InvalidSenderChain)
    );

    let mut duplicate = snapshot();
    let cursor = SenderChainCursorSnapshot {
        sender: member(1),
        next_index: 0,
        chain_key: [2; 32],
    };
    duplicate.sender_chains.senders = vec![cursor.clone(), cursor];
    assert_eq!(
        GroupState::from_snapshot(duplicate).err(),
        Some(GroupError::InvalidSenderChain)
    );
}

#[test]
fn sender_chain_snapshot_rejects_skipped_key_overflow_and_duplicates() {
    let skipped = SkippedGroupMessageKeySnapshot {
        sender: member(1),
        index: 0,
        route_tag: [3; 16],
        message_key: [4; 32],
    };

    let mut oversized = snapshot();
    oversized.sender_chains.skipped = (0..=GroupMode::Interactive.sender_skip_bound())
        .map(|index| SkippedGroupMessageKeySnapshot {
            index: index as u64,
            ..skipped.clone()
        })
        .collect();
    assert_eq!(
        GroupState::from_snapshot(oversized).err(),
        Some(GroupError::InvalidSenderChain)
    );

    let mut duplicate = snapshot();
    duplicate.sender_chains.skipped = vec![skipped.clone(), skipped];
    assert_eq!(
        GroupState::from_snapshot(duplicate).err(),
        Some(GroupError::InvalidSenderChain)
    );
}

#[test]
fn replay_snapshot_rejects_accepted_message_overflow_and_duplicates() {
    let accepted = AcceptedGroupMessage {
        sender: member(1),
        index: 0,
        route_tag: [5; 16],
    };

    let mut oversized = snapshot();
    oversized.replay_state.accepted_messages = (0..=REPLAY_WINDOW_WIDTH)
        .map(|index| AcceptedGroupMessage {
            index: index as u64,
            ..accepted
        })
        .collect();
    assert_eq!(
        GroupState::from_snapshot(oversized).err(),
        Some(GroupError::InvalidSenderChain)
    );

    let mut duplicate = snapshot();
    duplicate.replay_state.accepted_messages = vec![accepted, accepted];
    assert_eq!(
        GroupState::from_snapshot(duplicate).err(),
        Some(GroupError::InvalidSenderChain)
    );
}

#[test]
fn replay_snapshot_rejects_per_sender_overflow_and_route_duplicates() {
    let accepted = AcceptedGroupMessage {
        sender: member(1),
        index: 0,
        route_tag: [6; 16],
    };

    let mut per_sender = two_member_snapshot();
    per_sender.replay_state.accepted_messages = (0..=REPLAY_WINDOW_WIDTH)
        .map(|index| {
            let mut route_tag = [0_u8; 16];
            route_tag[..8].copy_from_slice(&(index as u64).to_be_bytes());
            AcceptedGroupMessage {
                index: index as u64,
                route_tag,
                ..accepted
            }
        })
        .collect();
    assert_eq!(
        GroupState::from_snapshot(per_sender).err(),
        Some(GroupError::InvalidSenderChain)
    );

    let mut duplicate_route = two_member_snapshot();
    duplicate_route.replay_state.accepted_messages = vec![
        accepted,
        AcceptedGroupMessage {
            sender: member(2),
            ..accepted
        },
    ];
    assert_eq!(
        GroupState::from_snapshot(duplicate_route).err(),
        Some(GroupError::InvalidSenderChain)
    );
}
