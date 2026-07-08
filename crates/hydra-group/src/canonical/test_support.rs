use super::commit_core::CommitCore;
use crate::{
    CommitKind, GovernancePolicy, GroupMode, GroupRole, MemberId, MemberStatus,
    MembershipMechanism, ModePolicy, RosterEntry, StateVersion,
};
use hydra_core::types::{Epoch, GroupId, IdentityFingerprint};

pub fn group_id() -> GroupId {
    GroupId([0x42; 32])
}

pub fn member(value: u8) -> MemberId {
    MemberId([value; 32])
}

pub fn fingerprint(value: u8) -> IdentityFingerprint {
    IdentityFingerprint([value; 32])
}

pub fn entry(member_value: u8, fingerprint_value: u8) -> RosterEntry {
    RosterEntry {
        member_id: member(member_value),
        device_identity_fingerprint: fingerprint(fingerprint_value),
        role: GroupRole::Member,
        status: MemberStatus::Active,
        tree_leaf_slot: u32::from(member_value),
        joined_epoch: Epoch(1),
        removed_epoch: Epoch(0),
    }
}

pub fn sorted_governance(count: u8, threshold: u8) -> GovernancePolicy {
    GovernancePolicy {
        policy_version: 1,
        threshold,
        authorized_signers: (1..=count).map(member).collect(),
    }
}

pub fn commit_core() -> CommitCore {
    CommitCore {
        commit_kind: CommitKind::Join,
        group_id: group_id(),
        old_group_mode: Some(GroupMode::Interactive),
        new_group_mode: GroupMode::Interactive,
        new_membership_mechanism: MembershipMechanism::TreeKem,
        old_epoch: Epoch(1),
        new_epoch: Epoch(2),
        old_state_version: StateVersion(3),
        new_state_version: StateVersion(4),
        parent_commit_hash: [1; 64],
        old_roster_hash: [2; 64],
        new_roster_hash: [3; 64],
        old_tree_hash: [4; 64],
        new_tree_hash: [5; 64],
        commit_nonce: [6; 32],
        change_payload_hash: [7; 64],
        key_schedule_commitment: [8; 64],
        governance_policy_hash: [9; 64],
        mode_policy_hash: [10; 64],
    }
}
