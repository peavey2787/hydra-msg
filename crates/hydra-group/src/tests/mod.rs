use crate::{
    epoch::next_epoch, rekey::rekey_path, validate_mode_mechanism, CommitKind, GovernancePolicy,
    GroupError, GroupMode, GroupPhase, GroupRole, GroupState, MemberId, MemberStatus,
    MembershipMechanism, ModePolicy,
};
use hydra_core::types::{Epoch, GroupId, IdentityFingerprint};

fn governance() -> GovernancePolicy {
    GovernancePolicy::single_signer(MemberId([1; 32]))
}

fn group_id() -> GroupId {
    GroupId([0x42; 32])
}

fn member(value: u8) -> MemberId {
    MemberId([value; 32])
}

fn fingerprint(value: u8) -> IdentityFingerprint {
    IdentityFingerprint([value; 32])
}

fn active_entry(member_value: u8, fingerprint_value: u8, role: GroupRole) -> crate::RosterEntry {
    crate::RosterEntry {
        member_id: member(member_value),
        device_identity_fingerprint: fingerprint(fingerprint_value),
        role,
        status: MemberStatus::Active,
        tree_leaf_slot: u32::from(member_value),
        joined_epoch: Epoch(1),
        removed_epoch: Epoch(0),
    }
}

fn removed_entry(member_value: u8, fingerprint_value: u8, role: GroupRole) -> crate::RosterEntry {
    crate::RosterEntry {
        member_id: member(member_value),
        device_identity_fingerprint: fingerprint(fingerprint_value),
        role,
        status: MemberStatus::Removed,
        tree_leaf_slot: u32::from(member_value),
        joined_epoch: Epoch(1),
        removed_epoch: Epoch(2),
    }
}

fn interactive_state() -> GroupState {
    GroupState::new_validated(crate::GroupStateConfig {
        group_id: group_id(),
        mode: GroupMode::Interactive,
        mechanism: MembershipMechanism::TreeKem,
        epoch: Epoch(2),
        state_version: crate::StateVersion(0),
        governance_policy: governance(),
        mode_policy: ModePolicy::default(),
        roster: vec![active_entry(1, 1, GroupRole::Member)],
    })
    .unwrap()
}

mod mode_rules;
mod roster_state;

mod resource_limits;
