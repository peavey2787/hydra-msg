use super::*;
use crate::{
    CommitSignature, GovernancePolicy, GroupError, GroupMode, GroupPhase, GroupRole, GroupState,
    MemberId, MemberStatus, MembershipMechanism, MembershipPrivateState, ModePolicy, RosterEntry,
};
use hydra_core::types::{Epoch, GroupId, IdentityFingerprint};

fn group_id() -> GroupId {
    GroupId([0x42; 32])
}

fn member(value: u8) -> MemberId {
    MemberId([value; 32])
}

fn fingerprint(value: u8) -> IdentityFingerprint {
    IdentityFingerprint([value; 32])
}

fn entry(member_value: u8, fingerprint_value: u8, role: GroupRole) -> RosterEntry {
    RosterEntry {
        member_id: member(member_value),
        device_identity_fingerprint: fingerprint(fingerprint_value),
        role,
        status: MemberStatus::Active,
        tree_leaf_slot: u32::from(member_value),
        joined_epoch: Epoch(1),
        removed_epoch: Epoch(0),
    }
}

fn lite_state() -> GroupState {
    GroupState::new_validated(crate::GroupStateConfig {
        group_id: group_id(),
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        epoch: Epoch(1),
        state_version: crate::StateVersion(1),
        governance_policy: GovernancePolicy::single_signer(member(1)),
        mode_policy: ModePolicy::default(),
        roster: vec![entry(1, 1, GroupRole::Member)],
    })
    .unwrap()
}

fn signature(signer: MemberId) -> CommitSignature {
    CommitSignature {
        signer,
        signature: [0x5a; hydra_core::ML_DSA_65_SIG_SIZE],
    }
}

fn role_change_plan(new_role: GroupRole) -> CommitPlan {
    CommitPlan {
        committer: member(1),
        commit_nonce: [0x77; 32],
        change: CommitChange::RoleChange {
            member_id: member(1),
            new_role,
        },
        signatures: vec![signature(member(1))],
        update_path: None,
        direct_epoch_secret: Some([0x88; 32]),
    }
}

#[test]
fn governance_signature_threshold_order_and_authorization_are_enforced() {
    let state = lite_state();
    assert_eq!(
        validate_governance_signatures(&state.governance_policy, &state.roster, &[]),
        Err(GroupError::InvalidSignatureSet)
    );
    let unauthorized = vec![signature(member(2))];
    assert_eq!(
        validate_governance_signatures(&state.governance_policy, &state.roster, &unauthorized),
        Err(GroupError::InvalidGovernanceSigner { signer: member(2) })
    );
    assert!(validate_governance_signatures(
        &state.governance_policy,
        &state.roster,
        &[signature(member(1))]
    )
    .is_ok());
}

#[test]
fn lite_role_change_prepares_and_applies_atomically() {
    let mut state = lite_state();
    let before_parent = state.last_commit_hash;
    let prepared = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
    assert_eq!(prepared.core.old_epoch, Epoch(1));
    assert_eq!(prepared.core.new_epoch, Epoch(2));
    assert_eq!(prepared.core.old_state_version, crate::StateVersion(1));
    assert_eq!(prepared.core.new_state_version, crate::StateVersion(2));
    assert_eq!(prepared.core.parent_commit_hash, before_parent);
    assert_ne!(prepared.commit_hash, [0; 64]);
    assert_ne!(prepared.signature_digest, prepared.commit_hash);

    apply_prepared_commit(&mut state, prepared).unwrap();
    assert_eq!(state.epoch, Epoch(2));
    assert_eq!(state.state_version, crate::StateVersion(2));
    assert_eq!(state.roster[0].role, GroupRole::Moderator);
    assert_ne!(state.last_commit_hash, before_parent);
    assert!(matches!(
        &state.membership,
        MembershipPrivateState::DirectWrap { .. }
    ));
    assert_eq!(state.sender_chains.len(), 1);
    assert_eq!(state.replay_state.senders.len(), 1);
    let first = state.next_sender_message_step(member(1)).unwrap();
    assert_eq!(first.sender, member(1));
    assert_eq!(first.index, 0);
    assert_eq!(state.sender_chains.next_index(member(1)), Some(1));
}

#[test]
fn invalid_commit_preserves_parent_state() {
    let state = lite_state();
    let before = (
        state.epoch,
        state.state_version,
        state.roster.clone(),
        state.roster_hash,
    );
    assert_eq!(
        prepare_commit(&state, role_change_plan(GroupRole::Audience)).map(|_| ()),
        Err(GroupError::InvalidRoleForMode {
            mode: GroupMode::Lite,
            role: GroupRole::Audience,
        })
    );
    assert_eq!(
        (
            state.epoch,
            state.state_version,
            state.roster.clone(),
            state.roster_hash
        ),
        before
    );
}

#[test]
fn non_create_counter_overflow_rejects_before_state_change() {
    let mut state = lite_state();
    state.epoch = Epoch(u64::MAX);
    let before = (
        state.epoch,
        state.state_version,
        state.roster.clone(),
        state.roster_hash,
    );
    assert_eq!(
        prepare_commit(&state, role_change_plan(GroupRole::Moderator)).map(|_| ()),
        Err(GroupError::CounterExhausted)
    );
    assert_eq!(
        (
            state.epoch,
            state.state_version,
            state.roster.clone(),
            state.roster_hash
        ),
        before
    );
}

#[test]
fn create_uses_epoch_and_state_version_zero() {
    let state = GroupState::new_empty(
        group_id(),
        GroupMode::Lite,
        MembershipMechanism::DirectWrap,
        GovernancePolicy::single_signer(member(1)),
        ModePolicy::default(),
    )
    .unwrap();
    let mut created = entry(1, 1, GroupRole::Member);
    created.joined_epoch = Epoch(0);
    let plan = CommitPlan {
        committer: member(1),
        commit_nonce: [0x11; 32],
        change: CommitChange::Create {
            new_roster: vec![created],
            new_governance_policy: GovernancePolicy::single_signer(member(1)),
            new_mode_policy: ModePolicy::default(),
            new_tree_hash: [0; 64],
        },
        signatures: vec![signature(member(1))],
        update_path: None,
        direct_epoch_secret: Some([0x33; 32]),
    };
    let prepared = prepare_commit(&state, plan).unwrap();
    assert_eq!(prepared.core.old_group_mode, None);
    assert_eq!(prepared.core.old_epoch, Epoch(0));
    assert_eq!(prepared.core.new_epoch, Epoch(0));
    assert_eq!(prepared.core.old_state_version, crate::StateVersion(0));
    assert_eq!(prepared.core.new_state_version, crate::StateVersion(0));
}

#[test]
fn install_reports_duplicate_without_mutation() {
    let mut state = lite_state();
    let first = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
    let duplicate = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
    assert_eq!(
        install_prepared_commit(&mut state, first),
        Ok(CommitInstallResult::Applied)
    );
    let before = (
        state.epoch,
        state.state_version,
        state.last_commit_hash,
        state.phase,
    );
    assert_eq!(
        install_prepared_commit(&mut state, duplicate),
        Ok(CommitInstallResult::Duplicate)
    );
    assert_eq!(
        (
            state.epoch,
            state.state_version,
            state.last_commit_hash,
            state.phase
        ),
        before
    );
}

#[test]
fn sibling_commit_marks_group_forked_and_wipes_private_material() {
    let mut state = lite_state();
    let first = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
    let mut sibling_plan = role_change_plan(GroupRole::Moderator);
    sibling_plan.commit_nonce = [0x78; 32];
    sibling_plan.direct_epoch_secret = Some([0x89; 32]);
    let sibling = prepare_commit(&state, sibling_plan).unwrap();

    assert_eq!(
        install_prepared_commit(&mut state, first),
        Ok(CommitInstallResult::Applied)
    );
    assert!(matches!(
        state.membership,
        MembershipPrivateState::DirectWrap { .. }
    ));
    assert_eq!(
        install_prepared_commit(&mut state, sibling),
        Ok(CommitInstallResult::Forked)
    );
    assert_eq!(state.phase, GroupPhase::Forked);
    assert!(matches!(state.membership, MembershipPrivateState::Empty));
    assert_eq!(
        state.require_sender(member(1)),
        Err(GroupError::InvalidState)
    );
}

#[test]
fn closed_or_forked_groups_reject_commit_installation() {
    let mut closed = lite_state();
    let prepared_for_closed =
        prepare_commit(&closed, role_change_plan(GroupRole::Moderator)).unwrap();
    closed.close();
    assert_eq!(
        install_prepared_commit(&mut closed, prepared_for_closed),
        Err(GroupError::InvalidState)
    );

    let mut forked = lite_state();
    let prepared_for_forked =
        prepare_commit(&forked, role_change_plan(GroupRole::Moderator)).unwrap();
    forked.mark_forked();
    assert_eq!(
        install_prepared_commit(&mut forked, prepared_for_forked),
        Err(GroupError::InvalidState)
    );
}

#[test]
fn treekem_commit_requires_update_path() {
    let state = GroupState::new_validated(crate::GroupStateConfig {
        group_id: group_id(),
        mode: GroupMode::Interactive,
        mechanism: MembershipMechanism::TreeKem,
        epoch: Epoch(1),
        state_version: crate::StateVersion(1),
        governance_policy: GovernancePolicy::single_signer(member(1)),
        mode_policy: ModePolicy::default(),
        roster: vec![entry(1, 1, GroupRole::Member)],
    })
    .unwrap();
    let plan = CommitPlan {
        committer: member(1),
        commit_nonce: [0x11; 32],
        change: CommitChange::TreeSelfUpdate {
            committer_member_id: member(1),
        },
        signatures: vec![signature(member(1))],
        update_path: None,
        direct_epoch_secret: None,
    };
    assert_eq!(
        prepare_commit(&state, plan).map(|_| ()),
        Err(GroupError::MissingUpdatePath)
    );
}

mod mutation_regressions;
