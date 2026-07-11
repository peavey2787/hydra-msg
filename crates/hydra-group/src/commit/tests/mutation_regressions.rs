use super::{entry, group_id, lite_state, member, role_change_plan, signature};
use crate::commit::validation::{
    validate_change_specific_signatures, validate_parent_for_change,
    verify_prepared_commit_integrity,
};
use crate::{
    prepare_commit, validate_governance_signatures, CommitChange, GovernancePolicy, GroupError,
    GroupMode, GroupRole, GroupState, MembershipMechanism, ModePolicy,
};
use hydra_core::types::Epoch;

fn create_change() -> CommitChange {
    CommitChange::Create {
        new_roster: vec![entry(1, 1, GroupRole::Member)],
        new_governance_policy: GovernancePolicy::single_signer(member(1)),
        new_mode_policy: ModePolicy::default(),
        new_tree_hash: [0; 64],
    }
}

#[test]
fn prepared_commit_integrity_rejects_each_independent_binding_change() {
    let state = lite_state();

    let mut encoded_tamper =
        prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
    encoded_tamper.encoded_core.push(0);
    assert_eq!(
        verify_prepared_commit_integrity(&encoded_tamper),
        Err(GroupError::InvalidCommitCore)
    );

    let mut digest_tamper = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
    digest_tamper.signature_digest[0] ^= 1;
    assert_eq!(
        verify_prepared_commit_integrity(&digest_tamper),
        Err(GroupError::InvalidCommitCore)
    );

    let mut hash_tamper = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
    hash_tamper.commit_hash[0] ^= 1;
    assert_eq!(
        verify_prepared_commit_integrity(&hash_tamper),
        Err(GroupError::InvalidCommitCore)
    );
}

#[test]
fn governance_threshold_rejects_one_valid_signature_when_two_are_required() {
    let policy = GovernancePolicy {
        policy_version: 1,
        threshold: 2,
        authorized_signers: vec![member(1), member(2)],
    };
    let roster = vec![
        entry(1, 1, GroupRole::Member),
        entry(2, 2, GroupRole::Member),
    ];
    assert_eq!(
        validate_governance_signatures(&policy, &roster, &[signature(member(1))]),
        Err(GroupError::InsufficientGovernanceSignatures)
    );
    assert!(validate_governance_signatures(
        &policy,
        &roster,
        &[signature(member(1)), signature(member(2))]
    )
    .is_ok());
}

#[test]
fn leave_change_requires_the_leaving_members_signature() {
    let change = CommitChange::Leave {
        member_id: member(1),
    };
    assert_eq!(
        validate_change_specific_signatures(&change, &[signature(member(2))]),
        Err(GroupError::InvalidCommitCore)
    );
    assert!(validate_change_specific_signatures(&change, &[signature(member(1))]).is_ok());
}

#[test]
fn create_parent_requires_each_zero_state_invariant_independently() {
    let committer = member(1);
    let change = create_change();
    let empty = GroupState::new_empty(
        group_id(),
        GroupMode::Lite,
        MembershipMechanism::DirectWrap,
        GovernancePolicy::single_signer(committer),
        ModePolicy::default(),
    )
    .unwrap();
    assert!(validate_parent_for_change(&empty, committer, &change).is_ok());

    let mut wrong_epoch = GroupState::new_empty(
        group_id(),
        GroupMode::Lite,
        MembershipMechanism::DirectWrap,
        GovernancePolicy::single_signer(committer),
        ModePolicy::default(),
    )
    .unwrap();
    wrong_epoch.epoch = Epoch(1);
    assert_eq!(
        validate_parent_for_change(&wrong_epoch, committer, &change),
        Err(GroupError::InvalidCommitParent)
    );

    let mut wrong_version = GroupState::new_empty(
        group_id(),
        GroupMode::Lite,
        MembershipMechanism::DirectWrap,
        GovernancePolicy::single_signer(committer),
        ModePolicy::default(),
    )
    .unwrap();
    wrong_version.state_version = crate::StateVersion(1);
    assert_eq!(
        validate_parent_for_change(&wrong_version, committer, &change),
        Err(GroupError::InvalidCommitParent)
    );

    let mut nonempty_roster = GroupState::new_empty(
        group_id(),
        GroupMode::Lite,
        MembershipMechanism::DirectWrap,
        GovernancePolicy::single_signer(committer),
        ModePolicy::default(),
    )
    .unwrap();
    nonempty_roster.roster.push(entry(1, 1, GroupRole::Member));
    assert_eq!(
        validate_parent_for_change(&nonempty_roster, committer, &change),
        Err(GroupError::InvalidCommitParent)
    );

    let mut nonzero_parent = GroupState::new_empty(
        group_id(),
        GroupMode::Lite,
        MembershipMechanism::DirectWrap,
        GovernancePolicy::single_signer(committer),
        ModePolicy::default(),
    )
    .unwrap();
    nonzero_parent.last_commit_hash[0] = 1;
    assert_eq!(
        validate_parent_for_change(&nonzero_parent, committer, &change),
        Err(GroupError::InvalidCommitParent)
    );
}

#[test]
fn leave_and_tree_self_update_are_bound_to_the_committer() {
    let state = lite_state();
    let committer = member(1);

    assert!(validate_parent_for_change(
        &state,
        committer,
        &CommitChange::Leave {
            member_id: committer,
        }
    )
    .is_ok());
    assert_eq!(
        validate_parent_for_change(
            &state,
            committer,
            &CommitChange::Leave {
                member_id: member(2),
            }
        ),
        Err(GroupError::InvalidCommitCore)
    );

    assert!(validate_parent_for_change(
        &state,
        committer,
        &CommitChange::TreeSelfUpdate {
            committer_member_id: committer,
        }
    )
    .is_ok());
    assert_eq!(
        validate_parent_for_change(
            &state,
            committer,
            &CommitChange::TreeSelfUpdate {
                committer_member_id: member(2),
            }
        ),
        Err(GroupError::InvalidCommitCore)
    );
}
