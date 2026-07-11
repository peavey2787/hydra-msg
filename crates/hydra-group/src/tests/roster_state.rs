use super::*;

#[test]
fn mode_mechanism_mismatch_preserves_group_state() {
    let mut state = GroupState::new_empty(
        group_id(),
        GroupMode::Interactive,
        MembershipMechanism::TreeKem,
        governance(),
        ModePolicy::default(),
    )
    .unwrap();
    state.epoch = Epoch(9);
    state.state_version.0 = 11;
    state.last_commit_hash = [0xa5; 64];

    let before = (
        state.mode,
        state.mechanism,
        state.epoch,
        state.state_version,
        state.last_commit_hash,
        state.phase,
    );
    assert_eq!(
        state.set_mode_and_mechanism(GroupMode::Lite, MembershipMechanism::TreeKem),
        Err(GroupError::InvalidModeMechanism {
            mode: GroupMode::Lite,
            mechanism: MembershipMechanism::TreeKem,
        })
    );
    let after = (
        state.mode,
        state.mechanism,
        state.epoch,
        state.state_version,
        state.last_commit_hash,
        state.phase,
    );
    assert_eq!(after, before);
}

#[test]
fn active_role_sets_match_the_mode_rules() {
    assert!(GroupRole::Member.is_active_in_mode(GroupMode::Interactive));
    assert!(GroupRole::Moderator.is_active_in_mode(GroupMode::Interactive));
    assert!(!GroupRole::Presenter.is_active_in_mode(GroupMode::Interactive));
    assert!(!GroupRole::Audience.is_active_in_mode(GroupMode::Interactive));

    assert!(GroupRole::Presenter.is_active_in_mode(GroupMode::Broadcast));
    assert!(GroupRole::Moderator.is_active_in_mode(GroupMode::Broadcast));
    assert!(GroupRole::Audience.is_active_in_mode(GroupMode::Broadcast));
    assert!(!GroupRole::Member.is_active_in_mode(GroupMode::Broadcast));
    assert!(!GroupRole::Audience.can_send_in_mode(GroupMode::Broadcast));

    assert!(GroupRole::Member.is_active_in_mode(GroupMode::Lite));
    assert!(GroupRole::Moderator.is_active_in_mode(GroupMode::Lite));
    assert!(!GroupRole::Presenter.is_active_in_mode(GroupMode::Lite));
    assert!(!GroupRole::Audience.is_active_in_mode(GroupMode::Lite));
}

#[test]
fn validated_group_state_accepts_canonical_active_roster_and_hashes_it() {
    let state = interactive_state();
    assert_eq!(state.roster.len(), 1);
    assert_ne!(state.roster_hash, [0; 64]);
    assert_eq!(
        state.require_sender(member(1)).unwrap().member_id,
        member(1)
    );
}

#[test]
fn active_roles_are_validated_by_mode_but_removed_history_is_retained() {
    assert_eq!(
        crate::validate_roster_for_mode(
            GroupMode::Interactive,
            Epoch(2),
            &[active_entry(1, 1, GroupRole::Presenter)]
        ),
        Err(GroupError::InvalidRoleForMode {
            mode: GroupMode::Interactive,
            role: GroupRole::Presenter,
        })
    );

    let roster = vec![
        active_entry(1, 1, GroupRole::Member),
        removed_entry(2, 2, GroupRole::Presenter),
    ];
    assert!(crate::validate_roster_for_mode(GroupMode::Interactive, Epoch(2), &roster).is_ok());
}

#[test]
fn broadcast_presenter_boundary_is_enforced() {
    let mut sixteen = (1..=16)
        .map(|value| active_entry(value, value, GroupRole::Presenter))
        .collect::<Vec<_>>();
    assert!(crate::validate_roster_for_mode(GroupMode::Broadcast, Epoch(1), &sixteen).is_ok());

    sixteen.push(active_entry(17, 17, GroupRole::Presenter));
    assert_eq!(
        crate::validate_roster_for_mode(GroupMode::Broadcast, Epoch(1), &sixteen),
        Err(GroupError::InvalidRoster)
    );
}

#[test]
fn governance_signers_must_be_active_roster_members() {
    let roster = vec![active_entry(1, 1, GroupRole::Member)];
    assert!(crate::validate_governance_for_roster(&governance(), &roster).is_ok());

    let missing = GovernancePolicy::single_signer(member(2));
    assert_eq!(
        crate::validate_governance_for_roster(&missing, &roster),
        Err(GroupError::InvalidGovernanceSigner { signer: member(2) })
    );

    let removed = vec![removed_entry(1, 1, GroupRole::Member)];
    assert_eq!(
        crate::validate_governance_for_roster(&governance(), &removed),
        Err(GroupError::InvalidGovernanceSigner { signer: member(1) })
    );
}

#[test]
fn roster_replacement_rejects_invalid_candidate_without_mutation() {
    let mut state = interactive_state();
    let before = (state.roster.clone(), state.roster_hash);
    let invalid = vec![active_entry(2, 2, GroupRole::Presenter)];
    assert_eq!(
        state.replace_roster(invalid),
        Err(GroupError::InvalidRoleForMode {
            mode: GroupMode::Interactive,
            role: GroupRole::Presenter,
        })
    );
    assert_eq!((state.roster.clone(), state.roster_hash), before);
}

#[test]
fn add_remove_and_role_change_validate_before_commit() {
    let mut state = interactive_state();
    assert_eq!(
        state.add_member(active_entry(1, 9, GroupRole::Member)),
        Err(GroupError::MemberAlreadyExists {
            member_id: member(1)
        })
    );
    assert_eq!(state.roster.len(), 1);

    state
        .add_member(active_entry(2, 2, GroupRole::Moderator))
        .unwrap();
    assert_eq!(state.roster.len(), 2);
    let hash_after_add = state.roster_hash;
    assert_eq!(
        state.change_member_role(member(2), GroupRole::Presenter),
        Err(GroupError::InvalidRoleForMode {
            mode: GroupMode::Interactive,
            role: GroupRole::Presenter,
        })
    );
    assert_eq!(state.roster_hash, hash_after_add);

    state
        .change_member_role(member(2), GroupRole::Member)
        .unwrap();
    assert_eq!(
        state
            .roster
            .iter()
            .find(|entry| entry.member_id == member(2))
            .unwrap()
            .role,
        GroupRole::Member
    );
    assert_eq!(
        state.remove_member(member(2), Epoch(1)),
        Err(GroupError::InvalidRoster)
    );
    state.remove_member(member(2), Epoch(2)).unwrap();
    assert_eq!(
        state.remove_member(member(2), Epoch(3)),
        Err(GroupError::MemberInactive {
            member_id: member(2)
        })
    );
}

#[test]
fn broadcast_audience_is_active_but_not_send_capable() {
    let state = GroupState::new_validated(crate::GroupStateConfig {
        group_id: group_id(),
        mode: GroupMode::Broadcast,
        mechanism: MembershipMechanism::TreeKem,
        epoch: Epoch(1),
        state_version: crate::StateVersion(0),
        governance_policy: GovernancePolicy::single_signer(member(1)),
        mode_policy: ModePolicy::default(),
        roster: vec![
            active_entry(1, 1, GroupRole::Moderator),
            active_entry(2, 2, GroupRole::Audience),
        ],
    })
    .unwrap();
    assert!(crate::ensure_active_member(&state.roster, member(2)).is_ok());
    assert_eq!(
        state.require_sender(member(2)),
        Err(GroupError::SenderNotAllowed {
            member_id: member(2)
        })
    );
}
