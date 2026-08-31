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
