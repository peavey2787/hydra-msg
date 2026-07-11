use super::*;

#[test]
fn crate_is_checked_as_a_workspace_member() {
    assert_eq!(next_epoch(Epoch(0)), Ok(Epoch(1)));
}

#[test]
fn epoch_overflow_rejects_instead_of_saturating() {
    assert_eq!(
        next_epoch(Epoch(u64::MAX)),
        Err(GroupError::CounterExhausted)
    );
}

#[test]
fn empty_rekey_path_rejects_without_panicking() {
    let mut tree = crate::public_tree::PublicTree::default();
    let mut path = crate::private_path::PrivatePath::default();
    assert_eq!(
        rekey_path(&mut tree, &mut path),
        Err(GroupError::InvalidTreePath)
    );
}

#[test]
fn group_modes_and_mechanisms_round_trip_and_reject_unknowns() {
    for mode in [
        GroupMode::Interactive,
        GroupMode::Broadcast,
        GroupMode::Lite,
    ] {
        assert_eq!(GroupMode::try_from(mode as u8), Ok(mode));
    }
    for mechanism in [
        MembershipMechanism::TreeKem,
        MembershipMechanism::DirectWrap,
    ] {
        assert_eq!(
            MembershipMechanism::try_from(mechanism as u8),
            Ok(mechanism)
        );
    }

    for value in [0x00, 0x04, 0xff] {
        assert!(GroupMode::try_from(value).is_err());
    }
    for value in [0x00, 0x03, 0xff] {
        assert!(MembershipMechanism::try_from(value).is_err());
    }
}

#[test]
fn group_roles_statuses_commit_kinds_and_phases_round_trip_and_reject_unknowns() {
    for role in [
        GroupRole::Member,
        GroupRole::Presenter,
        GroupRole::Moderator,
        GroupRole::Audience,
    ] {
        assert_eq!(GroupRole::try_from(role as u8), Ok(role));
    }
    for status in [MemberStatus::Active, MemberStatus::Removed] {
        assert_eq!(MemberStatus::try_from(status as u8), Ok(status));
    }
    for kind in [
        CommitKind::Create,
        CommitKind::Join,
        CommitKind::Leave,
        CommitKind::RemoveOrRevoke,
        CommitKind::GovernanceChange,
        CommitKind::IdentityRotate,
        CommitKind::RoleChange,
        CommitKind::ModeChange,
        CommitKind::TreeSelfUpdate,
    ] {
        assert_eq!(CommitKind::try_from(kind as u8), Ok(kind));
    }
    for phase in [GroupPhase::Active, GroupPhase::Forked, GroupPhase::Closed] {
        assert_eq!(GroupPhase::try_from(phase as u8), Ok(phase));
    }

    for value in [0x00, 0x05, 0xff] {
        assert!(GroupRole::try_from(value).is_err());
    }
    for value in [0x00, 0x03, 0xff] {
        assert!(MemberStatus::try_from(value).is_err());
    }
    for value in [0x00, 0x0a, 0xff] {
        assert!(CommitKind::try_from(value).is_err());
    }
    for value in [0x00, 0x04, 0xff] {
        assert!(GroupPhase::try_from(value).is_err());
    }
}

#[test]
fn mode_mechanism_pairing_is_closed_and_exact() {
    assert_eq!(
        validate_mode_mechanism(GroupMode::Interactive, MembershipMechanism::TreeKem),
        Ok(())
    );
    assert_eq!(
        validate_mode_mechanism(GroupMode::Broadcast, MembershipMechanism::TreeKem),
        Ok(())
    );
    assert_eq!(
        validate_mode_mechanism(GroupMode::Lite, MembershipMechanism::DirectWrap),
        Ok(())
    );

    assert_eq!(
        validate_mode_mechanism(GroupMode::Interactive, MembershipMechanism::DirectWrap),
        Err(GroupError::InvalidModeMechanism {
            mode: GroupMode::Interactive,
            mechanism: MembershipMechanism::DirectWrap,
        })
    );
    assert_eq!(
        validate_mode_mechanism(GroupMode::Broadcast, MembershipMechanism::DirectWrap),
        Err(GroupError::InvalidModeMechanism {
            mode: GroupMode::Broadcast,
            mechanism: MembershipMechanism::DirectWrap,
        })
    );
    assert_eq!(
        validate_mode_mechanism(GroupMode::Lite, MembershipMechanism::TreeKem),
        Err(GroupError::InvalidModeMechanism {
            mode: GroupMode::Lite,
            mechanism: MembershipMechanism::TreeKem,
        })
    );
}
