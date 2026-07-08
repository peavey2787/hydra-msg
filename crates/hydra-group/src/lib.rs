//! Epoch-based group messaging and TreeKEM-style rekey implementation.
//!
//! M7 starts by making this crate a first-class checked workspace member. The
//! remaining M7 slices replace the explicit `Unsupported` guardrails with the
//! full group commit, TreeKEM, sender-chain, and welcome machinery.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod commit;
pub mod distribution;
pub mod epoch;
pub mod error;
pub mod membership;
pub mod message;
pub mod private_path;
pub mod public_tree;
pub mod rekey;
pub mod state;
pub mod types;
pub mod validation;

pub use canonical::{
    change_payload_hash, checked_u16_be, checked_u32_be, commit_confirmation_tag, commit_hash,
    commit_sig_digest, direct_wrap_key_schedule_commitment, encode_change_payload,
    encode_commit_core, encode_governance_policy, encode_mode_policy, encode_roster,
    encode_roster_entry, encode_signature_set, governance_policy_hash, lp, member_id,
    mode_policy_hash, roster_hash, treekem_key_schedule_commitment, u16_be, u32_be, u64_be,
    validate_governance_policy, validate_roster_for_canonical_encoding, validate_signature_set,
    verify_commit_confirmation_tag, ChangePayload, CommitCore, CommitSignature, COMMIT_CORE_SIZE,
    MODE_POLICY_SIZE, ROSTER_ENTRY_SIZE,
};
pub use commit::{
    apply_prepared_commit, install_prepared_commit, prepare_commit, validate_governance_signatures,
    CommitChange, CommitInstallResult, CommitPlan, PreparedCommit,
};
pub use distribution::{
    encode_update_path, encrypt_path_updates, resolve_subtree, resolve_update_path_targets,
    update_path_hash, wrap_context, PathCiphertext, PathSecretTarget, ResolvedPathTarget,
    TreeKemWrapContext, UpdatePath, WRAPPED_PATH_SECRET_SIZE,
};
pub use epoch::{
    derive_epoch_key, derive_epoch_key_for_context, derive_sender_chain_key,
    derive_sender_message_step, next_epoch, sender_chain_commitment, EpochKeyContext,
    SenderMessageStep,
};
pub use error::{GroupError, GroupResult};
pub use message::{
    group_data_signature_digest, identity_fingerprint, GroupOutboundMessage, GroupReceivedMessage,
};
pub use private_path::{
    derive_and_install_path, parent_path, DerivedPublicPathNode, PrivatePath,
    PrivatePathNodeSecret, TreeKemPathContext, TreeKemPathUpdate,
};
pub use public_tree::{
    copath, direct_path, leaf_capacity_for_mode, leaf_node_index, left_child, occupied_leaf_hash,
    parent_index, parent_node_hash, right_child, sibling_index, vacant_leaf_hash,
    validate_node_key_flag, AffectedPathHash, PublicLeaf, PublicNodeKey, PublicTree,
    PublicTreeNode, NODE_KEY_ABSENT, NODE_KEY_PRESENT, ROOT_NODE_INDEX,
};
pub use state::{
    AcceptedGroupMessage, GroupReplayState, GroupReplayStateSnapshot, GroupState, GroupStateConfig,
    GroupStateSnapshot, MembershipPrivateState, MembershipPrivateStateSnapshot,
    PrivatePathNodeSecretSnapshot, SenderChainCursor, SenderChainCursorSnapshot, SenderChainState,
    SenderChainStateSnapshot, SenderReplayState, SenderReplayStateSnapshot,
    SkippedGroupMessageKeySnapshot,
};
pub use types::{
    mechanism_for_mode, validate_mode_mechanism, CommitKind, GovernancePolicy, GroupContext,
    GroupMode, GroupPhase, GroupRole, MemberId, MemberStatus, MembershipMechanism, ModePolicy,
    RosterEntry, StateVersion,
};

pub use validation::{
    ensure_active_member, ensure_member_absent, ensure_sender_allowed, roster_stats,
    validate_governance_for_roster, validate_roster_for_mode, RosterStats,
};

#[cfg(test)]
mod tests {
    use crate::{
        epoch::next_epoch, rekey::rekey_path, validate_mode_mechanism, CommitKind,
        GovernancePolicy, GroupError, GroupMode, GroupPhase, GroupRole, GroupState, MemberId,
        MemberStatus, MembershipMechanism, ModePolicy,
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

    fn active_entry(
        member_value: u8,
        fingerprint_value: u8,
        role: GroupRole,
    ) -> crate::RosterEntry {
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

    fn removed_entry(
        member_value: u8,
        fingerprint_value: u8,
        role: GroupRole,
    ) -> crate::RosterEntry {
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
}
