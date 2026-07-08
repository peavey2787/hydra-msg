use hydra_core::types::{Epoch, Secret32};

use crate::{
    roster_hash, validate_governance_for_roster, validate_mode_mechanism, validate_roster_for_mode,
    CommitKind, GroupError, GroupResult, GroupState, MemberStatus, MembershipMechanism,
    StateVersion,
};

use super::{
    membership::{mark_removed, prune_removed_governance_signer, remap_roster_slots_for_mode},
    tree_update::apply_update_path_to_public_tree,
    types::{CandidateState, CommitChange, CommitPlan},
};

pub(crate) fn build_transition(
    state: &GroupState,
    plan: &CommitPlan,
) -> GroupResult<CandidateState> {
    let (new_epoch, new_state_version) = next_transition_counters(state, plan.change.kind())?;
    let mut mode = state.mode;
    let mut mechanism = state.mechanism;
    let mut roster = state.roster.clone();
    let mut governance_policy = state.governance_policy.clone();
    let mut mode_policy = state.mode_policy;
    let mut tree_hash = state.tree_hash;
    let mut public_tree = None;
    let mut direct_epoch_secret = None;

    match &plan.change {
        CommitChange::Create {
            new_roster,
            new_governance_policy,
            new_mode_policy,
            new_tree_hash,
        } => {
            roster = new_roster.clone();
            governance_policy = new_governance_policy.clone();
            mode_policy = *new_mode_policy;
            tree_hash = *new_tree_hash;
        }
        CommitChange::Join { new_entry } => {
            if roster
                .iter()
                .any(|entry| entry.member_id == new_entry.member_id)
            {
                return Err(GroupError::MemberAlreadyExists {
                    member_id: new_entry.member_id,
                });
            }
            roster.push(new_entry.clone());
        }
        CommitChange::Leave { member_id } => {
            mark_removed(&mut roster, *member_id, new_epoch)?;
            prune_removed_governance_signer(&mut governance_policy, *member_id);
        }
        CommitChange::RemoveOrRevoke { member_id, .. } => {
            mark_removed(&mut roster, *member_id, new_epoch)?;
            prune_removed_governance_signer(&mut governance_policy, *member_id);
        }
        CommitChange::GovernanceChange {
            new_governance_policy,
        } => {
            governance_policy = new_governance_policy.clone();
        }
        CommitChange::IdentityRotate {
            old_member_id,
            new_entry,
            ..
        } => {
            mark_removed(&mut roster, *old_member_id, new_epoch)?;
            if roster
                .iter()
                .any(|entry| entry.member_id == new_entry.member_id)
            {
                return Err(GroupError::MemberAlreadyExists {
                    member_id: new_entry.member_id,
                });
            }
            roster.push(new_entry.clone());
        }
        CommitChange::RoleChange {
            member_id,
            new_role,
        } => {
            if !new_role.is_active_in_mode(mode) {
                return Err(GroupError::InvalidRoleForMode {
                    mode,
                    role: *new_role,
                });
            }
            let entry = roster
                .iter_mut()
                .find(|entry| entry.member_id == *member_id)
                .ok_or(GroupError::MemberNotFound {
                    member_id: *member_id,
                })?;
            if entry.status != MemberStatus::Active {
                return Err(GroupError::MemberInactive {
                    member_id: *member_id,
                });
            }
            entry.role = *new_role;
        }
        CommitChange::ModeChange {
            new_mode,
            new_mode_policy,
        } => {
            mode = *new_mode;
            mechanism = new_mode.required_mechanism();
            mode_policy = *new_mode_policy;
            remap_roster_slots_for_mode(mode, &mut roster)?;
            if mechanism == MembershipMechanism::DirectWrap {
                tree_hash = [0; 64];
            }
        }
        CommitChange::TreeSelfUpdate { .. } => {}
    }

    validate_mode_mechanism(mode, mechanism)?;
    validate_roster_for_mode(mode, new_epoch, &roster)?;
    validate_governance_for_roster(&governance_policy, &roster)?;
    let encoded_roster = crate::encode_roster(mode, &roster)?;
    let roster_hash = roster_hash(&encoded_roster)?;

    match mechanism {
        MembershipMechanism::TreeKem => {
            if plan.change.kind() != CommitKind::Create {
                let update_path = plan
                    .update_path
                    .as_ref()
                    .ok_or(GroupError::MissingUpdatePath)?;
                tree_hash = update_path.candidate_tree_hash;
                public_tree = apply_update_path_to_public_tree(state, update_path, &plan.change)?;
            }
        }
        MembershipMechanism::DirectWrap => {
            let secret = plan
                .direct_epoch_secret
                .ok_or(GroupError::MissingEpochSecret)?;
            direct_epoch_secret = Some(Secret32::new(secret));
        }
    }

    Ok(CandidateState {
        mode,
        mechanism,
        epoch: new_epoch,
        state_version: new_state_version,
        roster,
        roster_hash,
        tree_hash,
        governance_policy,
        mode_policy,
        public_tree,
        direct_epoch_secret,
    })
}

fn next_transition_counters(
    state: &GroupState,
    kind: CommitKind,
) -> GroupResult<(Epoch, StateVersion)> {
    if kind == CommitKind::Create {
        if state.epoch.0 != 0 || state.state_version.0 != 0 {
            return Err(GroupError::InvalidCommitParent);
        }
        return Ok((Epoch(0), StateVersion(0)));
    }
    let epoch = state
        .epoch
        .0
        .checked_add(1)
        .map(Epoch)
        .ok_or(GroupError::CounterExhausted)?;
    let state_version = state
        .state_version
        .0
        .checked_add(1)
        .map(StateVersion)
        .ok_or(GroupError::CounterExhausted)?;
    Ok((epoch, state_version))
}
