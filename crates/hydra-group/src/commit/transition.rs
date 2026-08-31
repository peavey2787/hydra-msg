use hydra_core::types::{Epoch, Secret32};

use crate::{
    roster_hash, validate_governance_for_roster, validate_mode_mechanism, validate_roster_for_mode,
    CommitKind, GovernancePolicy, GroupError, GroupMode, GroupResult, GroupRole, GroupState,
    MemberId, MemberStatus, MembershipMechanism, ModePolicy, RosterEntry, StateVersion,
};

use super::{
    membership::{mark_removed, prune_removed_governance_signer, remap_roster_slots_for_mode},
    tree_update::apply_update_path_to_public_tree,
    types::{CandidateState, CommitChange, CommitPlan},
};

struct TransitionDraft {
    mode: GroupMode,
    mechanism: MembershipMechanism,
    roster: Vec<RosterEntry>,
    governance_policy: GovernancePolicy,
    mode_policy: ModePolicy,
    tree_hash: [u8; 64],
}

impl TransitionDraft {
    fn from_state(state: &GroupState) -> Self {
        Self {
            mode: state.mode,
            mechanism: state.mechanism,
            roster: state.roster.clone(),
            governance_policy: state.governance_policy.clone(),
            mode_policy: state.mode_policy,
            tree_hash: state.tree_hash,
        }
    }
}

pub(crate) fn build_transition(
    state: &GroupState,
    plan: &CommitPlan,
) -> GroupResult<CandidateState> {
    let (new_epoch, new_state_version) = next_transition_counters(state, plan.change.kind())?;
    let mut draft = TransitionDraft::from_state(state);
    let mut public_tree = None;
    let mut direct_epoch_secret = None;

    apply_commit_change(&mut draft, &plan.change, new_epoch)?;
    validate_mode_mechanism(draft.mode, draft.mechanism)?;
    validate_roster_for_mode(draft.mode, new_epoch, &draft.roster)?;
    validate_governance_for_roster(&draft.governance_policy, &draft.roster)?;
    let encoded_roster = crate::encode_roster(draft.mode, &draft.roster)?;
    let roster_hash = roster_hash(&encoded_roster)?;

    apply_membership_material(
        state,
        plan,
        draft.mechanism,
        &mut draft.tree_hash,
        &mut public_tree,
        &mut direct_epoch_secret,
    )?;

    Ok(CandidateState {
        mode: draft.mode,
        mechanism: draft.mechanism,
        epoch: new_epoch,
        state_version: new_state_version,
        roster: draft.roster,
        roster_hash,
        tree_hash: draft.tree_hash,
        governance_policy: draft.governance_policy,
        mode_policy: draft.mode_policy,
        public_tree,
        direct_epoch_secret,
    })
}

fn apply_commit_change(
    draft: &mut TransitionDraft,
    change: &CommitChange,
    new_epoch: Epoch,
) -> GroupResult<()> {
    match change {
        CommitChange::Create {
            new_roster,
            new_governance_policy,
            new_mode_policy,
            new_tree_hash,
        } => {
            draft.roster = new_roster.clone();
            draft.governance_policy = new_governance_policy.clone();
            draft.mode_policy = *new_mode_policy;
            draft.tree_hash = *new_tree_hash;
        }
        CommitChange::Join { new_entry } => add_member(&mut draft.roster, new_entry)?,
        CommitChange::Leave { member_id } | CommitChange::RemoveOrRevoke { member_id, .. } => {
            mark_removed(&mut draft.roster, *member_id, new_epoch)?;
            prune_removed_governance_signer(&mut draft.governance_policy, *member_id);
        }
        CommitChange::GovernanceChange {
            new_governance_policy,
        } => {
            draft.governance_policy = new_governance_policy.clone();
        }
        CommitChange::IdentityRotate {
            old_member_id,
            new_entry,
            ..
        } => {
            mark_removed(&mut draft.roster, *old_member_id, new_epoch)?;
            add_member(&mut draft.roster, new_entry)?;
        }
        CommitChange::RoleChange {
            member_id,
            new_role,
        } => {
            change_member_role(draft.mode, &mut draft.roster, *member_id, *new_role)?;
        }
        CommitChange::ModeChange {
            new_mode,
            new_mode_policy,
        } => {
            draft.mode_policy = *new_mode_policy;
            apply_mode_change(draft, *new_mode)?;
        }
        CommitChange::TreeSelfUpdate { .. } => {}
    }
    Ok(())
}

fn add_member(roster: &mut Vec<RosterEntry>, new_entry: &RosterEntry) -> GroupResult<()> {
    if roster
        .iter()
        .any(|entry| entry.member_id == new_entry.member_id)
    {
        return Err(GroupError::MemberAlreadyExists {
            member_id: new_entry.member_id,
        });
    }
    roster.push(new_entry.clone());
    Ok(())
}

fn change_member_role(
    mode: GroupMode,
    roster: &mut [RosterEntry],
    member_id: MemberId,
    new_role: GroupRole,
) -> GroupResult<()> {
    if !new_role.is_active_in_mode(mode) {
        return Err(GroupError::InvalidRoleForMode {
            mode,
            role: new_role,
        });
    }
    let entry = roster
        .iter_mut()
        .find(|entry| entry.member_id == member_id)
        .ok_or(GroupError::MemberNotFound { member_id })?;
    if entry.status != MemberStatus::Active {
        return Err(GroupError::MemberInactive { member_id });
    }
    entry.role = new_role;
    Ok(())
}

fn apply_mode_change(draft: &mut TransitionDraft, new_mode: GroupMode) -> GroupResult<()> {
    draft.mode = new_mode;
    draft.mechanism = new_mode.required_mechanism();
    remap_roster_slots_for_mode(new_mode, &mut draft.roster)?;
    if draft.mechanism == MembershipMechanism::DirectWrap {
        draft.tree_hash = [0; 64];
    }
    Ok(())
}

fn apply_membership_material(
    state: &GroupState,
    plan: &CommitPlan,
    mechanism: MembershipMechanism,
    tree_hash: &mut [u8; 64],
    public_tree: &mut Option<crate::PublicTree>,
    direct_epoch_secret: &mut Option<Secret32>,
) -> GroupResult<()> {
    match mechanism {
        MembershipMechanism::TreeKem => {
            if plan.change.kind() != CommitKind::Create {
                let update_path = plan
                    .update_path
                    .as_ref()
                    .ok_or(GroupError::MissingUpdatePath)?;
                *tree_hash = update_path.candidate_tree_hash;
                *public_tree = apply_update_path_to_public_tree(state, update_path, &plan.change)?;
            }
        }
        MembershipMechanism::DirectWrap => {
            let secret = plan
                .direct_epoch_secret
                .ok_or(GroupError::MissingEpochSecret)?;
            *direct_epoch_secret = Some(Secret32::new(secret));
        }
    }
    Ok(())
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
