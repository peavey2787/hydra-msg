use hydra_core::types::{Epoch, Secret32};

use crate::{
    GovernancePolicy, GroupError, GroupMode, GroupResult, GroupState, MemberId, MemberStatus,
    MembershipMechanism, MembershipPrivateState, PublicTree, RosterEntry,
};

use super::types::CommitChange;

pub(crate) fn mark_removed(
    roster: &mut [RosterEntry],
    member_id: MemberId,
    removed_epoch: Epoch,
) -> GroupResult<()> {
    let entry = roster
        .iter_mut()
        .find(|entry| entry.member_id == member_id)
        .ok_or(GroupError::MemberNotFound { member_id })?;
    if entry.status != MemberStatus::Active {
        return Err(GroupError::MemberInactive { member_id });
    }
    entry.status = MemberStatus::Removed;
    entry.removed_epoch = removed_epoch;
    Ok(())
}

pub(crate) fn prune_removed_governance_signer(policy: &mut GovernancePolicy, member_id: MemberId) {
    policy
        .authorized_signers
        .retain(|authorized| *authorized != member_id);
}

pub(crate) fn removed_member_for_change(change: &CommitChange) -> Option<MemberId> {
    match change {
        CommitChange::Leave { member_id } | CommitChange::RemoveOrRevoke { member_id, .. } => {
            Some(*member_id)
        }
        _ => None,
    }
}

pub(crate) fn remap_roster_slots_for_mode(
    mode: GroupMode,
    roster: &mut [RosterEntry],
) -> GroupResult<()> {
    let mut active_indices = roster
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry.status == MemberStatus::Active).then_some(index))
        .collect::<Vec<_>>();
    active_indices.sort_by_key(|index| roster[*index].member_id.0);
    match mode.required_mechanism() {
        MembershipMechanism::TreeKem => {
            if active_indices.len() > mode.max_roster_entries() {
                return Err(GroupError::InvalidRoster);
            }
            for (slot, index) in active_indices.into_iter().enumerate() {
                roster[index].tree_leaf_slot =
                    u32::try_from(slot).map_err(|_| GroupError::CounterExhausted)?;
            }
        }
        MembershipMechanism::DirectWrap => {
            for index in active_indices {
                roster[index].tree_leaf_slot = u32::MAX;
            }
        }
    }
    Ok(())
}

pub(crate) fn install_membership_material(
    state: &mut GroupState,
    public_tree: Option<PublicTree>,
    direct_epoch_secret: Option<Secret32>,
) {
    match (state.mechanism, public_tree, direct_epoch_secret) {
        (MembershipMechanism::TreeKem, Some(public_tree), _) => match &mut state.membership {
            MembershipPrivateState::TreeKem {
                public_tree: current,
                ..
            } => *current = public_tree,
            _ => {
                state.membership = MembershipPrivateState::TreeKem {
                    public_tree,
                    private_path: crate::PrivatePath::default(),
                };
            }
        },
        (MembershipMechanism::DirectWrap, _, Some(epoch_secret)) => {
            state.membership = MembershipPrivateState::DirectWrap { epoch_secret };
        }
        _ => {}
    }
}
