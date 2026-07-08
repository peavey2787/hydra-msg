use crate::{
    direct_wrap_key_schedule_commitment, treekem_key_schedule_commitment, update_path_hash,
    CommitKind, GroupError, GroupResult, GroupState, MembershipMechanism,
};

use super::types::{CandidateState, CommitPlan};

pub(crate) fn key_schedule_commitment(
    state: &GroupState,
    transition: &CandidateState,
    plan: &CommitPlan,
) -> GroupResult<[u8; 64]> {
    match transition.mechanism {
        MembershipMechanism::TreeKem => {
            if plan.change.kind() == CommitKind::Create {
                Ok(treekem_key_schedule_commitment(
                    state.group_id,
                    transition.mode,
                    transition.epoch,
                    transition.tree_hash,
                    [0; 64],
                ))
            } else {
                let update_hash = update_path_hash(
                    plan.update_path
                        .as_ref()
                        .ok_or(GroupError::MissingUpdatePath)?,
                )?;
                Ok(treekem_key_schedule_commitment(
                    state.group_id,
                    transition.mode,
                    transition.epoch,
                    transition.tree_hash,
                    update_hash,
                ))
            }
        }
        MembershipMechanism::DirectWrap => {
            let secret = transition
                .direct_epoch_secret
                .as_ref()
                .ok_or(GroupError::MissingEpochSecret)?;
            Ok(direct_wrap_key_schedule_commitment(
                state.group_id,
                transition.mode,
                transition.epoch,
                plan.commit_nonce,
                secret,
            ))
        }
    }
}
