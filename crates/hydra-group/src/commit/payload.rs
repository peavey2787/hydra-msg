use crate::{GroupError, GroupResult, GroupState};

use super::types::CommitChange;

pub(crate) fn build_change_payload<'a>(
    state: &'a GroupState,
    change: &'a CommitChange,
) -> GroupResult<crate::ChangePayload<'a>> {
    match change {
        CommitChange::Create {
            new_governance_policy,
            new_mode_policy,
            ..
        } => Ok(crate::ChangePayload::Create {
            new_governance_policy,
            new_mode_policy: *new_mode_policy,
        }),
        CommitChange::Join { new_entry } => Ok(crate::ChangePayload::Join { new_entry }),
        CommitChange::Leave { member_id } => Ok(crate::ChangePayload::Leave {
            member_id: *member_id,
        }),
        CommitChange::RemoveOrRevoke {
            member_id,
            reason_code,
        } => Ok(crate::ChangePayload::RemoveOrRevoke {
            member_id: *member_id,
            reason_code: *reason_code,
        }),
        CommitChange::GovernanceChange {
            new_governance_policy,
        } => Ok(crate::ChangePayload::GovernanceChange {
            new_governance_policy,
        }),
        CommitChange::IdentityRotate {
            old_member_id,
            new_entry,
            rotation_digest,
        } => Ok(crate::ChangePayload::IdentityRotate {
            old_member_id: *old_member_id,
            new_entry,
            rotation_digest: *rotation_digest,
        }),
        CommitChange::RoleChange {
            member_id,
            new_role,
        } => {
            let old_role = state
                .roster
                .iter()
                .find(|entry| entry.member_id == *member_id)
                .ok_or(GroupError::MemberNotFound {
                    member_id: *member_id,
                })?
                .role;
            Ok(crate::ChangePayload::RoleChange {
                member_id: *member_id,
                old_role,
                new_role: *new_role,
            })
        }
        CommitChange::ModeChange {
            new_mode,
            new_mode_policy,
        } => Ok(crate::ChangePayload::ModeChange {
            old_mode: state.mode,
            new_mode: *new_mode,
            new_mode_policy: *new_mode_policy,
        }),
        CommitChange::TreeSelfUpdate {
            committer_member_id,
        } => Ok(crate::ChangePayload::TreeSelfUpdate {
            committer_member_id: *committer_member_id,
        }),
    }
}
