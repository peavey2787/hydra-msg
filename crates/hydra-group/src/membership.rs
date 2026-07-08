use crate::{MemberId, MemberStatus, RosterEntry};
use hydra_core::types::Epoch;

pub fn find_member(members: &[RosterEntry], member_id: MemberId) -> Option<&RosterEntry> {
    members.iter().find(|member| member.member_id == member_id)
}

pub fn deactivate_member(members: &mut [RosterEntry], member_id: MemberId, removed_epoch: Epoch) {
    if let Some(member) = members
        .iter_mut()
        .find(|member| member.member_id == member_id)
    {
        member.status = MemberStatus::Removed;
        member.removed_epoch = removed_epoch;
    }
}
