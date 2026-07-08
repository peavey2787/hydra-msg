use crate::{roster_hash, GroupMode, GroupResult, MemberStatus, RosterEntry};

pub(super) fn active_sender_entries(mode: GroupMode, roster: &[RosterEntry]) -> Vec<&RosterEntry> {
    roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active && entry.role.can_send_in_mode(mode))
        .collect()
}

pub(super) fn compute_roster_hash(
    mode: GroupMode,
    roster: &[RosterEntry],
) -> GroupResult<[u8; 64]> {
    roster_hash(&crate::encode_roster(mode, roster)?)
}
