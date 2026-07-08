use hydra_core::{types::Epoch, MAX_BROADCAST_PRESENTERS};

use crate::{
    canonical::{validate_governance_policy, validate_roster_for_canonical_encoding},
    GovernancePolicy, GroupError, GroupMode, GroupResult, GroupRole, MemberId, MemberStatus,
    RosterEntry,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RosterStats {
    pub total: usize,
    pub active: usize,
    pub removed: usize,
    pub send_capable: usize,
    pub broadcast_presenters: usize,
    pub moderators: usize,
}

#[must_use]
pub fn roster_stats(mode: GroupMode, roster: &[RosterEntry]) -> RosterStats {
    let mut stats = RosterStats {
        total: roster.len(),
        ..RosterStats::default()
    };
    for entry in roster {
        match entry.status {
            MemberStatus::Active => {
                stats.active += 1;
                if entry.role.can_send_in_mode(mode) {
                    stats.send_capable += 1;
                }
                if entry.role == GroupRole::Presenter {
                    stats.broadcast_presenters += 1;
                }
                if entry.role == GroupRole::Moderator {
                    stats.moderators += 1;
                }
            }
            MemberStatus::Removed => stats.removed += 1,
        }
    }
    stats
}

pub fn validate_roster_for_mode(
    mode: GroupMode,
    epoch: Epoch,
    roster: &[RosterEntry],
) -> GroupResult<RosterStats> {
    validate_roster_for_canonical_encoding(mode, roster)?;

    for entry in roster {
        if entry.joined_epoch.0 > epoch.0 {
            return Err(GroupError::InvalidRoster);
        }
        match entry.status {
            MemberStatus::Active => {
                if entry.removed_epoch.0 != 0 {
                    return Err(GroupError::InvalidRoster);
                }
                if !entry.role.is_active_in_mode(mode) {
                    return Err(GroupError::InvalidRoleForMode {
                        mode,
                        role: entry.role,
                    });
                }
            }
            MemberStatus::Removed => {
                if entry.removed_epoch.0 == 0
                    || entry.removed_epoch.0 <= entry.joined_epoch.0
                    || entry.removed_epoch.0 > epoch.0
                {
                    return Err(GroupError::InvalidRoster);
                }
            }
        }
    }

    let stats = roster_stats(mode, roster);
    if stats.active == 0 || stats.send_capable == 0 {
        return Err(GroupError::InvalidRoster);
    }
    if mode == GroupMode::Broadcast
        && stats.broadcast_presenters + stats.moderators > MAX_BROADCAST_PRESENTERS
    {
        return Err(GroupError::InvalidRoster);
    }
    Ok(stats)
}

pub fn validate_governance_for_roster(
    policy: &GovernancePolicy,
    roster: &[RosterEntry],
) -> GroupResult<()> {
    validate_governance_policy(policy)?;
    for signer in &policy.authorized_signers {
        let Some(entry) = roster.iter().find(|entry| entry.member_id == *signer) else {
            return Err(GroupError::InvalidGovernanceSigner { signer: *signer });
        };
        if entry.status != MemberStatus::Active {
            return Err(GroupError::InvalidGovernanceSigner { signer: *signer });
        }
    }
    Ok(())
}

pub fn ensure_active_member(
    roster: &[RosterEntry],
    member_id: MemberId,
) -> GroupResult<&RosterEntry> {
    let entry = roster
        .iter()
        .find(|entry| entry.member_id == member_id)
        .ok_or(GroupError::MemberNotFound { member_id })?;
    if entry.status == MemberStatus::Active {
        Ok(entry)
    } else {
        Err(GroupError::MemberInactive { member_id })
    }
}

pub fn ensure_sender_allowed(
    mode: GroupMode,
    roster: &[RosterEntry],
    member_id: MemberId,
) -> GroupResult<&RosterEntry> {
    let entry = ensure_active_member(roster, member_id)?;
    if entry.role.can_send_in_mode(mode) {
        Ok(entry)
    } else {
        Err(GroupError::SenderNotAllowed { member_id })
    }
}

pub fn ensure_member_absent(roster: &[RosterEntry], member_id: MemberId) -> GroupResult<()> {
    if roster.iter().any(|entry| entry.member_id == member_id) {
        Err(GroupError::MemberAlreadyExists { member_id })
    } else {
        Ok(())
    }
}
