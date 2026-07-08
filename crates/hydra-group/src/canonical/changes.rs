use super::{
    governance::{encode_governance_policy, encode_mode_policy},
    primitives::{lp, u16_be},
    roster::encode_roster_entry,
};
use crate::{
    CommitKind, GovernancePolicy, GroupMode, GroupResult, GroupRole, MemberId, ModePolicy,
    RosterEntry,
};

pub enum ChangePayload<'a> {
    Create {
        new_governance_policy: &'a GovernancePolicy,
        new_mode_policy: ModePolicy,
    },
    Join {
        new_entry: &'a RosterEntry,
    },
    Leave {
        member_id: MemberId,
    },
    RemoveOrRevoke {
        member_id: MemberId,
        reason_code: u16,
    },
    GovernanceChange {
        new_governance_policy: &'a GovernancePolicy,
    },
    IdentityRotate {
        old_member_id: MemberId,
        new_entry: &'a RosterEntry,
        rotation_digest: [u8; 64],
    },
    RoleChange {
        member_id: MemberId,
        old_role: GroupRole,
        new_role: GroupRole,
    },
    ModeChange {
        old_mode: GroupMode,
        new_mode: GroupMode,
        new_mode_policy: ModePolicy,
    },
    TreeSelfUpdate {
        committer_member_id: MemberId,
    },
}

impl ChangePayload<'_> {
    #[must_use]
    pub const fn kind(&self) -> CommitKind {
        match self {
            Self::Create { .. } => CommitKind::Create,
            Self::Join { .. } => CommitKind::Join,
            Self::Leave { .. } => CommitKind::Leave,
            Self::RemoveOrRevoke { .. } => CommitKind::RemoveOrRevoke,
            Self::GovernanceChange { .. } => CommitKind::GovernanceChange,
            Self::IdentityRotate { .. } => CommitKind::IdentityRotate,
            Self::RoleChange { .. } => CommitKind::RoleChange,
            Self::ModeChange { .. } => CommitKind::ModeChange,
            Self::TreeSelfUpdate { .. } => CommitKind::TreeSelfUpdate,
        }
    }
}

pub fn encode_change_payload(payload: &ChangePayload<'_>) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::new();
    match payload {
        ChangePayload::Create {
            new_governance_policy,
            new_mode_policy,
        } => {
            encoded.extend_from_slice(&lp(&encode_governance_policy(new_governance_policy)?)?);
            encoded.extend_from_slice(&lp(&encode_mode_policy(*new_mode_policy))?);
        }
        ChangePayload::Join { new_entry } => {
            encoded.extend_from_slice(&encode_roster_entry(new_entry));
        }
        ChangePayload::Leave { member_id } => {
            encoded.extend_from_slice(&member_id.0);
        }
        ChangePayload::RemoveOrRevoke {
            member_id,
            reason_code,
        } => {
            encoded.extend_from_slice(&member_id.0);
            encoded.extend_from_slice(&u16_be(*reason_code));
        }
        ChangePayload::GovernanceChange {
            new_governance_policy,
        } => {
            encoded.extend_from_slice(&lp(&encode_governance_policy(new_governance_policy)?)?);
        }
        ChangePayload::IdentityRotate {
            old_member_id,
            new_entry,
            rotation_digest,
        } => {
            encoded.extend_from_slice(&old_member_id.0);
            encoded.extend_from_slice(&encode_roster_entry(new_entry));
            encoded.extend_from_slice(rotation_digest);
        }
        ChangePayload::RoleChange {
            member_id,
            old_role,
            new_role,
        } => {
            encoded.extend_from_slice(&member_id.0);
            encoded.push(*old_role as u8);
            encoded.push(*new_role as u8);
        }
        ChangePayload::ModeChange {
            old_mode,
            new_mode,
            new_mode_policy,
        } => {
            encoded.push(*old_mode as u8);
            encoded.push(*new_mode as u8);
            encoded.extend_from_slice(&lp(&encode_mode_policy(*new_mode_policy))?);
        }
        ChangePayload::TreeSelfUpdate {
            committer_member_id,
        } => {
            encoded.extend_from_slice(&committer_member_id.0);
        }
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::{
            primitives::u32_be,
            roster::ROSTER_ENTRY_SIZE,
            test_support::{entry, member, sorted_governance},
        },
        GroupMode, GroupRole, ModePolicy,
    };

    #[test]
    fn every_change_payload_kind_uses_the_normative_shape() {
        let governance = sorted_governance(1, 1);
        let mode_policy = ModePolicy { bytes: [0xa5; 12] };
        let new_entry = entry(4, 5);

        let create = encode_change_payload(&ChangePayload::Create {
            new_governance_policy: &governance,
            new_mode_policy: mode_policy,
        })
        .unwrap();
        assert!(create.starts_with(&u32_be(36)));
        assert_eq!(&create[40..44], &u32_be(12));

        assert_eq!(
            encode_change_payload(&ChangePayload::Join {
                new_entry: &new_entry
            })
            .unwrap()
            .len(),
            ROSTER_ENTRY_SIZE
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::Leave {
                member_id: member(1)
            })
            .unwrap()
            .len(),
            32
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::RemoveOrRevoke {
                member_id: member(1),
                reason_code: 7,
            })
            .unwrap()
            .len(),
            34
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::RoleChange {
                member_id: member(1),
                old_role: GroupRole::Member,
                new_role: GroupRole::Moderator,
            })
            .unwrap()
            .len(),
            34
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::ModeChange {
                old_mode: GroupMode::Interactive,
                new_mode: GroupMode::Lite,
                new_mode_policy: mode_policy,
            })
            .unwrap()
            .len(),
            18
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::TreeSelfUpdate {
                committer_member_id: member(1)
            })
            .unwrap()
            .len(),
            32
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::IdentityRotate {
                old_member_id: member(1),
                new_entry: &new_entry,
                rotation_digest: [9; 64],
            })
            .unwrap()
            .len(),
            32 + ROSTER_ENTRY_SIZE + 64
        );
    }
}
