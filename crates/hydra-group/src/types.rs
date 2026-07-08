use hydra_core::types::{Epoch, GroupId, IdentityFingerprint};

use crate::error::{GroupError, GroupResult};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupMode {
    Interactive = 0x01,
    Broadcast = 0x02,
    Lite = 0x03,
}

impl GroupMode {
    #[must_use]
    pub const fn required_mechanism(self) -> MembershipMechanism {
        match self {
            Self::Interactive | Self::Broadcast => MembershipMechanism::TreeKem,
            Self::Lite => MembershipMechanism::DirectWrap,
        }
    }

    #[must_use]
    pub const fn max_roster_entries(self) -> usize {
        match self {
            Self::Interactive => hydra_core::MAX_INTERACTIVE_MEMBERS,
            Self::Broadcast => hydra_core::MAX_BROADCAST_MEMBERS,
            Self::Lite => hydra_core::MAX_LITE_MEMBERS,
        }
    }

    #[must_use]
    pub const fn sender_skip_bound(self) -> usize {
        match self {
            Self::Interactive => 64,
            Self::Broadcast => 256,
            Self::Lite => 32,
        }
    }
}

impl TryFrom<u8> for GroupMode {
    type Error = GroupError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Interactive),
            0x02 => Ok(Self::Broadcast),
            0x03 => Ok(Self::Lite),
            _ => Err(GroupError::InvalidDiscriminant {
                type_name: "GroupMode",
                value,
            }),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MembershipMechanism {
    TreeKem = 0x01,
    DirectWrap = 0x02,
}

impl TryFrom<u8> for MembershipMechanism {
    type Error = GroupError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::TreeKem),
            0x02 => Ok(Self::DirectWrap),
            _ => Err(GroupError::InvalidDiscriminant {
                type_name: "MembershipMechanism",
                value,
            }),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupRole {
    Member = 0x01,
    Presenter = 0x02,
    Moderator = 0x03,
    Audience = 0x04,
}

impl GroupRole {
    #[must_use]
    pub const fn is_active_in_mode(self, mode: GroupMode) -> bool {
        matches!(
            (mode, self),
            (
                GroupMode::Interactive | GroupMode::Lite,
                Self::Member | Self::Moderator
            ) | (
                GroupMode::Broadcast,
                Self::Presenter | Self::Moderator | Self::Audience
            )
        )
    }

    #[must_use]
    pub const fn can_send_in_mode(self, mode: GroupMode) -> bool {
        matches!(
            (mode, self),
            (
                GroupMode::Interactive | GroupMode::Lite,
                Self::Member | Self::Moderator
            ) | (GroupMode::Broadcast, Self::Presenter | Self::Moderator)
        )
    }
}

impl TryFrom<u8> for GroupRole {
    type Error = GroupError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Member),
            0x02 => Ok(Self::Presenter),
            0x03 => Ok(Self::Moderator),
            0x04 => Ok(Self::Audience),
            _ => Err(GroupError::InvalidDiscriminant {
                type_name: "GroupRole",
                value,
            }),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemberStatus {
    Active = 0x01,
    Removed = 0x02,
}

impl TryFrom<u8> for MemberStatus {
    type Error = GroupError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Active),
            0x02 => Ok(Self::Removed),
            _ => Err(GroupError::InvalidDiscriminant {
                type_name: "MemberStatus",
                value,
            }),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitKind {
    Create = 0x01,
    Join = 0x02,
    Leave = 0x03,
    RemoveOrRevoke = 0x04,
    GovernanceChange = 0x05,
    IdentityRotate = 0x06,
    RoleChange = 0x07,
    ModeChange = 0x08,
    TreeSelfUpdate = 0x09,
}

impl TryFrom<u8> for CommitKind {
    type Error = GroupError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Create),
            0x02 => Ok(Self::Join),
            0x03 => Ok(Self::Leave),
            0x04 => Ok(Self::RemoveOrRevoke),
            0x05 => Ok(Self::GovernanceChange),
            0x06 => Ok(Self::IdentityRotate),
            0x07 => Ok(Self::RoleChange),
            0x08 => Ok(Self::ModeChange),
            0x09 => Ok(Self::TreeSelfUpdate),
            _ => Err(GroupError::InvalidDiscriminant {
                type_name: "CommitKind",
                value,
            }),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupPhase {
    Active = 0x01,
    Forked = 0x02,
    Closed = 0x03,
}

impl TryFrom<u8> for GroupPhase {
    type Error = GroupError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Active),
            0x02 => Ok(Self::Forked),
            0x03 => Ok(Self::Closed),
            _ => Err(GroupError::InvalidDiscriminant {
                type_name: "GroupPhase",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateVersion(pub u64);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModePolicy {
    pub bytes: [u8; 12],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernancePolicy {
    pub policy_version: u8,
    pub threshold: u8,
    pub authorized_signers: Vec<MemberId>,
}

impl GovernancePolicy {
    #[must_use]
    pub fn single_signer(member_id: MemberId) -> Self {
        Self {
            policy_version: 1,
            threshold: 1,
            authorized_signers: vec![member_id],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterEntry {
    pub member_id: MemberId,
    pub device_identity_fingerprint: IdentityFingerprint,
    pub role: GroupRole,
    pub status: MemberStatus,
    pub tree_leaf_slot: u32,
    pub joined_epoch: Epoch,
    pub removed_epoch: Epoch,
}

impl RosterEntry {
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, MemberStatus::Active)
    }
}

#[must_use]
pub const fn mechanism_for_mode(mode: GroupMode) -> MembershipMechanism {
    mode.required_mechanism()
}

pub fn validate_mode_mechanism(mode: GroupMode, mechanism: MembershipMechanism) -> GroupResult<()> {
    if mechanism == mode.required_mechanism() {
        Ok(())
    } else {
        Err(GroupError::InvalidModeMechanism { mode, mechanism })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupContext {
    pub group_id: GroupId,
    pub mode: GroupMode,
    pub mechanism: MembershipMechanism,
    pub epoch: Epoch,
    pub state_version: StateVersion,
}

impl GroupContext {
    pub fn new(
        group_id: GroupId,
        mode: GroupMode,
        mechanism: MembershipMechanism,
        epoch: Epoch,
        state_version: StateVersion,
    ) -> GroupResult<Self> {
        validate_mode_mechanism(mode, mechanism)?;
        Ok(Self {
            group_id,
            mode,
            mechanism,
            epoch,
            state_version,
        })
    }
}
