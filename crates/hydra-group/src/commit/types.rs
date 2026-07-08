use hydra_core::types::{Epoch, Secret32};

use crate::{
    CommitCore, CommitKind, CommitSignature, GovernancePolicy, GroupMode, GroupRole, MemberId,
    MembershipMechanism, ModePolicy, PublicTree, RosterEntry, StateVersion, UpdatePath,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitChange {
    Create {
        new_roster: Vec<RosterEntry>,
        new_governance_policy: GovernancePolicy,
        new_mode_policy: ModePolicy,
        new_tree_hash: [u8; 64],
    },
    Join {
        new_entry: RosterEntry,
    },
    Leave {
        member_id: MemberId,
    },
    RemoveOrRevoke {
        member_id: MemberId,
        reason_code: u16,
    },
    GovernanceChange {
        new_governance_policy: GovernancePolicy,
    },
    IdentityRotate {
        old_member_id: MemberId,
        new_entry: RosterEntry,
        rotation_digest: [u8; 64],
    },
    RoleChange {
        member_id: MemberId,
        new_role: GroupRole,
    },
    ModeChange {
        new_mode: GroupMode,
        new_mode_policy: ModePolicy,
    },
    TreeSelfUpdate {
        committer_member_id: MemberId,
    },
}

impl CommitChange {
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

pub struct CommitPlan {
    pub committer: MemberId,
    pub commit_nonce: [u8; 32],
    pub change: CommitChange,
    pub signatures: Vec<CommitSignature>,
    pub update_path: Option<UpdatePath>,
    pub direct_epoch_secret: Option<[u8; 32]>,
}

pub struct PreparedCommit {
    pub core: CommitCore,
    pub encoded_core: Vec<u8>,
    pub signature_digest: [u8; 64],
    pub commit_hash: [u8; 64],
    pub signatures: Vec<CommitSignature>,
    pub(crate) candidate: CandidateState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitInstallResult {
    Applied,
    Duplicate,
    Forked,
}

pub(crate) struct CandidateState {
    pub(crate) mode: GroupMode,
    pub(crate) mechanism: MembershipMechanism,
    pub(crate) epoch: Epoch,
    pub(crate) state_version: StateVersion,
    pub(crate) roster: Vec<RosterEntry>,
    pub(crate) roster_hash: [u8; 64],
    pub(crate) tree_hash: [u8; 64],
    pub(crate) governance_policy: GovernancePolicy,
    pub(crate) mode_policy: ModePolicy,
    pub(crate) public_tree: Option<PublicTree>,
    pub(crate) direct_epoch_secret: Option<Secret32>,
}
