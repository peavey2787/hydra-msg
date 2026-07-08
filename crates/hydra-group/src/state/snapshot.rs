use super::AcceptedGroupMessage;
use crate::public_tree::PublicTree;
use crate::{
    GovernancePolicy, GroupMode, GroupPhase, MemberId, MembershipMechanism, ModePolicy,
    RosterEntry, StateVersion,
};
use hydra_core::protocol::replay::ReplayWindowSnapshot;
use hydra_core::types::{Epoch, GroupId, LeafIndex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivatePathNodeSecretSnapshot {
    pub node_index: u32,
    pub path_secret: [u8; 32],
    pub node_seed_d: [u8; 32],
    pub node_seed_z: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipPrivateStateSnapshot {
    TreeKem {
        public_tree: PublicTree,
        leaf_index: Option<LeafIndex>,
        path: Vec<PrivatePathNodeSecretSnapshot>,
    },
    DirectWrap {
        epoch_secret: [u8; 32],
    },
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderChainCursorSnapshot {
    pub sender: MemberId,
    pub next_index: u64,
    pub chain_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedGroupMessageKeySnapshot {
    pub sender: MemberId,
    pub index: u64,
    pub route_tag: [u8; 16],
    pub message_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderChainStateSnapshot {
    pub senders: Vec<SenderChainCursorSnapshot>,
    pub skipped: Vec<SkippedGroupMessageKeySnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderReplayStateSnapshot {
    pub sender: MemberId,
    pub replay: ReplayWindowSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupReplayStateSnapshot {
    pub senders: Vec<SenderReplayStateSnapshot>,
    pub accepted_messages: Vec<AcceptedGroupMessage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupStateSnapshot {
    pub group_id: GroupId,
    pub mode: GroupMode,
    pub mechanism: MembershipMechanism,
    pub epoch: Epoch,
    pub state_version: StateVersion,
    pub last_commit_hash: [u8; 64],
    pub previous_commit_hash: [u8; 64],
    pub roster_hash: [u8; 64],
    pub tree_hash: [u8; 64],
    pub governance_policy: GovernancePolicy,
    pub mode_policy: ModePolicy,
    pub roster: Vec<RosterEntry>,
    pub membership: MembershipPrivateStateSnapshot,
    pub sender_chains: SenderChainStateSnapshot,
    pub replay_state: GroupReplayStateSnapshot,
    pub phase: GroupPhase,
}
