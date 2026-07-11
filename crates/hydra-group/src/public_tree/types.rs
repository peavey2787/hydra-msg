use hydra_core::{
    types::{Epoch, IdentityFingerprint},
    ML_KEM_768_EK_SIZE,
};

use crate::{GroupMode, GroupRole, MemberId};

pub const ROOT_NODE_INDEX: u32 = 1;
pub const NODE_KEY_ABSENT: u8 = 0;
pub const NODE_KEY_PRESENT: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicNodeKey(pub [u8; ML_KEM_768_EK_SIZE]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicLeaf {
    pub member_id: MemberId,
    pub device_identity_fingerprint: IdentityFingerprint,
    pub role: GroupRole,
    pub generation: u64,
    pub node_key: Option<PublicNodeKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicTreeNode {
    pub node_index: u32,
    pub node_key: Option<PublicNodeKey>,
    pub leaf: Option<PublicLeaf>,
}

impl PublicTreeNode {
    #[must_use]
    pub const fn empty(node_index: u32) -> Self {
        Self {
            node_index,
            node_key: None,
            leaf: None,
        }
    }

    #[must_use]
    pub const fn is_occupied_leaf(&self) -> bool {
        self.leaf.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffectedPathHash {
    pub node_index: u32,
    pub hash: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicTree {
    pub mode: GroupMode,
    pub leaf_capacity: u32,
    pub tree_version: u64,
    pub epoch: Option<Epoch>,
    /// Heap-indexed public nodes. Index 0 is intentionally unused so protocol
    /// node indices can be used directly as vector indices after validation.
    pub nodes: Vec<PublicTreeNode>,
}
