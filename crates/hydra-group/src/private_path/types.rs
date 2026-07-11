use hydra_core::types::{Epoch, GroupId, LeafIndex, Secret32};

use crate::{GroupMode, PublicNodeKey, StateVersion};

pub struct PrivatePathNodeSecret {
    pub node_index: u32,
    pub path_secret: Secret32,
    pub node_seed_d: Secret32,
    pub node_seed_z: Secret32,
}

impl PrivatePathNodeSecret {
    pub fn clear(&mut self) {
        self.path_secret.wipe();
        self.node_seed_d.wipe();
        self.node_seed_z.wipe();
    }
}

impl Drop for PrivatePathNodeSecret {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Default)]
pub struct PrivatePath {
    pub leaf_index: Option<LeafIndex>,
    pub path: Vec<PrivatePathNodeSecret>,
}

impl PrivatePath {
    #[must_use]
    pub fn len(&self) -> usize {
        self.path.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }

    #[must_use]
    pub fn node_indices(&self) -> Vec<u32> {
        self.path.iter().map(|node| node.node_index).collect()
    }

    pub fn replace_with(&mut self, leaf_index: LeafIndex, path: Vec<PrivatePathNodeSecret>) {
        self.clear();
        self.leaf_index = Some(leaf_index);
        self.path = path;
    }

    pub fn clear(&mut self) {
        for node in &mut self.path {
            node.clear();
        }
        self.path.clear();
        self.leaf_index = None;
    }
}

impl Drop for PrivatePath {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeKemPathContext {
    pub group_id: GroupId,
    pub mode: GroupMode,
    pub epoch: Epoch,
    pub state_version: StateVersion,
    pub leaf_slot: u32,
    pub commit_nonce: [u8; 32],
    pub tree_hash: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedPublicPathNode {
    pub node_index: u32,
    pub node_key: PublicNodeKey,
}

pub struct TreeKemPathUpdate {
    pub leaf_slot: u32,
    pub direct_path: Vec<u32>,
    pub updated_nodes: Vec<DerivedPublicPathNode>,
    pub root_secret: Secret32,
    pub tree_hash_after: [u8; 64],
    pub tree_version_after: u64,
}
