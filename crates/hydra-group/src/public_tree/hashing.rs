use hydra_core::SUITE_ID;
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

use crate::{lp, u32_be, u64_be, GroupError, GroupMode, GroupResult};

use super::{
    geometry::{
        direct_path_for_capacity, is_leaf_node_for_capacity, leaf_capacity_for_mode,
        leaf_node_index_for_capacity, left_child, right_child,
    },
    AffectedPathHash, PublicLeaf, PublicNodeKey, PublicTree, NODE_KEY_ABSENT, NODE_KEY_PRESENT,
    ROOT_NODE_INDEX,
};

pub fn vacant_leaf_hash(mode: GroupMode, slot: u32) -> GroupResult<[u8; 64]> {
    vacant_leaf_hash_for_capacity(leaf_capacity_for_mode(mode)?, mode, slot)
}

pub fn occupied_leaf_hash(mode: GroupMode, slot: u32, leaf: &PublicLeaf) -> GroupResult<[u8; 64]> {
    occupied_leaf_hash_for_capacity(
        leaf_capacity_for_mode(mode)?,
        mode,
        slot,
        leaf,
        leaf.node_key.as_ref(),
    )
}

pub(super) fn vacant_leaf_hash_for_capacity(
    leaf_capacity: u32,
    mode: GroupMode,
    slot: u32,
) -> GroupResult<[u8; 64]> {
    let node_index = leaf_node_index_for_capacity(leaf_capacity, slot)?;
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/group/tree/vacant-leaf");
    input.extend_from_slice(&SUITE_ID);
    input.push(mode as u8);
    input.extend_from_slice(&u32_be(leaf_capacity));
    input.extend_from_slice(&u32_be(slot));
    input.extend_from_slice(&u32_be(node_index));
    input.push(NODE_KEY_ABSENT);
    Ok(RustCryptoBackend::sha3_512(&lp(&input)?))
}

pub(super) fn occupied_leaf_hash_for_capacity(
    leaf_capacity: u32,
    mode: GroupMode,
    slot: u32,
    leaf: &PublicLeaf,
    node_key: Option<&PublicNodeKey>,
) -> GroupResult<[u8; 64]> {
    let node_index = leaf_node_index_for_capacity(leaf_capacity, slot)?;
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/group/tree/occupied-leaf");
    input.extend_from_slice(&SUITE_ID);
    input.push(mode as u8);
    input.extend_from_slice(&u32_be(leaf_capacity));
    input.extend_from_slice(&u32_be(slot));
    input.extend_from_slice(&u32_be(node_index));
    input.extend_from_slice(&leaf.member_id.0);
    input.extend_from_slice(&leaf.device_identity_fingerprint.0);
    input.push(leaf.role as u8);
    input.extend_from_slice(&u64_be(leaf.generation));
    append_node_key(&mut input, node_key);
    Ok(RustCryptoBackend::sha3_512(&lp(&input)?))
}

pub fn parent_node_hash(
    node_index: u32,
    left_hash: &[u8; 64],
    right_hash: &[u8; 64],
    node_key: Option<&PublicNodeKey>,
) -> GroupResult<[u8; 64]> {
    if node_index == 0 {
        return Err(GroupError::InvalidTreeNode { node_index });
    }
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/group/tree/parent");
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&u32_be(node_index));
    append_node_key(&mut input, node_key);
    input.extend_from_slice(left_hash);
    input.extend_from_slice(right_hash);
    Ok(RustCryptoBackend::sha3_512(&lp(&input)?))
}

fn append_node_key(output: &mut Vec<u8>, node_key: Option<&PublicNodeKey>) {
    match node_key {
        Some(key) => {
            output.push(NODE_KEY_PRESENT);
            output.extend_from_slice(&key.0);
        }
        None => output.push(NODE_KEY_ABSENT),
    }
}

impl PublicTree {
    pub fn tree_hash(&self) -> GroupResult<[u8; 64]> {
        self.node_hash(ROOT_NODE_INDEX)
    }

    pub fn node_hash(&self, node_index: u32) -> GroupResult<[u8; 64]> {
        self.validate_hash_node_index(node_index)?;
        if is_leaf_node_for_capacity(self.leaf_capacity, node_index)? {
            let slot = node_index - self.leaf_capacity;
            let node = self.node(node_index)?;
            match &node.leaf {
                Some(leaf) => occupied_leaf_hash_for_capacity(
                    self.leaf_capacity,
                    self.mode,
                    slot,
                    leaf,
                    node.node_key.as_ref().or(leaf.node_key.as_ref()),
                ),
                None => vacant_leaf_hash_for_capacity(self.leaf_capacity, self.mode, slot),
            }
        } else {
            let left = left_child(node_index)?;
            let right = right_child(node_index)?;
            let left_hash = self.node_hash(left)?;
            let right_hash = self.node_hash(right)?;
            parent_node_hash(
                node_index,
                &left_hash,
                &right_hash,
                self.node(node_index)?.node_key.as_ref(),
            )
        }
    }

    pub fn recompute_affected_path(&self, slot: u32) -> GroupResult<Vec<AffectedPathHash>> {
        direct_path_for_capacity(self.leaf_capacity, slot)?
            .into_iter()
            .map(|node_index| {
                Ok(AffectedPathHash {
                    node_index,
                    hash: self.node_hash(node_index)?,
                })
            })
            .collect()
    }

    fn validate_hash_node_index(&self, node_index: u32) -> GroupResult<()> {
        super::geometry::validate_node_index_for_capacity(self.leaf_capacity, node_index)
    }
}
