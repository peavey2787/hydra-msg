use hydra_core::{
    types::{Epoch, IdentityFingerprint},
    ML_KEM_768_EK_SIZE, SUITE_ID,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

use crate::{
    lp, u32_be, u64_be, GroupError, GroupMode, GroupResult, GroupRole, MemberId,
    MembershipMechanism,
};

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

impl PublicTree {
    pub fn new(mode: GroupMode, epoch: Option<Epoch>) -> GroupResult<Self> {
        let leaf_capacity = leaf_capacity_for_mode(mode)?;
        let node_count_exclusive = leaf_capacity
            .checked_mul(2)
            .ok_or(GroupError::CounterExhausted)?;
        let mut nodes = Vec::with_capacity(
            usize::try_from(node_count_exclusive).map_err(|_| GroupError::CounterExhausted)?,
        );
        for node_index in 0..node_count_exclusive {
            nodes.push(PublicTreeNode::empty(node_index));
        }
        Ok(Self {
            mode,
            leaf_capacity,
            tree_version: 0,
            epoch,
            nodes,
        })
    }

    pub fn occupy_leaf(&mut self, slot: u32, leaf: PublicLeaf) -> GroupResult<()> {
        let node_index = leaf_node_index_for_capacity(self.leaf_capacity, slot)?;
        let node = self.node_mut(node_index)?;
        node.node_key = leaf.node_key.clone();
        node.leaf = Some(leaf);
        self.bump_tree_version()
    }

    pub fn vacate_leaf(&mut self, slot: u32) -> GroupResult<()> {
        let node_index = leaf_node_index_for_capacity(self.leaf_capacity, slot)?;
        let node = self.node_mut(node_index)?;
        node.node_key = None;
        node.leaf = None;
        self.bump_tree_version()
    }

    pub fn update_leaf_role(&mut self, slot: u32, role: GroupRole) -> GroupResult<()> {
        let capacity = self.leaf_capacity;
        let node_index = leaf_node_index_for_capacity(capacity, slot)?;
        let node = self.node_mut(node_index)?;
        let Some(leaf) = node.leaf.as_mut() else {
            return Err(GroupError::InvalidTreeSlot { slot, capacity });
        };
        leaf.role = role;
        self.bump_tree_version()
    }

    pub fn set_node_key(
        &mut self,
        node_index: u32,
        node_key: Option<PublicNodeKey>,
    ) -> GroupResult<()> {
        self.validate_node_index(node_index)?;
        self.node_mut(node_index)?.node_key = node_key;
        self.bump_tree_version()
    }

    #[must_use]
    pub fn leaf(&self, slot: u32) -> Option<&PublicLeaf> {
        let node_index = leaf_node_index_for_capacity(self.leaf_capacity, slot).ok()?;
        self.nodes
            .get(usize::try_from(node_index).ok()?)?
            .leaf
            .as_ref()
    }

    pub fn tree_hash(&self) -> GroupResult<[u8; 64]> {
        self.node_hash(ROOT_NODE_INDEX)
    }

    pub fn node_hash(&self, node_index: u32) -> GroupResult<[u8; 64]> {
        self.validate_node_index(node_index)?;
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

    fn node(&self, node_index: u32) -> GroupResult<&PublicTreeNode> {
        self.validate_node_index(node_index)?;
        self.nodes
            .get(usize::try_from(node_index).map_err(|_| GroupError::CounterExhausted)?)
            .ok_or(GroupError::InvalidTreeNode { node_index })
    }

    fn node_mut(&mut self, node_index: u32) -> GroupResult<&mut PublicTreeNode> {
        self.validate_node_index(node_index)?;
        self.nodes
            .get_mut(usize::try_from(node_index).map_err(|_| GroupError::CounterExhausted)?)
            .ok_or(GroupError::InvalidTreeNode { node_index })
    }

    fn validate_node_index(&self, node_index: u32) -> GroupResult<()> {
        validate_node_index_for_capacity(self.leaf_capacity, node_index)
    }

    fn bump_tree_version(&mut self) -> GroupResult<()> {
        self.tree_version = self
            .tree_version
            .checked_add(1)
            .ok_or(GroupError::CounterExhausted)?;
        Ok(())
    }
}

impl Default for PublicTree {
    fn default() -> Self {
        Self::new(GroupMode::Interactive, None).expect("interactive public tree shape is valid")
    }
}

pub fn leaf_capacity_for_mode(mode: GroupMode) -> GroupResult<u32> {
    match mode {
        GroupMode::Interactive => Ok(hydra_core::MAX_INTERACTIVE_MEMBERS as u32),
        GroupMode::Broadcast => Ok(hydra_core::MAX_BROADCAST_MEMBERS as u32),
        GroupMode::Lite => Err(GroupError::InvalidModeMechanism {
            mode,
            mechanism: MembershipMechanism::TreeKem,
        }),
    }
}

pub fn validate_node_key_flag(flag: u8) -> GroupResult<()> {
    match flag {
        NODE_KEY_ABSENT | NODE_KEY_PRESENT => Ok(()),
        _ => Err(GroupError::InvalidTreeNodeKeyFlag { flag }),
    }
}

#[must_use]
pub const fn parent_index(node_index: u32) -> Option<u32> {
    if node_index == ROOT_NODE_INDEX {
        None
    } else {
        Some(node_index / 2)
    }
}

pub fn left_child(node_index: u32) -> GroupResult<u32> {
    node_index
        .checked_mul(2)
        .ok_or(GroupError::CounterExhausted)
}

pub fn right_child(node_index: u32) -> GroupResult<u32> {
    left_child(node_index)?
        .checked_add(1)
        .ok_or(GroupError::CounterExhausted)
}

pub fn sibling_index(node_index: u32) -> GroupResult<u32> {
    if node_index == ROOT_NODE_INDEX {
        return Err(GroupError::InvalidTreeNode { node_index });
    }
    if node_index.is_multiple_of(2) {
        node_index
            .checked_add(1)
            .ok_or(GroupError::CounterExhausted)
    } else {
        Ok(node_index - 1)
    }
}

pub fn leaf_node_index(mode: GroupMode, slot: u32) -> GroupResult<u32> {
    leaf_node_index_for_capacity(leaf_capacity_for_mode(mode)?, slot)
}

pub fn direct_path(mode: GroupMode, slot: u32) -> GroupResult<Vec<u32>> {
    direct_path_for_capacity(leaf_capacity_for_mode(mode)?, slot)
}

pub fn copath(mode: GroupMode, slot: u32) -> GroupResult<Vec<u32>> {
    copath_for_capacity(leaf_capacity_for_mode(mode)?, slot)
}

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

fn leaf_node_index_for_capacity(leaf_capacity: u32, slot: u32) -> GroupResult<u32> {
    if slot >= leaf_capacity {
        return Err(GroupError::InvalidTreeSlot {
            slot,
            capacity: leaf_capacity,
        });
    }
    leaf_capacity
        .checked_add(slot)
        .ok_or(GroupError::CounterExhausted)
}

fn validate_node_index_for_capacity(leaf_capacity: u32, node_index: u32) -> GroupResult<()> {
    let exclusive = leaf_capacity
        .checked_mul(2)
        .ok_or(GroupError::CounterExhausted)?;
    if (ROOT_NODE_INDEX..exclusive).contains(&node_index) {
        Ok(())
    } else {
        Err(GroupError::InvalidTreeNode { node_index })
    }
}

fn is_leaf_node_for_capacity(leaf_capacity: u32, node_index: u32) -> GroupResult<bool> {
    validate_node_index_for_capacity(leaf_capacity, node_index)?;
    Ok(node_index >= leaf_capacity)
}

fn direct_path_for_capacity(leaf_capacity: u32, slot: u32) -> GroupResult<Vec<u32>> {
    let mut cursor = leaf_node_index_for_capacity(leaf_capacity, slot)?;
    let mut path = Vec::new();
    loop {
        path.push(cursor);
        let Some(parent) = parent_index(cursor) else {
            break;
        };
        cursor = parent;
    }
    Ok(path)
}

fn copath_for_capacity(leaf_capacity: u32, slot: u32) -> GroupResult<Vec<u32>> {
    let mut cursor = leaf_node_index_for_capacity(leaf_capacity, slot)?;
    let mut path = Vec::new();
    while let Some(parent) = parent_index(cursor) {
        let sibling = sibling_index(cursor)?;
        validate_node_index_for_capacity(leaf_capacity, sibling)?;
        path.push(sibling);
        cursor = parent;
    }
    Ok(path)
}

fn vacant_leaf_hash_for_capacity(
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

fn occupied_leaf_hash_for_capacity(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn member(value: u8) -> MemberId {
        MemberId([value; 32])
    }

    fn fingerprint(value: u8) -> IdentityFingerprint {
        IdentityFingerprint([value; 32])
    }

    fn node_key(value: u8) -> PublicNodeKey {
        PublicNodeKey([value; ML_KEM_768_EK_SIZE])
    }

    fn leaf(member_value: u8) -> PublicLeaf {
        PublicLeaf {
            member_id: member(member_value),
            device_identity_fingerprint: fingerprint(member_value + 1),
            role: GroupRole::Member,
            generation: 0,
            node_key: Some(node_key(member_value + 2)),
        }
    }

    #[test]
    fn capacity_is_power_of_two_and_only_treekem_modes_are_admitted() {
        assert_eq!(leaf_capacity_for_mode(GroupMode::Interactive), Ok(256));
        assert_eq!(leaf_capacity_for_mode(GroupMode::Broadcast), Ok(8_192));
        assert_eq!(
            leaf_capacity_for_mode(GroupMode::Lite).unwrap_err(),
            GroupError::InvalidModeMechanism {
                mode: GroupMode::Lite,
                mechanism: MembershipMechanism::TreeKem,
            }
        );
        assert!(leaf_capacity_for_mode(GroupMode::Interactive)
            .unwrap()
            .is_power_of_two());
        assert!(leaf_capacity_for_mode(GroupMode::Broadcast)
            .unwrap()
            .is_power_of_two());
    }

    #[test]
    fn heap_parent_child_relationships_are_checked() {
        assert_eq!(parent_index(ROOT_NODE_INDEX), None);
        assert_eq!(left_child(1), Ok(2));
        assert_eq!(right_child(1), Ok(3));
        assert_eq!(parent_index(2), Some(1));
        assert_eq!(parent_index(3), Some(1));
        assert_eq!(sibling_index(2), Ok(3));
        assert_eq!(sibling_index(3), Ok(2));
        assert_eq!(left_child(u32::MAX), Err(GroupError::CounterExhausted));
        assert_eq!(right_child(u32::MAX), Err(GroupError::CounterExhausted));
        assert_eq!(
            sibling_index(ROOT_NODE_INDEX),
            Err(GroupError::InvalidTreeNode { node_index: 1 })
        );
    }

    #[test]
    fn leaf_slot_boundaries_are_enforced() {
        assert_eq!(leaf_node_index(GroupMode::Interactive, 0), Ok(256));
        assert_eq!(leaf_node_index(GroupMode::Interactive, 255), Ok(511));
        assert_eq!(
            leaf_node_index(GroupMode::Interactive, 256),
            Err(GroupError::InvalidTreeSlot {
                slot: 256,
                capacity: 256
            })
        );
        assert_eq!(leaf_node_index(GroupMode::Broadcast, 8_191), Ok(16_383));
        assert_eq!(
            leaf_node_index(GroupMode::Broadcast, 8_192),
            Err(GroupError::InvalidTreeSlot {
                slot: 8_192,
                capacity: 8_192
            })
        );
    }

    #[test]
    fn direct_paths_include_leaf_and_root_for_boundary_slots() {
        assert_eq!(
            direct_path(GroupMode::Interactive, 0).unwrap(),
            vec![256, 128, 64, 32, 16, 8, 4, 2, 1]
        );
        assert_eq!(
            direct_path(GroupMode::Interactive, 128).unwrap(),
            vec![384, 192, 96, 48, 24, 12, 6, 3, 1]
        );
        assert_eq!(
            direct_path(GroupMode::Interactive, 255).unwrap(),
            vec![511, 255, 127, 63, 31, 15, 7, 3, 1]
        );
    }

    #[test]
    fn copaths_cover_boundary_slots_from_leaf_sibling_to_root_sibling() {
        assert_eq!(
            copath(GroupMode::Interactive, 0).unwrap(),
            vec![257, 129, 65, 33, 17, 9, 5, 3]
        );
        assert_eq!(
            copath(GroupMode::Interactive, 255).unwrap(),
            vec![510, 254, 126, 62, 30, 14, 6, 2]
        );
    }

    #[test]
    fn node_key_flag_accepts_only_zero_or_one() {
        assert_eq!(validate_node_key_flag(NODE_KEY_ABSENT), Ok(()));
        assert_eq!(validate_node_key_flag(NODE_KEY_PRESENT), Ok(()));
        assert_eq!(
            validate_node_key_flag(2),
            Err(GroupError::InvalidTreeNodeKeyFlag { flag: 2 })
        );
    }

    #[test]
    fn vacant_occupied_and_parent_hashes_are_deterministic_and_separated() {
        let vacant_a = vacant_leaf_hash(GroupMode::Interactive, 0).unwrap();
        let vacant_b = vacant_leaf_hash(GroupMode::Interactive, 0).unwrap();
        assert_eq!(vacant_a, vacant_b);

        let occupied = occupied_leaf_hash(GroupMode::Interactive, 0, &leaf(1)).unwrap();
        assert_ne!(vacant_a, occupied);

        let parent_a = parent_node_hash(128, &occupied, &vacant_a, None).unwrap();
        let parent_b = parent_node_hash(128, &occupied, &vacant_a, None).unwrap();
        let parent_with_key =
            parent_node_hash(128, &occupied, &vacant_a, Some(&node_key(9))).unwrap();
        assert_eq!(parent_a, parent_b);
        assert_ne!(parent_a, parent_with_key);
    }

    #[test]
    fn tree_hash_changes_when_leaf_fields_or_occupancy_change() {
        let mut tree = PublicTree::new(GroupMode::Interactive, Some(Epoch(7))).unwrap();
        let empty_root = tree.tree_hash().unwrap();

        tree.occupy_leaf(0, leaf(1)).unwrap();
        let occupied_root = tree.tree_hash().unwrap();
        assert_ne!(empty_root, occupied_root);

        let mut changed_member = leaf(2);
        changed_member.device_identity_fingerprint = fingerprint(2);
        tree.occupy_leaf(0, changed_member).unwrap();
        let changed_member_root = tree.tree_hash().unwrap();
        assert_ne!(occupied_root, changed_member_root);

        let mut changed_role = leaf(1);
        changed_role.role = GroupRole::Moderator;
        tree.occupy_leaf(0, changed_role).unwrap();
        let changed_role_root = tree.tree_hash().unwrap();
        assert_ne!(occupied_root, changed_role_root);

        let mut changed_fingerprint = leaf(1);
        changed_fingerprint.device_identity_fingerprint = fingerprint(99);
        tree.occupy_leaf(0, changed_fingerprint).unwrap();
        let changed_fingerprint_root = tree.tree_hash().unwrap();
        assert_ne!(occupied_root, changed_fingerprint_root);

        let mut changed_generation = leaf(1);
        changed_generation.generation = 1;
        tree.occupy_leaf(0, changed_generation).unwrap();
        let changed_generation_root = tree.tree_hash().unwrap();
        assert_ne!(occupied_root, changed_generation_root);

        let mut changed_key = leaf(1);
        changed_key.node_key = Some(node_key(77));
        tree.occupy_leaf(0, changed_key).unwrap();
        let changed_key_root = tree.tree_hash().unwrap();
        assert_ne!(occupied_root, changed_key_root);

        tree.vacate_leaf(0).unwrap();
        assert_eq!(tree.tree_hash().unwrap(), empty_root);
    }

    #[test]
    fn affected_path_recomputes_leaf_to_root_hashes() {
        let mut tree = PublicTree::new(GroupMode::Interactive, None).unwrap();
        tree.occupy_leaf(0, leaf(1)).unwrap();
        let affected = tree.recompute_affected_path(0).unwrap();
        let path = direct_path(GroupMode::Interactive, 0).unwrap();
        assert_eq!(affected.len(), path.len());
        assert_eq!(affected.first().unwrap().node_index, 256);
        assert_eq!(affected.last().unwrap().node_index, ROOT_NODE_INDEX);
        assert_eq!(affected.last().unwrap().hash, tree.tree_hash().unwrap());
    }
}
