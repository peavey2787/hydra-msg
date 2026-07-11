use hydra_core::types::Epoch;

use crate::{GroupError, GroupMode, GroupResult, GroupRole};

use super::{
    geometry::{
        leaf_capacity_for_mode, leaf_node_index_for_capacity, validate_node_index_for_capacity,
    },
    PublicLeaf, PublicNodeKey, PublicTree, PublicTreeNode,
};

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

    pub(crate) fn node(&self, node_index: u32) -> GroupResult<&PublicTreeNode> {
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
