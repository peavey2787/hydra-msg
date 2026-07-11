use crate::{GroupError, GroupMode, GroupResult, MembershipMechanism};

use super::{NODE_KEY_ABSENT, NODE_KEY_PRESENT, ROOT_NODE_INDEX};

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

pub(super) fn leaf_node_index_for_capacity(leaf_capacity: u32, slot: u32) -> GroupResult<u32> {
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

pub(super) fn validate_node_index_for_capacity(
    leaf_capacity: u32,
    node_index: u32,
) -> GroupResult<()> {
    let exclusive = leaf_capacity
        .checked_mul(2)
        .ok_or(GroupError::CounterExhausted)?;
    if (ROOT_NODE_INDEX..exclusive).contains(&node_index) {
        Ok(())
    } else {
        Err(GroupError::InvalidTreeNode { node_index })
    }
}

pub(super) fn is_leaf_node_for_capacity(leaf_capacity: u32, node_index: u32) -> GroupResult<bool> {
    validate_node_index_for_capacity(leaf_capacity, node_index)?;
    Ok(node_index >= leaf_capacity)
}

pub(super) fn direct_path_for_capacity(leaf_capacity: u32, slot: u32) -> GroupResult<Vec<u32>> {
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
