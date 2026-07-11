use crate::{
    left_child, parent_index, right_child, sibling_index, GroupError, GroupMode, GroupResult,
    PublicNodeKey, PublicTree, ROOT_NODE_INDEX,
};

use super::PathSecretTarget;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPathTarget {
    pub node_index: u32,
    pub node_key: PublicNodeKey,
}

pub fn resolve_update_path_targets(
    tree: &PublicTree,
    committer_leaf_slot: u32,
    excluded_nodes: &[u32],
) -> GroupResult<Vec<PathSecretTarget>> {
    if tree.mode == GroupMode::Lite {
        return Err(GroupError::InvalidModeMechanism {
            mode: GroupMode::Lite,
            mechanism: crate::MembershipMechanism::TreeKem,
        });
    }
    let full_direct_path = crate::direct_path(tree.mode, committer_leaf_slot)?;
    if full_direct_path.last().copied() != Some(ROOT_NODE_INDEX) {
        return Err(GroupError::InvalidTreePath);
    }

    let mut targets = Vec::new();
    for node_index in full_direct_path
        .iter()
        .copied()
        .take(full_direct_path.len() - 1)
    {
        let parent_node_index = parent_index(node_index).ok_or(GroupError::InvalidTreePath)?;
        let subtree = sibling_index(node_index)?;
        for resolved in resolve_subtree(tree, subtree, excluded_nodes)? {
            targets.push(PathSecretTarget {
                parent_node_index,
                target_node_index: resolved.node_index,
                node_key: resolved.node_key,
            });
        }
    }
    targets.sort_by_key(|target| (target.parent_node_index, target.target_node_index));
    if targets.windows(2).any(|pair| {
        pair[0].parent_node_index == pair[1].parent_node_index
            && pair[0].target_node_index == pair[1].target_node_index
    }) {
        return Err(GroupError::InvalidTreeResolution);
    }
    Ok(targets)
}

pub fn resolve_subtree(
    tree: &PublicTree,
    subtree_root: u32,
    excluded_nodes: &[u32],
) -> GroupResult<Vec<ResolvedPathTarget>> {
    validate_tree_node(tree, subtree_root)?;
    let node = tree_node(tree, subtree_root)?;
    if !subtree_has_occupied_leaf(tree, subtree_root)? {
        return Ok(Vec::new());
    }
    if let Some(node_key) = &node.node_key {
        if !excluded_nodes.contains(&subtree_root) {
            return Ok(vec![ResolvedPathTarget {
                node_index: subtree_root,
                node_key: node_key.clone(),
            }]);
        }
    }
    if is_leaf_node(tree, subtree_root)? {
        return Ok(Vec::new());
    }

    let mut resolved = resolve_subtree(tree, left_child(subtree_root)?, excluded_nodes)?;
    resolved.extend(resolve_subtree(
        tree,
        right_child(subtree_root)?,
        excluded_nodes,
    )?);
    resolved.sort_by_key(|target| target.node_index);
    if resolved
        .windows(2)
        .any(|pair| pair[0].node_index == pair[1].node_index)
    {
        return Err(GroupError::InvalidTreeResolution);
    }
    Ok(resolved)
}

fn tree_node(tree: &PublicTree, node_index: u32) -> GroupResult<&crate::PublicTreeNode> {
    validate_tree_node(tree, node_index)?;
    tree.nodes
        .get(usize::try_from(node_index).map_err(|_| GroupError::CounterExhausted)?)
        .ok_or(GroupError::InvalidTreeNode { node_index })
}

fn validate_tree_node(tree: &PublicTree, node_index: u32) -> GroupResult<()> {
    let exclusive = tree
        .leaf_capacity
        .checked_mul(2)
        .ok_or(GroupError::CounterExhausted)?;
    if (ROOT_NODE_INDEX..exclusive).contains(&node_index) {
        Ok(())
    } else {
        Err(GroupError::InvalidTreeNode { node_index })
    }
}

fn is_leaf_node(tree: &PublicTree, node_index: u32) -> GroupResult<bool> {
    validate_tree_node(tree, node_index)?;
    Ok(node_index >= tree.leaf_capacity)
}

fn subtree_has_occupied_leaf(tree: &PublicTree, node_index: u32) -> GroupResult<bool> {
    let node = tree_node(tree, node_index)?;
    if is_leaf_node(tree, node_index)? {
        return Ok(node.leaf.is_some());
    }
    Ok(subtree_has_occupied_leaf(tree, left_child(node_index)?)?
        || subtree_has_occupied_leaf(tree, right_child(node_index)?)?)
}
