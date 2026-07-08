use crate::{
    GroupError, GroupMode, GroupResult, GroupState, MemberStatus, MembershipPrivateState,
    PublicLeaf, PublicTree, UpdatePath,
};

use super::{
    membership::{remap_roster_slots_for_mode, removed_member_for_change},
    types::CommitChange,
};

pub(crate) fn apply_update_path_to_public_tree(
    state: &GroupState,
    update_path: &UpdatePath,
    change: &CommitChange,
) -> GroupResult<Option<PublicTree>> {
    let target_mode = match change {
        CommitChange::ModeChange { new_mode, .. } => *new_mode,
        _ => state.mode,
    };
    let old_tree = match &state.membership {
        MembershipPrivateState::TreeKem { public_tree, .. } => Some(public_tree),
        _ => None,
    };
    let mut candidate = if matches!(change, CommitChange::ModeChange { .. }) {
        build_mode_change_public_tree(state, target_mode, old_tree)?
    } else {
        old_tree.cloned().ok_or(GroupError::InvalidState)?
    };
    if candidate.mode != target_mode || update_path.leaf_capacity != candidate.leaf_capacity {
        return Err(GroupError::InvalidUpdatePath);
    }
    if let Some(member_id) = removed_member_for_change(change) {
        let entry = state
            .roster
            .iter()
            .find(|entry| entry.member_id == member_id)
            .ok_or(GroupError::MemberNotFound { member_id })?;
        candidate.vacate_leaf(entry.tree_leaf_slot)?;
    }
    if let CommitChange::RoleChange {
        member_id,
        new_role,
    } = change
    {
        let entry = state
            .roster
            .iter()
            .find(|entry| entry.member_id == *member_id)
            .ok_or(GroupError::MemberNotFound {
                member_id: *member_id,
            })?;
        candidate.update_leaf_role(entry.tree_leaf_slot, *new_role)?;
    }
    for node in &update_path.updated_nodes {
        candidate.set_node_key(node.node_index, Some(node.node_key.clone()))?;
    }
    if candidate.tree_hash()? != update_path.candidate_tree_hash {
        return Err(GroupError::InvalidUpdatePath);
    }
    Ok(Some(candidate))
}

fn build_mode_change_public_tree(
    state: &GroupState,
    target_mode: GroupMode,
    old_tree: Option<&PublicTree>,
) -> GroupResult<PublicTree> {
    let mut roster = state.roster.clone();
    remap_roster_slots_for_mode(target_mode, &mut roster)?;
    let mut tree = PublicTree::new(target_mode, Some(state.epoch))?;
    for entry in roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active)
    {
        let old_leaf = old_tree.and_then(|tree| {
            tree.nodes
                .iter()
                .filter_map(|node| node.leaf.as_ref())
                .find(|leaf| leaf.member_id == entry.member_id)
        });
        let leaf = PublicLeaf {
            member_id: entry.member_id,
            device_identity_fingerprint: entry.device_identity_fingerprint,
            role: entry.role,
            generation: old_leaf.map_or(0, |leaf| leaf.generation),
            node_key: old_leaf.and_then(|leaf| leaf.node_key.clone()),
        };
        tree.occupy_leaf(entry.tree_leaf_slot, leaf)?;
    }
    Ok(tree)
}
