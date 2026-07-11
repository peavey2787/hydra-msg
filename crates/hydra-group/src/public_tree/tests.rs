use super::*;
use crate::{GroupError, GroupMode, GroupRole, MemberId, MembershipMechanism};
use hydra_core::{
    types::{Epoch, IdentityFingerprint},
    ML_KEM_768_EK_SIZE,
};

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
    let parent_with_key = parent_node_hash(128, &occupied, &vacant_a, Some(&node_key(9))).unwrap();
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
