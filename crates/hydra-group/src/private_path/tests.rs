use super::*;
use crate::{GroupError, GroupMode, PublicTree, StateVersion, ROOT_NODE_INDEX};
use hydra_core::types::{Epoch, GroupId, LeafIndex, Secret32};

fn group_id(value: u8) -> GroupId {
    GroupId([value; 32])
}

fn leaf_secret(value: u8) -> Secret32 {
    Secret32::new([value; 32])
}

fn context(
    mode: GroupMode,
    leaf_slot: u32,
    epoch: u64,
    state_version: u64,
    nonce: u8,
    tree_hash: [u8; 64],
) -> TreeKemPathContext {
    TreeKemPathContext {
        group_id: group_id(0x42),
        mode,
        epoch: Epoch(epoch),
        state_version: StateVersion(state_version),
        leaf_slot,
        commit_nonce: [nonce; 32],
        tree_hash,
    }
}

fn derive_once(context: TreeKemPathContext) -> (TreeKemPathUpdate, PublicTree, PrivatePath) {
    let mut tree = PublicTree::new(context.mode, Some(context.epoch)).unwrap();
    let before_hash = tree.tree_hash().unwrap();
    let mut context = context;
    if context.tree_hash == [0; 64] {
        context.tree_hash = before_hash;
    }
    let mut private_path = PrivatePath::default();
    let secret = leaf_secret(0x33);
    let update = derive_and_install_path(&mut tree, &mut private_path, context, &secret).unwrap();
    (update, tree, private_path)
}

#[test]
fn parent_path_excludes_leaf_and_includes_root_once() {
    assert_eq!(
        parent_path(GroupMode::Interactive, 0).unwrap(),
        vec![128, 64, 32, 16, 8, 4, 2, 1]
    );
    assert_eq!(
        parent_path(GroupMode::Interactive, 255)
            .unwrap()
            .last()
            .copied(),
        Some(ROOT_NODE_INDEX)
    );
    assert_eq!(
        parent_path(GroupMode::Interactive, 256),
        Err(GroupError::InvalidTreeSlot {
            slot: 256,
            capacity: 256,
        })
    );
}

#[test]
fn same_inputs_reproduce_same_path_secrets_and_node_keys() {
    let c = context(GroupMode::Interactive, 7, 9, 11, 0x55, [0x44; 64]);
    let (left, left_tree, left_path) = derive_once(c);
    let (right, right_tree, right_path) = derive_once(c);
    assert_eq!(left.direct_path, right.direct_path);
    assert_eq!(left.updated_nodes, right.updated_nodes);
    assert_eq!(
        left.root_secret.expose_for_backend(),
        right.root_secret.expose_for_backend()
    );
    assert_eq!(left.tree_hash_after, right.tree_hash_after);
    assert_eq!(left_tree.tree_hash(), right_tree.tree_hash());
    assert_eq!(left_path.node_indices(), right_path.node_indices());
}

#[test]
fn nonce_epoch_and_state_version_change_outputs() {
    let base = context(GroupMode::Interactive, 7, 9, 11, 0x55, [0x44; 64]);
    let changed_nonce = context(GroupMode::Interactive, 7, 9, 11, 0x56, [0x44; 64]);
    let changed_epoch = context(GroupMode::Interactive, 7, 10, 11, 0x55, [0x44; 64]);
    let changed_version = context(GroupMode::Interactive, 7, 9, 12, 0x55, [0x44; 64]);
    let base_update = derive_once(base).0;
    assert_ne!(
        base_update.root_secret.expose_for_backend(),
        derive_once(changed_nonce)
            .0
            .root_secret
            .expose_for_backend()
    );
    assert_ne!(
        base_update.updated_nodes,
        derive_once(changed_epoch).0.updated_nodes
    );
    assert_ne!(
        base_update.tree_hash_after,
        derive_once(changed_version).0.tree_hash_after
    );
}

#[test]
fn private_path_contains_only_parent_direct_path_nodes() {
    let c = context(GroupMode::Interactive, 3, 1, 1, 0x77, [0x22; 64]);
    let (update, _tree, private_path) = derive_once(c);
    assert_eq!(private_path.leaf_index, Some(LeafIndex(3)));
    assert_eq!(private_path.node_indices(), update.direct_path);
    assert!(!private_path
        .node_indices()
        .contains(&leaf_node_for_interactive_slot(3)));
    assert_eq!(
        private_path.node_indices().last().copied(),
        Some(ROOT_NODE_INDEX)
    );
}

#[test]
fn failed_derivation_preserves_parent_state() {
    let mut tree = PublicTree::new(GroupMode::Interactive, Some(Epoch(1))).unwrap();
    let mut private_path = PrivatePath::default();
    let original_tree = tree.clone();
    let original_private_indices = private_path.node_indices();
    let secret = leaf_secret(0x33);
    let bad_context = context(GroupMode::Broadcast, 0, 1, 1, 0x88, [0x11; 64]);
    assert_eq!(
        derive_and_install_path(&mut tree, &mut private_path, bad_context, &secret).map(|_| ()),
        Err(GroupError::InvalidState)
    );
    assert_eq!(tree, original_tree);
    assert_eq!(private_path.node_indices(), original_private_indices);
}

#[test]
fn clear_removes_installed_private_path() {
    let c = context(GroupMode::Interactive, 3, 1, 1, 0x77, [0x22; 64]);
    let (_update, _tree, mut private_path) = derive_once(c);
    assert!(!private_path.is_empty());
    private_path.clear();
    assert!(private_path.is_empty());
    assert_eq!(private_path.leaf_index, None);
}

const fn leaf_node_for_interactive_slot(slot: u32) -> u32 {
    256 + slot
}
