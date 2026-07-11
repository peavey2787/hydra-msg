use super::*;
use crate::{
    derive_and_install_path, GroupMode, PrivatePath, PublicLeaf, PublicNodeKey, PublicTree,
    StateVersion, TreeKemPathContext, TreeKemPathUpdate,
};
use hydra_core::types::{Epoch, GroupId, IdentityFingerprint, Secret32};

fn group_id(value: u8) -> GroupId {
    GroupId([value; 32])
}

fn member(value: u8) -> crate::MemberId {
    crate::MemberId([value; 32])
}

fn fingerprint(value: u8) -> IdentityFingerprint {
    IdentityFingerprint([value; 32])
}

fn leaf(member_value: u8, node_key: PublicNodeKey) -> PublicLeaf {
    PublicLeaf {
        member_id: member(member_value),
        device_identity_fingerprint: fingerprint(member_value + 1),
        role: crate::GroupRole::Member,
        generation: 0,
        node_key: Some(node_key),
    }
}

fn path_context(
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

fn wrap_context_for(update: &TreeKemPathUpdate, nonce: u8) -> TreeKemWrapContext {
    TreeKemWrapContext {
        group_id: group_id(0x42),
        mode: GroupMode::Interactive,
        new_epoch: Epoch(2),
        new_state_version: StateVersion(3),
        commit_nonce: [nonce; 32],
        tree_hash: update.tree_hash_after,
    }
}

fn leaf_secret(value: u8) -> Secret32 {
    Secret32::new([value; 32])
}

fn derive_valid_node_key(seed: u8) -> PublicNodeKey {
    let mut tree = PublicTree::new(GroupMode::Interactive, Some(Epoch(1))).unwrap();
    let mut private_path = PrivatePath::default();
    let before_hash = tree.tree_hash().unwrap();
    let context = path_context(GroupMode::Interactive, 5, 1, 1, seed, before_hash);
    derive_and_install_path(&mut tree, &mut private_path, context, &leaf_secret(seed))
        .unwrap()
        .updated_nodes
        .remove(0)
        .node_key
}

fn wrapped_fixture() -> (
    PublicTree,
    PrivatePath,
    TreeKemPathUpdate,
    TreeKemWrapContext,
) {
    let recipient_key = derive_valid_node_key(0x21);
    let mut tree = PublicTree::new(GroupMode::Interactive, Some(Epoch(1))).unwrap();
    tree.occupy_leaf(1, leaf(1, recipient_key.clone())).unwrap();
    tree.set_node_key(3, Some(recipient_key)).unwrap();
    tree.occupy_leaf(255, leaf(2, derive_valid_node_key(0x22)))
        .unwrap();

    let before_hash = tree.tree_hash().unwrap();
    let mut private_path = PrivatePath::default();
    let context = path_context(GroupMode::Interactive, 0, 1, 1, 0x33, before_hash);
    let update =
        derive_and_install_path(&mut tree, &mut private_path, context, &leaf_secret(0x44)).unwrap();
    let wrap = wrap_context_for(&update, 0x55);
    (tree, private_path, update, wrap)
}

#[test]
fn resolution_recurses_until_it_finds_authorized_public_keys() {
    let key = derive_valid_node_key(0x31);
    let mut tree = PublicTree::new(GroupMode::Interactive, Some(Epoch(1))).unwrap();
    tree.occupy_leaf(1, leaf(1, key.clone())).unwrap();
    let resolved = resolve_subtree(&tree, 257, &[]).unwrap();
    assert_eq!(
        resolved,
        vec![ResolvedPathTarget {
            node_index: 257,
            node_key: key.clone()
        }]
    );

    assert_eq!(resolve_subtree(&tree, 257, &[257]).unwrap(), Vec::new());
    tree.set_node_key(128, Some(key.clone())).unwrap();
    assert_eq!(resolve_subtree(&tree, 128, &[]).unwrap()[0].node_index, 128);
    let excluded_parent = resolve_subtree(&tree, 128, &[128]).unwrap();
    assert_eq!(
        excluded_parent,
        vec![ResolvedPathTarget {
            node_index: 257,
            node_key: key
        }]
    );
}

#[test]
fn update_path_targets_are_sorted_and_bound_to_parent_path_secrets() {
    let (tree, _private_path, _update, _wrap) = wrapped_fixture();
    let targets = resolve_update_path_targets(&tree, 0, &[]).unwrap();
    assert!(targets.windows(2).all(|pair| {
        (pair[0].parent_node_index, pair[0].target_node_index)
            < (pair[1].parent_node_index, pair[1].target_node_index)
    }));
    assert!(targets
        .iter()
        .any(|target| target.parent_node_index == 1 && target.target_node_index == 3));
    assert!(targets
        .iter()
        .any(|target| target.parent_node_index == 128 && target.target_node_index == 257));
}

#[test]
fn encrypt_path_updates_is_deterministic_for_same_inputs() {
    let (tree, private_path, update, wrap) = wrapped_fixture();
    let first = encrypt_path_updates(&tree, &private_path, wrap, &update, &[]).unwrap();
    let second = encrypt_path_updates(&tree, &private_path, wrap, &update, &[]).unwrap();
    assert_eq!(first, second);
    assert!(!first.path_ciphertexts.is_empty());
    assert_eq!(first.candidate_tree_hash, update.tree_hash_after);
    assert_eq!(first.committer_leaf_index, LeafIndex(update.leaf_slot));
    assert_eq!(first.leaf_capacity, tree.leaf_capacity);
}

#[test]
fn commit_nonce_and_tree_hash_change_wrapped_outputs() {
    let (tree, private_path, update, wrap) = wrapped_fixture();
    let baseline = encrypt_path_updates(&tree, &private_path, wrap, &update, &[]).unwrap();
    let changed_nonce = encrypt_path_updates(
        &tree,
        &private_path,
        TreeKemWrapContext {
            commit_nonce: [0x56; 32],
            ..wrap
        },
        &update,
        &[],
    )
    .unwrap();
    assert_ne!(baseline.path_ciphertexts, changed_nonce.path_ciphertexts);
}

#[test]
fn update_path_encoding_sorts_and_hashes_canonical_form() {
    let (tree, private_path, update, wrap) = wrapped_fixture();
    let mut path = encrypt_path_updates(&tree, &private_path, wrap, &update, &[]).unwrap();
    path.updated_nodes.reverse();
    path.path_ciphertexts.reverse();
    let encoded = encode_update_path(&path).unwrap();
    let hash = update_path_hash(&path).unwrap();
    assert_eq!(hash, update_path_hash(&path).unwrap());
    assert_eq!(encoded[0..4], update.leaf_slot.to_be_bytes());
    assert_eq!(encoded[4..8], tree.leaf_capacity.to_be_bytes());
}

#[test]
fn invalid_context_or_private_path_rejects_before_output() {
    let (tree, mut private_path, update, wrap) = wrapped_fixture();
    let bad_context = TreeKemWrapContext {
        tree_hash: [0xff; 64],
        ..wrap
    };
    assert_eq!(
        encrypt_path_updates(&tree, &private_path, bad_context, &update, &[]).map(|_| ()),
        Err(GroupError::InvalidState)
    );
    private_path.clear();
    assert_eq!(
        encrypt_path_updates(&tree, &private_path, wrap, &update, &[]).map(|_| ()),
        Err(GroupError::InvalidTreePath)
    );
}

#[test]
fn empty_or_duplicate_updated_nodes_reject_in_canonical_encoding() {
    let (_tree, _private_path, update, _wrap) = wrapped_fixture();
    let mut invalid = UpdatePath {
        committer_leaf_index: LeafIndex(update.leaf_slot),
        leaf_capacity: 256,
        updated_nodes: Vec::new(),
        path_ciphertexts: Vec::new(),
        candidate_tree_hash: update.tree_hash_after,
    };
    assert_eq!(
        encode_update_path(&invalid),
        Err(GroupError::InvalidUpdatePath)
    );
    invalid.updated_nodes = vec![
        update.updated_nodes[0].clone(),
        update.updated_nodes[0].clone(),
    ];
    assert_eq!(
        encode_update_path(&invalid),
        Err(GroupError::InvalidUpdatePath)
    );
}
