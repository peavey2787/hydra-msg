use hydra_core::{
    types::{Epoch, GroupId, LeafIndex},
    AEAD_TAG_SIZE, ML_KEM_768_CT_SIZE,
};

use crate::{
    GroupError, GroupMode, GroupResult, PrivatePath, PublicNodeKey, PublicTree, StateVersion,
    TreeKemPathUpdate,
};

mod encoding;
mod targets;
mod validation;
mod wrapping;

#[cfg(test)]
mod tests;

pub use encoding::{encode_update_path, update_path_hash};
pub use targets::{resolve_subtree, resolve_update_path_targets, ResolvedPathTarget};
pub use wrapping::wrap_context;

use validation::sort_and_validate_path_ciphertexts;
use wrapping::{private_path_secret, wrap_path_secret};

pub const WRAPPED_PATH_SECRET_SIZE: usize = 32 + AEAD_TAG_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeKemWrapContext {
    pub group_id: GroupId,
    pub mode: GroupMode,
    pub new_epoch: Epoch,
    pub new_state_version: StateVersion,
    pub commit_nonce: [u8; 32],
    pub tree_hash: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathSecretTarget {
    pub parent_node_index: u32,
    pub target_node_index: u32,
    pub node_key: PublicNodeKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathCiphertext {
    pub parent_node_index: u32,
    pub target_node_index: u32,
    pub kem_ciphertext: [u8; ML_KEM_768_CT_SIZE],
    pub wrapped_path_secret: [u8; WRAPPED_PATH_SECRET_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePath {
    pub committer_leaf_index: LeafIndex,
    pub leaf_capacity: u32,
    pub updated_nodes: Vec<crate::DerivedPublicPathNode>,
    pub path_ciphertexts: Vec<PathCiphertext>,
    pub candidate_tree_hash: [u8; 64],
}

pub fn encrypt_path_updates(
    tree: &PublicTree,
    private_path: &PrivatePath,
    context: TreeKemWrapContext,
    path_update: &TreeKemPathUpdate,
    excluded_nodes: &[u32],
) -> GroupResult<UpdatePath> {
    if tree.mode != context.mode || path_update.tree_hash_after != context.tree_hash {
        return Err(GroupError::InvalidState);
    }
    if private_path.leaf_index != Some(LeafIndex(path_update.leaf_slot)) {
        return Err(GroupError::InvalidTreePath);
    }
    if private_path.node_indices() != path_update.direct_path {
        return Err(GroupError::InvalidTreePath);
    }

    let targets = resolve_update_path_targets(tree, path_update.leaf_slot, excluded_nodes)?;
    let mut path_ciphertexts = Vec::with_capacity(targets.len());
    for target in targets {
        let path_secret = private_path_secret(private_path, target.parent_node_index)?;
        path_ciphertexts.push(wrap_path_secret(
            &context,
            target.parent_node_index,
            target.target_node_index,
            &target.node_key,
            path_secret,
        )?);
    }
    sort_and_validate_path_ciphertexts(&mut path_ciphertexts)?;

    let update_path = UpdatePath {
        committer_leaf_index: LeafIndex(path_update.leaf_slot),
        leaf_capacity: tree.leaf_capacity,
        updated_nodes: path_update.updated_nodes.clone(),
        path_ciphertexts,
        candidate_tree_hash: path_update.tree_hash_after,
    };
    encode_update_path(&update_path)?;
    Ok(update_path)
}
