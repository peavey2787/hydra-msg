use hydra_core::{
    types::{LeafIndex, Secret32},
    ML_KEM_768_EK_SIZE,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};
use ml_kem::{
    kem::{FromSeed, KeyExport},
    MlKem768, Seed,
};

use crate::{
    direct_path, GroupError, GroupMode, GroupResult, PublicNodeKey, PublicTree, ROOT_NODE_INDEX,
};

use super::{
    encoding::{
        encode_path_context, encode_root_context, hkdf_info, LABEL_TREE_NODE_SEED, LABEL_TREE_PATH,
        LABEL_TREE_ROOT,
    },
    DerivedPublicPathNode, PrivatePath, PrivatePathNodeSecret, TreeKemPathContext,
    TreeKemPathUpdate,
};

pub fn derive_and_install_path(
    tree: &mut PublicTree,
    private_path: &mut PrivatePath,
    context: TreeKemPathContext,
    leaf_secret: &Secret32,
) -> GroupResult<TreeKemPathUpdate> {
    if tree.mode != context.mode {
        return Err(GroupError::InvalidState);
    }

    let direct_path = parent_path(context.mode, context.leaf_slot)?;
    if direct_path.last().copied() != Some(ROOT_NODE_INDEX) {
        return Err(GroupError::InvalidTreePath);
    }

    let mut candidate_tree = tree.clone();
    let mut candidate_private_path = Vec::with_capacity(direct_path.len());
    let mut updated_nodes = Vec::with_capacity(direct_path.len());
    let mut current_secret = Secret32::new(*leaf_secret.expose_for_backend());

    for node_index in &direct_path {
        let node_context = encode_path_context(&context, *node_index)?;
        let path_secret = derive_secret32(&current_secret, LABEL_TREE_PATH, &node_context)?;
        let mut next_current = Secret32::new(*path_secret.expose_for_backend());
        let node_seed = derive_node_seed(&path_secret, &node_context)?;
        let node_key = mlkem_node_key_from_seed(node_seed)?;

        candidate_tree.set_node_key(*node_index, Some(node_key.clone()))?;
        updated_nodes.push(DerivedPublicPathNode {
            node_index: *node_index,
            node_key,
        });

        candidate_private_path.push(PrivatePathNodeSecret {
            node_index: *node_index,
            path_secret,
            node_seed_d: Secret32::new(node_seed[0]),
            node_seed_z: Secret32::new(node_seed[1]),
        });
        current_secret.wipe();
        current_secret = Secret32::new(*next_current.expose_for_backend());
        next_current.wipe();
    }

    let root_context = encode_root_context(&context, &direct_path)?;
    let root_secret = derive_secret32(&current_secret, LABEL_TREE_ROOT, &root_context)?;
    current_secret.wipe();
    let tree_hash_after = candidate_tree.tree_hash()?;
    let tree_version_after = candidate_tree.tree_version;

    *tree = candidate_tree;
    private_path.replace_with(LeafIndex(context.leaf_slot), candidate_private_path);

    Ok(TreeKemPathUpdate {
        leaf_slot: context.leaf_slot,
        direct_path,
        updated_nodes,
        root_secret,
        tree_hash_after,
        tree_version_after,
    })
}

pub fn parent_path(mode: GroupMode, leaf_slot: u32) -> GroupResult<Vec<u32>> {
    let mut path = direct_path(mode, leaf_slot)?;
    if path.is_empty() {
        return Err(GroupError::InvalidTreePath);
    }
    path.remove(0);
    if path.is_empty() || path.last().copied() != Some(ROOT_NODE_INDEX) {
        return Err(GroupError::InvalidTreePath);
    }
    Ok(path)
}

fn derive_secret32(secret: &Secret32, label: &[u8], context: &[u8]) -> GroupResult<Secret32> {
    let info = hkdf_info(label, context)?;
    let output = RustCryptoBackend::hkdf_expand(secret.expose_for_backend(), &info, 32)
        .map_err(|_| GroupError::InvalidTreePath)?;
    let bytes: [u8; 32] = output
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)?;
    Ok(Secret32::new(bytes))
}

fn derive_node_seed(path_secret: &Secret32, context: &[u8]) -> GroupResult<[[u8; 32]; 2]> {
    let info = hkdf_info(LABEL_TREE_NODE_SEED, context)?;
    let output = RustCryptoBackend::hkdf_expand(path_secret.expose_for_backend(), &info, 64)
        .map_err(|_| GroupError::InvalidTreePath)?;
    let d: [u8; 32] = output[0..32]
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)?;
    let z: [u8; 32] = output[32..64]
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)?;
    Ok([d, z])
}

fn mlkem_node_key_from_seed(mut node_seed: [[u8; 32]; 2]) -> GroupResult<PublicNodeKey> {
    let mut seed_bytes = [0_u8; 64];
    seed_bytes[..32].copy_from_slice(&node_seed[0]);
    seed_bytes[32..].copy_from_slice(&node_seed[1]);
    let mut seed: Seed = seed_bytes.into();
    let (_decapsulation, encapsulation) = MlKem768::from_seed(&seed);
    let encoded = encapsulation.to_bytes();
    let mut output = [0_u8; ML_KEM_768_EK_SIZE];
    output.copy_from_slice(encoded.as_ref());
    seed.as_mut_slice().fill(0);
    seed_bytes.fill(0);
    node_seed[0].fill(0);
    node_seed[1].fill(0);
    Ok(PublicNodeKey(output))
}
