use hydra_core::{
    types::{Epoch, GroupId, LeafIndex, Secret32},
    ML_KEM_768_EK_SIZE, SUITE_ID,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};
use ml_kem::{
    kem::{FromSeed, KeyExport},
    MlKem768, Seed,
};

use crate::{
    direct_path, lp, u32_be, u64_be, GroupError, GroupMode, GroupResult, PublicNodeKey, PublicTree,
    StateVersion, ROOT_NODE_INDEX,
};

const LABEL_TREE_PATH: &[u8] = b"HYDRA-MSG/v1/group/tree/path";
const LABEL_TREE_NODE_SEED: &[u8] = b"HYDRA-MSG/v1/group/tree/node-seed";
const LABEL_TREE_ROOT: &[u8] = b"HYDRA-MSG/v1/group/tree/root";

pub struct PrivatePathNodeSecret {
    pub node_index: u32,
    pub path_secret: Secret32,
    pub node_seed_d: Secret32,
    pub node_seed_z: Secret32,
}

impl PrivatePathNodeSecret {
    pub fn clear(&mut self) {
        self.path_secret.wipe();
        self.node_seed_d.wipe();
        self.node_seed_z.wipe();
    }
}

impl Drop for PrivatePathNodeSecret {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Default)]
pub struct PrivatePath {
    pub leaf_index: Option<LeafIndex>,
    pub path: Vec<PrivatePathNodeSecret>,
}

impl PrivatePath {
    #[must_use]
    pub fn len(&self) -> usize {
        self.path.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }

    #[must_use]
    pub fn node_indices(&self) -> Vec<u32> {
        self.path.iter().map(|node| node.node_index).collect()
    }

    pub fn replace_with(&mut self, leaf_index: LeafIndex, path: Vec<PrivatePathNodeSecret>) {
        self.clear();
        self.leaf_index = Some(leaf_index);
        self.path = path;
    }

    pub fn clear(&mut self) {
        for node in &mut self.path {
            node.clear();
        }
        self.path.clear();
        self.leaf_index = None;
    }
}

impl Drop for PrivatePath {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeKemPathContext {
    pub group_id: GroupId,
    pub mode: GroupMode,
    pub epoch: Epoch,
    pub state_version: StateVersion,
    pub leaf_slot: u32,
    pub commit_nonce: [u8; 32],
    pub tree_hash: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedPublicPathNode {
    pub node_index: u32,
    pub node_key: PublicNodeKey,
}

pub struct TreeKemPathUpdate {
    pub leaf_slot: u32,
    pub direct_path: Vec<u32>,
    pub updated_nodes: Vec<DerivedPublicPathNode>,
    pub root_secret: Secret32,
    pub tree_hash_after: [u8; 64],
    pub tree_version_after: u64,
}

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

fn encode_path_context(context: &TreeKemPathContext, node_index: u32) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SUITE_ID);
    encoded.extend_from_slice(&context.group_id.0);
    encoded.push(context.mode as u8);
    encoded.extend_from_slice(&u64_be(context.epoch.0));
    encoded.extend_from_slice(&u64_be(context.state_version.0));
    encoded.extend_from_slice(&u32_be(context.leaf_slot));
    encoded.extend_from_slice(&u32_be(node_index));
    encoded.extend_from_slice(&context.commit_nonce);
    encoded.extend_from_slice(&context.tree_hash);
    lp(&encoded)
}

fn encode_root_context(context: &TreeKemPathContext, direct_path: &[u32]) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SUITE_ID);
    encoded.extend_from_slice(&context.group_id.0);
    encoded.push(context.mode as u8);
    encoded.extend_from_slice(&u64_be(context.epoch.0));
    encoded.extend_from_slice(&u64_be(context.state_version.0));
    encoded.extend_from_slice(&u32_be(context.leaf_slot));
    encoded.extend_from_slice(&context.commit_nonce);
    encoded.extend_from_slice(&context.tree_hash);
    encoded.extend_from_slice(&u32_be(
        u32::try_from(direct_path.len()).map_err(|_| GroupError::CounterExhausted)?,
    ));
    for node_index in direct_path {
        encoded.extend_from_slice(&u32_be(*node_index));
    }
    lp(&encoded)
}

fn hkdf_info(label: &[u8], context: &[u8]) -> GroupResult<Vec<u8>> {
    let mut info = Vec::new();
    info.extend_from_slice(&lp(label)?);
    info.extend_from_slice(&lp(context)?);
    Ok(info)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicTree;

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
        let update =
            derive_and_install_path(&mut tree, &mut private_path, context, &secret).unwrap();
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
}
