use hydra_core::{
    types::{Epoch, GroupId, LeafIndex, Secret32},
    AEAD_NONCE_SIZE, AEAD_TAG_SIZE, ML_KEM_768_CT_SIZE, SUITE_ID,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use ml_kem::{ml_kem_768::EncapsulationKey, B32};

use crate::{
    checked_u16_be, left_child, lp, parent_index, right_child, sibling_index, u32_be, u64_be,
    DerivedPublicPathNode, GroupError, GroupMode, GroupResult, PrivatePath, PublicNodeKey,
    PublicTree, StateVersion, TreeKemPathUpdate, NODE_KEY_PRESENT, ROOT_NODE_INDEX,
};

const LABEL_WRAP_SALT: &[u8] = b"HYDRA-MSG/v1/group/tree/wrap-salt";
const LABEL_WRAP_KEY: &[u8] = b"HYDRA-MSG/v1/group/tree/wrap-key";
const LABEL_WRAP_ENTROPY: &[u8] = b"HYDRA-MSG/v1/group/tree/wrap-entropy";
const LABEL_UPDATE_PATH_HASH: &[u8] = b"HYDRA-MSG/v1/group/tree/update-path-hash";

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
pub struct ResolvedPathTarget {
    pub node_index: u32,
    pub node_key: PublicNodeKey,
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
    pub updated_nodes: Vec<DerivedPublicPathNode>,
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

pub fn encode_update_path(update_path: &UpdatePath) -> GroupResult<Vec<u8>> {
    let mut updated_nodes = update_path.updated_nodes.clone();
    sort_and_validate_updated_nodes(&mut updated_nodes)?;
    let mut path_ciphertexts = update_path.path_ciphertexts.clone();
    sort_and_validate_path_ciphertexts(&mut path_ciphertexts)?;

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&u32_be(update_path.committer_leaf_index.0));
    encoded.extend_from_slice(&u32_be(update_path.leaf_capacity));
    encoded.extend_from_slice(&checked_u16_be(updated_nodes.len())?);
    for node in &updated_nodes {
        encoded.extend_from_slice(&u32_be(node.node_index));
        encoded.push(NODE_KEY_PRESENT);
        encoded.extend_from_slice(&node.node_key.0);
    }
    encoded.extend_from_slice(&checked_u16_be(path_ciphertexts.len())?);
    for ciphertext in &path_ciphertexts {
        encoded.extend_from_slice(&u32_be(ciphertext.parent_node_index));
        encoded.extend_from_slice(&u32_be(ciphertext.target_node_index));
        encoded.extend_from_slice(&ciphertext.kem_ciphertext);
        encoded.extend_from_slice(&ciphertext.wrapped_path_secret);
    }
    encoded.extend_from_slice(&update_path.candidate_tree_hash);
    Ok(encoded)
}

pub fn update_path_hash(update_path: &UpdatePath) -> GroupResult<[u8; 64]> {
    let encoded = encode_update_path(update_path)?;
    let mut input = Vec::new();
    input.extend_from_slice(LABEL_UPDATE_PATH_HASH);
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&lp(&encoded)?);
    Ok(RustCryptoBackend::sha3_512(&input))
}

pub fn wrap_context(
    context: &TreeKemWrapContext,
    parent_node_index: u32,
    target_node_index: u32,
) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&context.group_id.0);
    encoded.push(context.mode as u8);
    encoded.extend_from_slice(&u64_be(context.new_epoch.0));
    encoded.extend_from_slice(&u64_be(context.new_state_version.0));
    encoded.extend_from_slice(&context.commit_nonce);
    encoded.extend_from_slice(&u32_be(parent_node_index));
    encoded.extend_from_slice(&u32_be(target_node_index));
    encoded.extend_from_slice(&context.tree_hash);
    Ok(encoded)
}

fn wrap_path_secret(
    context: &TreeKemWrapContext,
    parent_node_index: u32,
    target_node_index: u32,
    node_key: &PublicNodeKey,
    path_secret: &Secret32,
) -> GroupResult<PathCiphertext> {
    let wrap_context = wrap_context(context, parent_node_index, target_node_index)?;
    let (kem_ciphertext, mut kem_shared_secret) =
        deterministic_encapsulate(node_key, &wrap_context)?;
    let wrap_key = derive_wrap_key(&wrap_context, &kem_shared_secret)?;
    kem_shared_secret.fill(0);

    let mut aad = Vec::with_capacity(wrap_context.len() + kem_ciphertext.len());
    aad.extend_from_slice(&wrap_context);
    aad.extend_from_slice(&kem_ciphertext);
    let sealed = RustCryptoBackend::aead_seal(
        &SecretBytes::from_array(wrap_key),
        &[0_u8; AEAD_NONCE_SIZE],
        &aad,
        path_secret.expose_for_backend(),
    )
    .map_err(|_| GroupError::InvalidTreePath)?;
    let wrapped_path_secret: [u8; WRAPPED_PATH_SECRET_SIZE] = sealed
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)?;
    Ok(PathCiphertext {
        parent_node_index,
        target_node_index,
        kem_ciphertext,
        wrapped_path_secret,
    })
}

fn deterministic_encapsulate(
    node_key: &PublicNodeKey,
    wrap_context: &[u8],
) -> GroupResult<([u8; ML_KEM_768_CT_SIZE], [u8; 32])> {
    let mut encoded_key = ml_kem::kem::Key::<EncapsulationKey>::default();
    encoded_key.copy_from_slice(&node_key.0);
    let encapsulation_key =
        EncapsulationKey::new(&encoded_key).map_err(|_| GroupError::InvalidTreeResolution)?;
    let wrap_entropy = derive_wrap_entropy(wrap_context)?;
    let mut entropy: B32 = wrap_entropy.into();
    let (ciphertext, mut shared_secret) = encapsulation_key.encapsulate_deterministic(&entropy);
    entropy.as_mut_slice().fill(0);
    let mut encoded_ciphertext = [0_u8; ML_KEM_768_CT_SIZE];
    encoded_ciphertext.copy_from_slice(ciphertext.as_ref());
    let mut encoded_shared_secret = [0_u8; 32];
    encoded_shared_secret.copy_from_slice(shared_secret.as_ref());
    shared_secret.as_mut_slice().fill(0);
    Ok((encoded_ciphertext, encoded_shared_secret))
}

fn derive_wrap_entropy(wrap_context: &[u8]) -> GroupResult<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(&lp(LABEL_WRAP_ENTROPY)?);
    info.extend_from_slice(&lp(wrap_context)?);
    let output = RustCryptoBackend::hkdf_expand(&[0_u8; 32], &info, 32)
        .map_err(|_| GroupError::InvalidTreePath)?;
    output
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)
}

fn derive_wrap_key(wrap_context: &[u8], kem_shared_secret: &[u8]) -> GroupResult<[u8; 32]> {
    let mut salt_input = Vec::new();
    salt_input.extend_from_slice(LABEL_WRAP_SALT);
    salt_input.extend_from_slice(&SUITE_ID);
    salt_input.extend_from_slice(&lp(wrap_context)?);
    let salt = RustCryptoBackend::sha3_512(&salt_input);
    let wrap_prk = RustCryptoBackend::hkdf_extract(&salt, kem_shared_secret);
    let mut info = Vec::new();
    info.extend_from_slice(&lp(LABEL_WRAP_KEY)?);
    info.extend_from_slice(&lp(wrap_context)?);
    let output = RustCryptoBackend::hkdf_expand(wrap_prk.expose_secret(), &info, 32)
        .map_err(|_| GroupError::InvalidTreePath)?;
    output
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)
}

fn private_path_secret(private_path: &PrivatePath, node_index: u32) -> GroupResult<&Secret32> {
    private_path
        .path
        .iter()
        .find(|secret| secret.node_index == node_index)
        .map(|secret| &secret.path_secret)
        .ok_or(GroupError::InvalidTreePath)
}

fn sort_and_validate_updated_nodes(nodes: &mut [DerivedPublicPathNode]) -> GroupResult<()> {
    if nodes.is_empty() {
        return Err(GroupError::InvalidUpdatePath);
    }
    nodes.sort_by_key(|node| node.node_index);
    if nodes
        .windows(2)
        .any(|pair| pair[0].node_index == pair[1].node_index)
    {
        return Err(GroupError::InvalidUpdatePath);
    }
    Ok(())
}

fn sort_and_validate_path_ciphertexts(ciphertexts: &mut [PathCiphertext]) -> GroupResult<()> {
    ciphertexts
        .sort_by_key(|ciphertext| (ciphertext.parent_node_index, ciphertext.target_node_index));
    if ciphertexts.windows(2).any(|pair| {
        pair[0].parent_node_index == pair[1].parent_node_index
            && pair[0].target_node_index == pair[1].target_node_index
    }) {
        return Err(GroupError::InvalidUpdatePath);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_and_install_path, PublicLeaf, StateVersion, TreeKemPathContext};
    use hydra_core::types::IdentityFingerprint;

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
            derive_and_install_path(&mut tree, &mut private_path, context, &leaf_secret(0x44))
                .unwrap();
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
}
