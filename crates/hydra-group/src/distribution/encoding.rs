use hydra_core::SUITE_ID;
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

use crate::{checked_u16_be, lp, u32_be, GroupResult, NODE_KEY_PRESENT};

use super::{
    validation::{sort_and_validate_path_ciphertexts, sort_and_validate_updated_nodes},
    UpdatePath,
};

const LABEL_UPDATE_PATH_HASH: &[u8] = b"HYDRA-MSG/v1/group/tree/update-path-hash";

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
