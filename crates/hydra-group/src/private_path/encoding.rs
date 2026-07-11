use hydra_core::SUITE_ID;

use crate::{lp, u32_be, u64_be, GroupError, GroupResult};

use super::TreeKemPathContext;

pub(super) const LABEL_TREE_PATH: &[u8] = b"HYDRA-MSG/v1/group/tree/path";
pub(super) const LABEL_TREE_NODE_SEED: &[u8] = b"HYDRA-MSG/v1/group/tree/node-seed";
pub(super) const LABEL_TREE_ROOT: &[u8] = b"HYDRA-MSG/v1/group/tree/root";

pub(super) fn encode_path_context(
    context: &TreeKemPathContext,
    node_index: u32,
) -> GroupResult<Vec<u8>> {
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

pub(super) fn encode_root_context(
    context: &TreeKemPathContext,
    direct_path: &[u32],
) -> GroupResult<Vec<u8>> {
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

pub(super) fn hkdf_info(label: &[u8], context: &[u8]) -> GroupResult<Vec<u8>> {
    let mut info = Vec::new();
    info.extend_from_slice(&lp(label)?);
    info.extend_from_slice(&lp(context)?);
    Ok(info)
}
