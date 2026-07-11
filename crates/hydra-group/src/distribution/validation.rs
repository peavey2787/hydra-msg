use crate::{DerivedPublicPathNode, GroupError, GroupResult};

use super::PathCiphertext;

pub(super) fn sort_and_validate_updated_nodes(
    nodes: &mut [DerivedPublicPathNode],
) -> GroupResult<()> {
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

pub(super) fn sort_and_validate_path_ciphertexts(
    ciphertexts: &mut [PathCiphertext],
) -> GroupResult<()> {
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
