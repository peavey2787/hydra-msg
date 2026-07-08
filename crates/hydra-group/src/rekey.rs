use crate::private_path::PrivatePath;
use crate::public_tree::{PublicNodeKey, PublicTree};
use crate::{GroupError, GroupResult};
use hydra_core::{types::Epoch, ML_KEM_768_EK_SIZE};
use ml_kem::{
    kem::{FromSeed, KeyExport},
    MlKem768, Seed,
};

#[derive(Debug, PartialEq, Eq)]
pub struct RekeyUpdate {
    pub new_epoch: Epoch,
    pub tree_version: u64,
    pub changed_nodes: Vec<u32>,
}

pub fn rekey_path(tree: &mut PublicTree, path: &mut PrivatePath) -> GroupResult<RekeyUpdate> {
    if path.leaf_index.is_none() || path.path.is_empty() {
        return Err(GroupError::InvalidTreePath);
    }
    let new_epoch = match tree.epoch {
        Some(epoch) => crate::next_epoch(epoch)?,
        None => Epoch(0),
    };
    let mut candidate = tree.clone();
    let mut changed_nodes = Vec::with_capacity(path.path.len());
    for node in &path.path {
        let node_key = public_node_key_from_private_node_seed(
            node.node_seed_d.expose_for_backend(),
            node.node_seed_z.expose_for_backend(),
        );
        candidate.set_node_key(node.node_index, Some(node_key))?;
        if changed_nodes.contains(&node.node_index) {
            return Err(GroupError::InvalidTreePath);
        }
        changed_nodes.push(node.node_index);
    }
    candidate.epoch = Some(new_epoch);
    *tree = candidate;
    Ok(RekeyUpdate {
        new_epoch,
        tree_version: tree.tree_version,
        changed_nodes,
    })
}

fn public_node_key_from_private_node_seed(d: &[u8; 32], z: &[u8; 32]) -> PublicNodeKey {
    let mut seed_bytes = [0_u8; 64];
    seed_bytes[..32].copy_from_slice(d);
    seed_bytes[32..].copy_from_slice(z);
    let mut seed: Seed = seed_bytes.into();
    let (_decapsulation, encapsulation) = MlKem768::from_seed(&seed);
    let encoded = encapsulation.to_bytes();
    let mut output = [0_u8; ML_KEM_768_EK_SIZE];
    output.copy_from_slice(encoded.as_ref());
    seed.as_mut_slice().fill(0);
    seed_bytes.fill(0);
    PublicNodeKey(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_and_install_path, GroupMode, StateVersion, TreeKemPathContext};
    use hydra_core::types::{GroupId, Secret32};

    #[test]
    fn empty_rekey_rejects_without_mutation() {
        let mut tree = PublicTree::new(GroupMode::Interactive, Some(Epoch(7))).unwrap();
        let before = (tree.epoch, tree.tree_version, tree.tree_hash().unwrap());
        let mut path = PrivatePath::default();
        assert_eq!(
            rekey_path(&mut tree, &mut path),
            Err(GroupError::InvalidTreePath)
        );
        assert_eq!(
            (tree.epoch, tree.tree_version, tree.tree_hash().unwrap()),
            before
        );
    }

    #[test]
    fn rekey_reinstalls_private_path_node_keys_and_advances_epoch() {
        let mut tree = PublicTree::new(GroupMode::Interactive, Some(Epoch(7))).unwrap();
        let before_hash = tree.tree_hash().unwrap();
        let mut path = PrivatePath::default();
        let update = derive_and_install_path(
            &mut tree,
            &mut path,
            TreeKemPathContext {
                group_id: GroupId([0x42; 32]),
                mode: GroupMode::Interactive,
                epoch: Epoch(8),
                state_version: StateVersion(9),
                leaf_slot: 3,
                commit_nonce: [0x55; 32],
                tree_hash: before_hash,
            },
            &Secret32::new([0x11; 32]),
        )
        .unwrap();
        let mut target = PublicTree::new(GroupMode::Interactive, Some(Epoch(7))).unwrap();
        let rekey = rekey_path(&mut target, &mut path).unwrap();
        assert_eq!(rekey.new_epoch, Epoch(8));
        assert_eq!(rekey.changed_nodes, update.direct_path);
        assert_eq!(target.tree_hash().unwrap(), update.tree_hash_after);
    }
}
