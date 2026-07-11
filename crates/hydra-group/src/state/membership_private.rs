use super::{MembershipPrivateStateSnapshot, PrivatePathNodeSecretSnapshot};
use crate::private_path::PrivatePath;
use crate::public_tree::{direct_path, leaf_capacity_for_mode, PublicTree};
use crate::{GroupError, GroupMode, GroupResult, MembershipMechanism, PrivatePathNodeSecret};
use hydra_core::types::Secret32;

pub enum MembershipPrivateState {
    TreeKem {
        public_tree: PublicTree,
        private_path: PrivatePath,
    },
    DirectWrap {
        epoch_secret: Secret32,
    },
    Empty,
}

impl MembershipPrivateState {
    pub fn clear(&mut self) {
        let mut old = std::mem::replace(self, Self::Empty);
        old.wipe_in_place();
    }

    fn wipe_in_place(&mut self) {
        match self {
            Self::TreeKem { private_path, .. } => private_path.clear(),
            Self::DirectWrap { epoch_secret } => epoch_secret.wipe(),
            Self::Empty => {}
        }
    }

    #[must_use]
    pub const fn mechanism(&self) -> Option<MembershipMechanism> {
        match self {
            Self::TreeKem { .. } => Some(MembershipMechanism::TreeKem),
            Self::DirectWrap { .. } => Some(MembershipMechanism::DirectWrap),
            Self::Empty => None,
        }
    }

    #[must_use]
    pub fn export_snapshot(&self) -> Option<MembershipPrivateStateSnapshot> {
        match self {
            Self::TreeKem {
                public_tree,
                private_path,
            } => Some(MembershipPrivateStateSnapshot::TreeKem {
                public_tree: public_tree.clone(),
                leaf_index: private_path.leaf_index,
                path: private_path
                    .path
                    .iter()
                    .map(|node| PrivatePathNodeSecretSnapshot {
                        node_index: node.node_index,
                        path_secret: *node.path_secret.expose_for_backend(),
                        node_seed_d: *node.node_seed_d.expose_for_backend(),
                        node_seed_z: *node.node_seed_z.expose_for_backend(),
                    })
                    .collect(),
            }),
            Self::DirectWrap { epoch_secret } => Some(MembershipPrivateStateSnapshot::DirectWrap {
                epoch_secret: *epoch_secret.expose_for_backend(),
            }),
            Self::Empty => Some(MembershipPrivateStateSnapshot::Empty),
        }
    }

    pub fn from_snapshot(
        snapshot: MembershipPrivateStateSnapshot,
        mode: GroupMode,
    ) -> GroupResult<Self> {
        Ok(match snapshot {
            MembershipPrivateStateSnapshot::TreeKem {
                public_tree,
                leaf_index,
                path,
            } => {
                let capacity = leaf_capacity_for_mode(mode)?;
                let expected_nodes = capacity
                    .checked_mul(2)
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or(GroupError::CounterExhausted)?;
                if public_tree.mode != mode
                    || public_tree.leaf_capacity != capacity
                    || public_tree.nodes.len() != expected_nodes
                    || public_tree
                        .nodes
                        .iter()
                        .enumerate()
                        .any(|(index, node)| usize::try_from(node.node_index).ok() != Some(index))
                {
                    return Err(GroupError::InvalidState);
                }
                let max_path = direct_path(mode, 0)?.len();
                if path.len() > max_path || leaf_index.is_some_and(|index| index.0 >= capacity) {
                    return Err(GroupError::InvalidState);
                }
                let mut seen = std::collections::HashSet::new();
                if path.iter().any(|node| !seen.insert(node.node_index)) {
                    return Err(GroupError::InvalidState);
                }
                Self::TreeKem {
                    public_tree,
                    private_path: PrivatePath {
                        leaf_index,
                        path: path
                            .into_iter()
                            .map(|node| PrivatePathNodeSecret {
                                node_index: node.node_index,
                                path_secret: Secret32::new(node.path_secret),
                                node_seed_d: Secret32::new(node.node_seed_d),
                                node_seed_z: Secret32::new(node.node_seed_z),
                            })
                            .collect(),
                    },
                }
            }
            MembershipPrivateStateSnapshot::DirectWrap { epoch_secret } => Self::DirectWrap {
                epoch_secret: Secret32::new(epoch_secret),
            },
            MembershipPrivateStateSnapshot::Empty => Self::Empty,
        })
    }
}

impl Drop for MembershipPrivateState {
    fn drop(&mut self) {
        self.wipe_in_place();
    }
}
