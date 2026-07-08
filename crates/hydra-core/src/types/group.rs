use crate::types::{GroupId, IdentityFingerprint};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LeafIndex(pub u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMemberDescriptor {
    pub group_id: GroupId,
    pub identity: IdentityFingerprint,
    pub leaf_index: LeafIndex,
    pub joined_epoch: Epoch,
    pub is_active: bool,
}
