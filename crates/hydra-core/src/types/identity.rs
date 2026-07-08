use crate::constants::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityPublicKey(pub [u8; ML_DSA_65_VK_SIZE]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentityFingerprint(pub [u8; HASH_SIZE]);
