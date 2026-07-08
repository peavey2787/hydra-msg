use crate::constants::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; SESSION_ID_SIZE]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GroupId(pub [u8; GROUP_ID_SIZE]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageIndex(pub u64);

/// Minimal secret wrapper for protocol-level state.
///
/// Production app code should wrap protocol secrets in validated app/backend
/// containers that provide stronger cleanup, page-locking where available,
/// and retired-secret handling.
pub struct Secret32(pub [u8; 32]);

impl Secret32 {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    #[must_use]
    pub fn expose_for_backend(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn wipe(&mut self) {
        self.0.fill(0);
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.wipe();
    }
}
