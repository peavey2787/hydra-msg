use getrandom::SysRng;
use rand_core::TryRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{error::exact_array, CryptoError, CryptoResult, SecretBytes};

/// X25519 private scalar. `StaticSecret` zeroizes its storage on drop.
pub struct X25519SecretKey(StaticSecret);

impl X25519SecretKey {
    pub fn generate() -> CryptoResult<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        SysRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| CryptoError::EntropyUnavailable)?;
        Ok(Self(StaticSecret::from(*bytes)))
    }

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let bytes = Zeroizing::new(exact_array::<32>("X25519 private value", bytes)?);
        Ok(Self(StaticSecret::from(*bytes)))
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    pub fn diffie_hellman(&self, peer_public_key: &[u8]) -> CryptoResult<SecretBytes<32>> {
        let peer = PublicKey::from(exact_array::<32>("X25519 public value", peer_public_key)?);
        let shared = self.0.diffie_hellman(&peer).to_bytes();
        if shared.iter().all(|byte| *byte == 0) {
            return Err(CryptoError::WeakPublicKey);
        }
        Ok(SecretBytes::new(shared))
    }
}
