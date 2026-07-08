use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size secret storage.
///
/// This type deliberately omits `Clone`, `Copy`, `Debug`, `Display`, and
/// serialization. Its owned bytes are zeroized on drop. Backend calls may
/// borrow them but must not retain the reference.
///
/// ```compile_fail
/// use hydra_crypto::{CryptoBackend, RustCryptoBackend};
///
/// let secret = RustCryptoBackend::hkdf_extract(b"salt", b"secret");
/// let duplicate = secret.clone();
/// # drop(duplicate);
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Takes ownership of secret bytes so their storage is cleared on drop.
    #[must_use]
    pub const fn from_array(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub(crate) const fn new(bytes: [u8; N]) -> Self {
        Self::from_array(bytes)
    }

    /// Exposes bytes only for an immediate cryptographic operation.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.bytes
    }
}
