use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};
use zeroize::Zeroizing;

use crate::{error::exact_array, CryptoError, CryptoResult, SecretBytes};

pub fn seal(
    key: &SecretBytes<32>,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let nonce = exact_array::<12>("ChaCha20-Poly1305 nonce", nonce)?;
    let cipher = ChaCha20Poly1305::new(key.expose_secret().into());
    cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::BackendFailure)
}

pub fn open(
    key: &SecretBytes<32>,
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let nonce = exact_array::<12>("ChaCha20-Poly1305 nonce", nonce)?;
    if ciphertext_and_tag.len() < 16 {
        return Err(CryptoError::InvalidLength {
            field: "ChaCha20-Poly1305 ciphertext and tag",
            expected: 16,
            actual: ciphertext_and_tag.len(),
        });
    }
    let cipher = ChaCha20Poly1305::new(key.expose_secret().into());
    cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthenticationFailed)
}
