use hmac::{Hmac, KeyInit, Mac};
use sha3::Sha3_256;

use crate::{CryptoError, CryptoResult, SecretBytes};

type HmacSha3_256 = Hmac<Sha3_256>;

pub fn hmac_sha3_256(key: &SecretBytes<32>, input: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha3_256::new_from_slice(key.expose_secret())
        .expect("HMAC accepts every fixed 32-byte key");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

pub fn verify_hmac_sha3_256(
    key: &SecretBytes<32>,
    input: &[u8],
    expected: &[u8],
) -> CryptoResult<()> {
    if expected.len() != 32 {
        return Err(CryptoError::InvalidLength {
            field: "HMAC-SHA3-256 tag",
            expected: 32,
            actual: expected.len(),
        });
    }
    let mut mac = HmacSha3_256::new_from_slice(key.expose_secret())
        .expect("HMAC accepts every fixed 32-byte key");
    mac.update(input);
    mac.verify_slice(expected)
        .map_err(|_| CryptoError::AuthenticationFailed)
}
