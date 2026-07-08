use sha3::{Digest, Sha3_256, Sha3_512};

#[must_use]
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    Sha3_256::digest(input).into()
}

#[must_use]
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    Sha3_512::digest(input).into()
}
