use super::{exact_array_from_vec, hex_decode};
use crate::{HydraMsgError, HydraResult, BACKUP_MAGIC};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

pub(super) fn backup_key(password: &str) -> SecretBytes<32> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade/backup-key");
    input.extend_from_slice(password.as_bytes());
    RustCryptoBackend::hkdf_extract(b"HYDRA-MSG/v1/facade/backup", &input)
}

pub(super) fn parse_backup_outer(bytes: &[u8]) -> HydraResult<([u8; 12], Vec<u8>)> {
    if !bytes.starts_with(BACKUP_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("backup magic"));
    }
    let text = std::str::from_utf8(&bytes[BACKUP_MAGIC.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("backup utf-8"))?;
    let mut lines = text.lines();
    let nonce = exact_array_from_vec(hex_decode(
        lines
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("backup nonce"))?,
    )?)?;
    let ciphertext = hex_decode(
        lines
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("backup ciphertext"))?,
    )?;
    Ok((nonce, ciphertext))
}

pub(super) fn decode_backup(bytes: &[u8], password: &str) -> HydraResult<Vec<u8>> {
    let (nonce, ciphertext) = parse_backup_outer(bytes)?;
    let key = backup_key(password);
    let plaintext = RustCryptoBackend::aead_open(&key, &nonce, BACKUP_MAGIC, &ciphertext)?;
    Ok((*plaintext).clone())
}
