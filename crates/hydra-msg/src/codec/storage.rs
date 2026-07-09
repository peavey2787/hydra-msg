use super::{
    decode_kdf_fields, derive_password_key, encode_kdf_fields, exact_array_from_vec, hex_decode,
    hex_encode, required_field, PasswordKdfRecord,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::STATE_MAGIC;
use crate::{HydraMsgError, HydraResult, BACKUP_MAGIC};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

#[cfg(not(target_arch = "wasm32"))]
const STATE_KEY_LABEL: &[u8] = b"HYDRA-MSG/facade/state-key";
const BACKUP_KEY_LABEL: &[u8] = b"HYDRA-MSG/facade/backup-key";

pub(crate) fn new_storage_kdf() -> HydraResult<PasswordKdfRecord> {
    PasswordKdfRecord::new_interactive()
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn state_key(password: &str, kdf: &PasswordKdfRecord) -> HydraResult<SecretBytes<32>> {
    derive_password_key(STATE_KEY_LABEL, password, kdf)
}

pub(crate) fn backup_key(password: &str, kdf: &PasswordKdfRecord) -> HydraResult<SecretBytes<32>> {
    derive_password_key(BACKUP_KEY_LABEL, password, kdf)
}

pub(crate) fn encode_backup(
    snapshot: &[u8],
    password: &str,
    kdf: &PasswordKdfRecord,
    nonce: [u8; 12],
) -> HydraResult<Vec<u8>> {
    let key = backup_key(password, kdf)?;
    let nonce_hex = hex_encode(&nonce);
    let aad = backup_aad(kdf, &nonce_hex);
    let ciphertext = RustCryptoBackend::aead_seal(&key, &nonce, aad.as_bytes(), snapshot)?;
    let mut out = aad.into_bytes();
    out.extend_from_slice(b"ciphertext\t");
    out.extend_from_slice(hex_encode(&ciphertext).as_bytes());
    out.push(b'\n');
    Ok(out)
}

pub(crate) fn parse_backup_outer(bytes: &[u8]) -> HydraResult<()> {
    parse_backup(bytes)?;
    Ok(())
}

pub(crate) fn decode_backup(bytes: &[u8], password: &str) -> HydraResult<Vec<u8>> {
    let (aad, kdf, nonce, ciphertext) = parse_backup(bytes)?;
    let key = backup_key(password, &kdf)?;
    let plaintext = RustCryptoBackend::aead_open(&key, &nonce, aad.as_bytes(), &ciphertext)?;
    Ok((*plaintext).clone())
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn encode_encrypted_state(
    snapshot: &[u8],
    key: &SecretBytes<32>,
    kdf: &PasswordKdfRecord,
    nonce: [u8; 12],
) -> HydraResult<Vec<u8>> {
    let nonce_hex = hex_encode(&nonce);
    let aad = state_aad(kdf, &nonce_hex);
    let ciphertext = RustCryptoBackend::aead_seal(key, &nonce, aad.as_bytes(), snapshot)?;
    let mut out = aad.into_bytes();
    out.extend_from_slice(b"ciphertext\t");
    out.extend_from_slice(hex_encode(&ciphertext).as_bytes());
    out.push(b'\n');
    Ok(out)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn decode_encrypted_state(bytes: &[u8], key: &SecretBytes<32>) -> HydraResult<Vec<u8>> {
    let (aad, _, nonce, ciphertext) = parse_encrypted_state(bytes)?;
    let plaintext = RustCryptoBackend::aead_open(key, &nonce, aad.as_bytes(), &ciphertext)?;
    Ok((*plaintext).clone())
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn parse_state_kdf(bytes: &[u8]) -> HydraResult<PasswordKdfRecord> {
    let (_, kdf, _, _) = parse_encrypted_state(bytes)?;
    Ok(kdf)
}

fn parse_backup(bytes: &[u8]) -> HydraResult<(String, PasswordKdfRecord, [u8; 12], Vec<u8>)> {
    if !bytes.starts_with(BACKUP_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("backup magic"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| HydraMsgError::InvalidEncoding("backup utf-8"))?;
    let mut lines = text.lines();
    let magic = lines
        .next()
        .ok_or(HydraMsgError::InvalidEncoding("backup magic line"))?;
    if magic != "HYDRA-MSG-BACKUP" {
        return Err(HydraMsgError::InvalidEncoding("backup magic line"));
    }
    let kdf = decode_kdf_fields(&mut lines)?;
    let nonce_hex = required_field(&mut lines, "nonce", "backup nonce")?;
    let nonce = exact_array_from_vec(hex_decode(nonce_hex)?)?;
    let ciphertext = hex_decode(required_field(
        &mut lines,
        "ciphertext",
        "backup ciphertext",
    )?)?;
    Ok((backup_aad(&kdf, nonce_hex), kdf, nonce, ciphertext))
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_encrypted_state(
    bytes: &[u8],
) -> HydraResult<(String, PasswordKdfRecord, [u8; 12], Vec<u8>)> {
    if !bytes.starts_with(STATE_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("state magic"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| HydraMsgError::InvalidEncoding("state utf-8"))?;
    let mut lines = text.lines();
    let magic = lines
        .next()
        .ok_or(HydraMsgError::InvalidEncoding("state magic line"))?;
    if magic != "HYDRA-MSG-STATE" {
        return Err(HydraMsgError::InvalidEncoding("state magic line"));
    }
    let kdf = decode_kdf_fields(&mut lines)?;
    let nonce_hex = required_field(&mut lines, "nonce", "state nonce")?;
    let nonce = exact_array_from_vec(hex_decode(nonce_hex)?)?;
    let ciphertext = hex_decode(required_field(
        &mut lines,
        "ciphertext",
        "state ciphertext",
    )?)?;
    Ok((state_aad(&kdf, nonce_hex), kdf, nonce, ciphertext))
}

#[cfg(not(target_arch = "wasm32"))]
fn state_aad(kdf: &PasswordKdfRecord, nonce_hex: &str) -> String {
    format!(
        "{}{}nonce\t{}\n",
        std::str::from_utf8(STATE_MAGIC).unwrap_or_default(),
        encode_kdf_fields(kdf),
        nonce_hex
    )
}

fn backup_aad(kdf: &PasswordKdfRecord, nonce_hex: &str) -> String {
    format!(
        "{}{}nonce\t{}\n",
        std::str::from_utf8(BACKUP_MAGIC).unwrap_or_default(),
        encode_kdf_fields(kdf),
        nonce_hex
    )
}
