use super::{exact_array_from_vec, hex_decode, hex_encode};
use crate::{HydraMsgError, HydraResult, BACKUP_MAGIC, STATE_V2_MAGIC};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

pub(crate) const STATE_V2_KDF_PROFILE: &str = "hkdf-sha3-256-v1";

pub(crate) fn backup_key(password: &str) -> SecretBytes<32> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade/backup-key");
    input.extend_from_slice(password.as_bytes());
    RustCryptoBackend::hkdf_extract(b"HYDRA-MSG/v1/facade/backup", &input)
}

pub(crate) fn state_key(password: &str) -> SecretBytes<32> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v2/facade/state-key");
    input.extend_from_slice(password.as_bytes());
    RustCryptoBackend::hkdf_extract(b"HYDRA-MSG/v2/facade/state", &input)
}

pub(crate) fn parse_backup_outer(bytes: &[u8]) -> HydraResult<([u8; 12], Vec<u8>)> {
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

pub(crate) fn decode_backup(bytes: &[u8], password: &str) -> HydraResult<Vec<u8>> {
    let (nonce, ciphertext) = parse_backup_outer(bytes)?;
    let key = backup_key(password);
    let plaintext = RustCryptoBackend::aead_open(&key, &nonce, BACKUP_MAGIC, &ciphertext)?;
    Ok((*plaintext).clone())
}

pub(crate) fn encode_encrypted_state_v2(
    snapshot: &[u8],
    key: &SecretBytes<32>,
    nonce: [u8; 12],
) -> HydraResult<Vec<u8>> {
    let nonce_hex = hex_encode(&nonce);
    let aad = state_v2_aad(&nonce_hex);
    let ciphertext = RustCryptoBackend::aead_seal(key, &nonce, aad.as_bytes(), snapshot)?;
    let mut out = aad.into_bytes();
    out.extend_from_slice(b"ciphertext\t");
    out.extend_from_slice(hex_encode(&ciphertext).as_bytes());
    out.push(b'\n');
    Ok(out)
}

pub(crate) fn decode_encrypted_state_v2(
    bytes: &[u8],
    key: &SecretBytes<32>,
) -> HydraResult<Vec<u8>> {
    let (aad, nonce, ciphertext) = parse_encrypted_state_v2(bytes)?;
    let plaintext = RustCryptoBackend::aead_open(key, &nonce, aad.as_bytes(), &ciphertext)?;
    Ok((*plaintext).clone())
}

fn parse_encrypted_state_v2(bytes: &[u8]) -> HydraResult<(String, [u8; 12], Vec<u8>)> {
    if !bytes.starts_with(STATE_V2_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("state v2 magic"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("state v2 utf-8"))?;
    let mut lines = text.lines();
    let magic = lines
        .next()
        .ok_or(HydraMsgError::InvalidEncoding("state v2 magic line"))?;
    if magic != "HYDRA-MSG-STATE-V2" {
        return Err(HydraMsgError::InvalidEncoding("state v2 magic line"));
    }
    let kdf = field_value(
        lines
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("state v2 kdf"))?,
        "kdf",
    )?;
    if kdf != STATE_V2_KDF_PROFILE {
        return Err(HydraMsgError::Unsupported("state v2 kdf profile"));
    }
    let nonce_hex = field_value(
        lines
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("state v2 nonce"))?,
        "nonce",
    )?;
    let nonce = exact_array_from_vec(hex_decode(nonce_hex)?)?;
    let ciphertext = hex_decode(field_value(
        lines
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("state v2 ciphertext"))?,
        "ciphertext",
    )?)?;
    Ok((state_v2_aad(nonce_hex), nonce, ciphertext))
}

fn field_value<'a>(line: &'a str, name: &str) -> HydraResult<&'a str> {
    let (got, value) = line
        .split_once('\t')
        .ok_or(HydraMsgError::InvalidEncoding("state v2 field"))?;
    if got == name {
        Ok(value)
    } else {
        Err(HydraMsgError::InvalidEncoding("state v2 field name"))
    }
}

fn state_v2_aad(nonce_hex: &str) -> String {
    format!(
        "{}kdf\t{}\nnonce\t{}\n",
        std::str::from_utf8(STATE_V2_MAGIC).unwrap_or_default(),
        STATE_V2_KDF_PROFILE,
        nonce_hex
    )
}
