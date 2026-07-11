use crate::{codec::*, HydraResult};

pub(crate) fn encode_backup_snapshot(snapshot: &[u8], password: &str) -> HydraResult<Vec<u8>> {
    let kdf = new_storage_kdf()?;
    encode_backup(snapshot, password, &kdf, random_array::<12>()?)
}

pub(crate) fn decode_backup_snapshot(bytes: &[u8], password: &str) -> HydraResult<Vec<u8>> {
    decode_backup(bytes, password)
}

pub(crate) fn seal_state_snapshot(
    snapshot: &[u8],
    key: &hydra_crypto::SecretBytes<32>,
    kdf: &PasswordKdfRecord,
) -> HydraResult<Vec<u8>> {
    encode_encrypted_state(snapshot, key, kdf, random_array::<12>()?)
}

pub(crate) fn open_state_snapshot(
    bytes: &[u8],
    key: &hydra_crypto::SecretBytes<32>,
) -> HydraResult<Vec<u8>> {
    decode_encrypted_state(bytes, key)
}

pub(crate) fn read_state_kdf(bytes: &[u8]) -> HydraResult<PasswordKdfRecord> {
    parse_state_kdf(bytes)
}

pub(crate) fn new_state_kdf() -> HydraResult<PasswordKdfRecord> {
    new_storage_kdf()
}

pub(crate) fn derive_state_key(
    password: &str,
    kdf: &PasswordKdfRecord,
) -> HydraResult<hydra_crypto::SecretBytes<32>> {
    state_key(password, kdf)
}
