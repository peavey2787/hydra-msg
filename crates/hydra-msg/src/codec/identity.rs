use super::{
    derive_password_key, encode_kdf_columns, exact_array_from_vec, hex_decode,
    hex_encode, parse_kdf_columns, random_array, PasswordKdfRecord,
};
use crate::{HydraMsgError, HydraResult, IdentityId, IdentityRecord, ID_EXPORT_MAGIC};
use hydra_crypto::{CryptoBackend, MlDsaKeyPair, RustCryptoBackend, SecretBytes};

const IDENTITY_SEED_KEY_LABEL: &[u8] = b"HYDRA-MSG/v1/facade/identity-seed-key";
const IDENTITY_PASSWORD_TAG_LABEL: &[u8] = b"HYDRA-MSG/v1/facade/identity-password-tag";

pub(crate) fn identity_record_from_seed(
    label: String,
    seed: [u8; 32],
    password: &str,
    unlocked: bool,
) -> HydraResult<IdentityRecord> {
    let keypair = MlDsaKeyPair::from_seed(seed)?;
    let public_key = keypair.verification_key.to_bytes();
    let id = IdentityId(RustCryptoBackend::sha3_256(&public_key));
    let kdf = PasswordKdfRecord::new_interactive()?;
    let seed_key = derive_identity_seed_key(password, &kdf)?;
    let seed_nonce = random_array::<12>()?;
    let encrypted_seed = encrypt_seed_with_key(&seed_key, &seed, seed_nonce)?;
    Ok(IdentityRecord {
        id,
        label,
        seed: unlocked.then_some(seed),
        public_key,
        password_kdf: kdf,
        password_tag: password_tag(id, &seed_key),
        seed_nonce,
        encrypted_seed,
        unlocked,
    })
}

pub(crate) fn decrypt_seed(record: &IdentityRecord, password: &str) -> HydraResult<[u8; 32]> {
    let key = verified_identity_seed_key(record, password)?;
    let plaintext = RustCryptoBackend::aead_open(
        &key,
        &record.seed_nonce,
        b"HYDRA-MSG/v1/facade/encrypted-seed",
        &record.encrypted_seed,
    )?;
    exact_array_from_vec((*plaintext).clone())
}

pub(crate) fn verify_password(record: &IdentityRecord, password: &str) -> HydraResult<()> {
    verified_identity_seed_key(record, password).map(|_| ())
}

pub(crate) fn encode_identity_line(record: &IdentityRecord) -> String {
    let kdf = encode_kdf_columns(&record.password_kdf);
    [
        "identity".to_string(),
        record.id.hex(),
        hex_encode(record.label.as_bytes()),
        hex_encode(&record.public_key),
        kdf[0].clone(),
        kdf[1].clone(),
        kdf[2].clone(),
        kdf[3].clone(),
        kdf[4].clone(),
        kdf[5].clone(),
        hex_encode(&record.password_tag),
        hex_encode(&record.seed_nonce),
        hex_encode(&record.encrypted_seed),
    ]
    .join("\t")
}

pub(crate) fn decode_identity_line(line: &str) -> HydraResult<IdentityRecord> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() != 13 || parts[0] != "identity" {
        return Err(HydraMsgError::InvalidEncoding("identity state record"));
    }
    let id = IdentityId(exact_array_from_vec(hex_decode(parts[1])?)?);
    let label = String::from_utf8(hex_decode(parts[2])?)
        .map_err(|_| HydraMsgError::InvalidEncoding("identity label"))?;
    let public_key = exact_array_from_vec(hex_decode(parts[3])?)?;
    let expected_id = IdentityId(RustCryptoBackend::sha3_256(&public_key));
    if id != expected_id {
        return Err(HydraMsgError::InvalidEncoding(
            "identity fingerprint mismatch",
        ));
    }
    Ok(IdentityRecord {
        id,
        label,
        seed: None,
        public_key,
        password_kdf: parse_kdf_columns(&parts[4..10])?,
        password_tag: exact_array_from_vec(hex_decode(parts[10])?)?,
        seed_nonce: exact_array_from_vec(hex_decode(parts[11])?)?,
        encrypted_seed: hex_decode(parts[12])?,
        unlocked: false,
    })
}

pub(crate) fn encode_identity_export(seed: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ID_EXPORT_MAGIC);
    out.extend_from_slice(&hex_encode(seed).into_bytes());
    out.push(b'\n');
    out
}

pub(crate) fn decode_identity_export(bytes: &[u8]) -> HydraResult<[u8; 32]> {
    if !bytes.starts_with(ID_EXPORT_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("identity export magic"));
    }
    let text = std::str::from_utf8(&bytes[ID_EXPORT_MAGIC.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("identity export utf-8"))?;
    exact_array_from_vec(hex_decode(text.trim())?)
}

fn verified_identity_seed_key(
    record: &IdentityRecord,
    password: &str,
) -> HydraResult<SecretBytes<32>> {
    let key = derive_identity_seed_key(password, &record.password_kdf)?;
    if record.password_tag == password_tag(record.id, &key) {
        Ok(key)
    } else {
        Err(HydraMsgError::InvalidPassword)
    }
}

fn derive_identity_seed_key(
    password: &str,
    kdf: &PasswordKdfRecord,
) -> HydraResult<SecretBytes<32>> {
    derive_password_key(IDENTITY_SEED_KEY_LABEL, password, kdf)
}

fn encrypt_seed_with_key(
    key: &SecretBytes<32>,
    seed: &[u8; 32],
    nonce: [u8; 12],
) -> HydraResult<Vec<u8>> {
    RustCryptoBackend::aead_seal(key, &nonce, b"HYDRA-MSG/v1/facade/encrypted-seed", seed)
        .map_err(Into::into)
}

fn password_tag(id: IdentityId, key: &SecretBytes<32>) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(IDENTITY_PASSWORD_TAG_LABEL);
    input.extend_from_slice(&id.0);
    RustCryptoBackend::hmac_sha3_256(key, &input)
}
