use super::{exact_array_from_vec, hex_decode, hex_encode, random_array};
use crate::{HydraMsgError, HydraResult, IdentityId, IdentityRecord, ID_EXPORT_MAGIC};
use hydra_crypto::{CryptoBackend, MlDsaKeyPair, RustCryptoBackend, SecretBytes};

pub(super) fn identity_record_from_seed(
    label: String,
    seed: [u8; 32],
    password: &str,
    unlocked: bool,
) -> HydraResult<IdentityRecord> {
    let keypair = MlDsaKeyPair::from_seed(seed)?;
    let public_key = keypair.verification_key.to_bytes();
    let id = IdentityId(RustCryptoBackend::sha3_256(&public_key));
    let seed_nonce = random_array::<12>()?;
    let encrypted_seed = encrypt_seed(id, &seed, password, seed_nonce)?;
    Ok(IdentityRecord {
        id,
        label,
        seed: unlocked.then_some(seed),
        public_key,
        password_tag: password_tag(password),
        seed_nonce,
        encrypted_seed,
        unlocked,
    })
}

pub(super) fn seed_key(id: IdentityId, password: &str) -> SecretBytes<32> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade/identity-seed-key");
    input.extend_from_slice(&id.0);
    input.extend_from_slice(password.as_bytes());
    RustCryptoBackend::hkdf_extract(b"HYDRA-MSG/v1/facade/identity-seed", &input)
}

pub(super) fn encrypt_seed(
    id: IdentityId,
    seed: &[u8; 32],
    password: &str,
    nonce: [u8; 12],
) -> HydraResult<Vec<u8>> {
    let key = seed_key(id, password);
    RustCryptoBackend::aead_seal(&key, &nonce, b"HYDRA-MSG/v1/facade/encrypted-seed", seed)
        .map_err(Into::into)
}

pub(super) fn decrypt_seed(record: &IdentityRecord, password: &str) -> HydraResult<[u8; 32]> {
    verify_password(record, password)?;
    let key = seed_key(record.id, password);
    let plaintext = RustCryptoBackend::aead_open(
        &key,
        &record.seed_nonce,
        b"HYDRA-MSG/v1/facade/encrypted-seed",
        &record.encrypted_seed,
    )?;
    exact_array_from_vec((*plaintext).clone())
}

pub(super) fn verify_password(record: &IdentityRecord, password: &str) -> HydraResult<()> {
    if record.password_tag == password_tag(password) {
        Ok(())
    } else {
        Err(HydraMsgError::InvalidPassword)
    }
}

pub(super) fn password_tag(password: &str) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade/password-tag");
    input.extend_from_slice(password.as_bytes());
    RustCryptoBackend::sha3_256(&input)
}

pub(super) fn encode_identity_line(record: &IdentityRecord) -> String {
    [
        "identity".to_string(),
        record.id.hex(),
        hex_encode(record.label.as_bytes()),
        hex_encode(&record.public_key),
        hex_encode(&record.password_tag),
        hex_encode(&record.seed_nonce),
        hex_encode(&record.encrypted_seed),
    ]
    .join("	")
}

pub(super) fn decode_identity_line(line: &str) -> HydraResult<IdentityRecord> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() != 7 || parts[0] != "identity" {
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
        password_tag: exact_array_from_vec(hex_decode(parts[4])?)?,
        seed_nonce: exact_array_from_vec(hex_decode(parts[5])?)?,
        encrypted_seed: hex_decode(parts[6])?,
        unlocked: false,
    })
}

pub(super) fn encode_identity_export(seed: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ID_EXPORT_MAGIC);
    out.extend_from_slice(&hex_encode(seed).into_bytes());
    out.push(b'\n');
    out
}

pub(super) fn decode_identity_export(bytes: &[u8]) -> HydraResult<[u8; 32]> {
    if !bytes.starts_with(ID_EXPORT_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("identity export magic"));
    }
    let text = std::str::from_utf8(&bytes[ID_EXPORT_MAGIC.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("identity export utf-8"))?;
    exact_array_from_vec(hex_decode(text.trim())?)
}
