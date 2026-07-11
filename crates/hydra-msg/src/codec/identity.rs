use super::{
    derive_password_key, encode_kdf_columns, exact_array_from_vec, hex_decode, hex_encode,
    parse_kdf_columns, random_array, PasswordKdfRecord,
};
use crate::{
    limits::{
        reject_encoded_size, validate_label_encoding, MAX_IDENTITY_EXPORT_BYTES, MAX_LABEL_BYTES,
    },
    HydraMsgError, HydraResult, IdentityId, IdentityRecord, ID_EXPORT_MAGIC,
};
use hydra_crypto::{CryptoBackend, MlDsaKeyPair, RustCryptoBackend, SecretBytes};

const IDENTITY_SEED_KEY_LABEL: &[u8] = b"HYDRA-MSG/facade/identity-seed-key";
const IDENTITY_PASSWORD_TAG_LABEL: &[u8] = b"HYDRA-MSG/facade/identity-password-tag";

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

pub(crate) fn rewrap_identity_record(
    record: &mut IdentityRecord,
    old_password: &str,
    new_password: &str,
) -> HydraResult<()> {
    let seed = decrypt_seed(record, old_password)?;
    let kdf = PasswordKdfRecord::new_interactive()?;
    let seed_key = derive_identity_seed_key(new_password, &kdf)?;
    let seed_nonce = random_array::<12>()?;
    let encrypted_seed = encrypt_seed_with_key(&seed_key, &seed, seed_nonce)?;
    record.password_kdf = kdf;
    record.password_tag = password_tag(record.id, &seed_key);
    record.seed_nonce = seed_nonce;
    record.encrypted_seed = encrypted_seed;
    record.seed = record.unlocked.then_some(seed);
    Ok(())
}

pub(crate) fn decrypt_seed(record: &IdentityRecord, password: &str) -> HydraResult<[u8; 32]> {
    let key = verified_identity_seed_key(record, password)?;
    let plaintext = RustCryptoBackend::aead_open(
        &key,
        &record.seed_nonce,
        b"HYDRA-MSG/facade/encrypted-seed",
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
    let parts = line.split('\t').take(14).collect::<Vec<_>>();
    if parts.len() != 13 || parts[0] != "identity" {
        return Err(HydraMsgError::InvalidEncoding("identity state record"));
    }
    reject_encoded_size(
        parts[1].len(),
        hydra_core::HASH_SIZE * 2,
        "identity id size",
    )?;
    if parts[1].len() != hydra_core::HASH_SIZE * 2 {
        return Err(HydraMsgError::InvalidEncoding("identity id size"));
    }
    let id = IdentityId(exact_array_from_vec(hex_decode(parts[1])?)?);
    reject_encoded_size(parts[2].len(), MAX_LABEL_BYTES * 2, "identity label size")?;
    let label = String::from_utf8(hex_decode(parts[2])?)
        .map_err(|_| HydraMsgError::InvalidEncoding("identity label"))?;
    validate_label_encoding(&label, "identity label size")?;
    if parts[3].len() != hydra_core::ML_DSA_65_VK_SIZE * 2 {
        return Err(HydraMsgError::InvalidEncoding("identity public key size"));
    }
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
        password_tag: decode_fixed_hex::<32>(parts[10], "identity password tag")?,
        seed_nonce: decode_fixed_hex::<12>(parts[11], "identity seed nonce")?,
        encrypted_seed: {
            reject_encoded_size(parts[12].len(), 128, "encrypted identity seed size")?;
            let encrypted_seed = hex_decode(parts[12])?;
            if encrypted_seed.len() != 48 {
                return Err(HydraMsgError::InvalidEncoding(
                    "encrypted identity seed size",
                ));
            }
            encrypted_seed
        },
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
    reject_encoded_size(
        bytes.len(),
        MAX_IDENTITY_EXPORT_BYTES,
        "identity export size",
    )?;
    if !bytes.starts_with(ID_EXPORT_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("identity export magic"));
    }
    let text = std::str::from_utf8(&bytes[ID_EXPORT_MAGIC.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("identity export utf-8"))?;
    decode_fixed_hex::<32>(text.trim(), "identity export seed")
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
    description: &'static str,
) -> HydraResult<[u8; N]> {
    if value.len() != N * 2 {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    exact_array_from_vec(hex_decode(value)?)
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
    RustCryptoBackend::aead_seal(key, &nonce, b"HYDRA-MSG/facade/encrypted-seed", seed)
        .map_err(Into::into)
}

fn password_tag(id: IdentityId, key: &SecretBytes<32>) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(IDENTITY_PASSWORD_TAG_LABEL);
    input.extend_from_slice(&id.0);
    RustCryptoBackend::hmac_sha3_256(key, &input)
}
