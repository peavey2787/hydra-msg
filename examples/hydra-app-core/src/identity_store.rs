use std::path::{Path, PathBuf};

use hydra_core::{types::IdentityFingerprint, ML_DSA_65_VK_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use zeroize::Zeroize;

use crate::{
    random::random_array,
    secret_handling::{
        crash_safe_atomic_write, derive_storage_key, read_crash_safe, StorageKdfPolicy,
        KDF_ID_SCRYPT,
    },
    AppError, AppIdentity, AppResult, PublicIdentity,
};

const STORE_MAGIC: &[u8; 8] = b"HYDRAID1";
const STORE_VERSION: u8 = 1;
const STORE_SALT_SIZE: usize = 32;
const STORE_NONCE_SIZE: usize = 12;
const STORE_HEADER_SIZE: usize = 8 + 1 + 1 + 4 + STORE_SALT_SIZE + STORE_NONCE_SIZE;
const PLAINTEXT_MAGIC: &[u8; 15] = b"HYDRAID-PLAIN-1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceFingerprint(pub [u8; 32]);

pub(crate) struct IdentityBackupRecord {
    pub(crate) device_id: DeviceId,
    pub(crate) device_fingerprint: DeviceFingerprint,
    pub(crate) generation: u64,
    pub(crate) revoked: bool,
    pub(crate) identity_seed: [u8; 32],
    pub(crate) verification_key: [u8; ML_DSA_65_VK_SIZE],
    pub(crate) identity_fingerprint: IdentityFingerprint,
}

impl Drop for IdentityBackupRecord {
    fn drop(&mut self) {
        self.identity_seed.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredIdentityMetadata {
    pub device_id: DeviceId,
    pub device_fingerprint: DeviceFingerprint,
    pub identity_fingerprint: IdentityFingerprint,
    pub generation: u64,
    pub revoked: bool,
}

/// Encrypted local identity database.
///
/// The on-disk file contains authenticated ciphertext only for ML-DSA private
/// seed material. Public identity metadata may be returned to the application,
/// but raw private key bytes are never exposed by this type.
pub struct IdentityStore {
    path: PathBuf,
    device_id: DeviceId,
    device_fingerprint: DeviceFingerprint,
    generation: u64,
    revoked: bool,
    identity: AppIdentity,
    identity_seed: SecretBytes<32>,
}

impl IdentityStore {
    pub fn create(path: impl AsRef<Path>, password: &[u8]) -> AppResult<Self> {
        let path = path.as_ref().to_path_buf();
        let device_id = DeviceId(random_array()?);
        let mut seed = random_array::<32>()?;
        let identity = AppIdentity::from_seed(seed)?;
        let device_fingerprint = derive_device_fingerprint(device_id, identity.fingerprint());
        let store = Self {
            path,
            device_id,
            device_fingerprint,
            generation: 0,
            revoked: false,
            identity,
            identity_seed: SecretBytes::from_array(seed),
        };
        seed.zeroize();
        store.save(password)?;
        Ok(store)
    }

    pub fn load(path: impl AsRef<Path>, password: &[u8]) -> AppResult<Self> {
        Self::load_inner(path.as_ref(), password, None)
    }

    pub fn load_for_device(
        path: impl AsRef<Path>,
        password: &[u8],
        expected_device_id: DeviceId,
    ) -> AppResult<Self> {
        Self::load_inner(path.as_ref(), password, Some(expected_device_id))
    }

    pub fn save(&self, password: &[u8]) -> AppResult<()> {
        let mut salt = random_array::<STORE_SALT_SIZE>()?;
        let nonce = random_array::<STORE_NONCE_SIZE>()?;
        let kdf_policy = StorageKdfPolicy::scrypt_interactive();
        let key = derive_store_key(password, &salt, kdf_policy)?;
        let plaintext = self.encode_plaintext()?;
        let header = encode_header(kdf_policy, &salt, &nonce);
        let ciphertext = RustCryptoBackend::aead_seal(&key, &nonce, &header, &plaintext)?;
        salt.zeroize();
        let mut file = Vec::with_capacity(header.len() + ciphertext.len());
        file.extend_from_slice(&header);
        file.extend_from_slice(&ciphertext);
        atomic_write(&self.path, &file)?;
        Ok(())
    }

    pub fn rotate(&mut self, password: &[u8]) -> AppResult<()> {
        if self.revoked {
            return Err(AppError::InvalidState(
                "cannot rotate a revoked identity store",
            ));
        }
        let mut seed = random_array::<32>()?;
        let identity = AppIdentity::from_seed(seed)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(AppError::InvalidState("identity generation exhausted"))?;
        self.identity = identity;
        self.identity_seed = SecretBytes::from_array(seed);
        seed.zeroize();
        self.generation = generation;
        self.device_fingerprint =
            derive_device_fingerprint(self.device_id, self.identity.fingerprint());
        self.save(password)
    }

    pub fn revoke(&mut self, password: &[u8]) -> AppResult<()> {
        self.revoked = true;
        self.save(password)
    }

    pub fn identity(&self) -> AppResult<&AppIdentity> {
        if self.revoked {
            Err(AppError::InvalidState("identity store is revoked"))
        } else {
            Ok(&self.identity)
        }
    }

    #[must_use]
    pub fn public_identity(&self) -> PublicIdentity {
        self.identity.public_identity()
    }

    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub const fn device_fingerprint(&self) -> DeviceFingerprint {
        self.device_fingerprint
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub(crate) fn export_backup_record(&self) -> IdentityBackupRecord {
        let public = self.identity.public_identity();
        IdentityBackupRecord {
            device_id: self.device_id,
            device_fingerprint: self.device_fingerprint,
            generation: self.generation,
            revoked: self.revoked,
            identity_seed: *self.identity_seed.expose_secret(),
            verification_key: public.public_key().0,
            identity_fingerprint: self.identity.fingerprint(),
        }
    }

    /// Copy this encrypted identity into a new identity-store file using a new
    /// password.
    ///
    /// This is intended for import workflows. The private seed is
    /// re-encrypted directly into the target store and is never returned to the
    /// caller. By default callers should pass `preserve_device_id = false` so an
    /// imported identity becomes a new device rather than a silent clone of an
    /// active device.
    pub fn copy_to_path(
        &self,
        path: impl AsRef<Path>,
        password: &[u8],
        preserve_device_id: bool,
    ) -> AppResult<Self> {
        Self::import_backup_record(
            path,
            password,
            self.export_backup_record(),
            preserve_device_id,
        )
    }

    pub(crate) fn import_backup_record(
        path: impl AsRef<Path>,
        password: &[u8],
        mut record: IdentityBackupRecord,
        preserve_device_id: bool,
    ) -> AppResult<Self> {
        let identity = AppIdentity::from_seed(record.identity_seed)?;
        let public = identity.public_identity();
        if public.public_key().0 != record.verification_key
            || identity.fingerprint() != record.identity_fingerprint
        {
            return Err(AppError::InvalidInput(
                "identity backup failed internal consistency checks",
            ));
        }
        let device_id = if preserve_device_id {
            record.device_id
        } else {
            DeviceId(random_array()?)
        };
        let device_fingerprint = derive_device_fingerprint(device_id, identity.fingerprint());
        if preserve_device_id && device_fingerprint != record.device_fingerprint {
            return Err(AppError::InvalidInput(
                "identity backup has inconsistent device fingerprint",
            ));
        }
        let store = Self {
            path: path.as_ref().to_path_buf(),
            device_id,
            device_fingerprint,
            generation: record.generation,
            revoked: record.revoked,
            identity,
            identity_seed: SecretBytes::from_array(record.identity_seed),
        };
        record.identity_seed.zeroize();
        store.save(password)?;
        Ok(store)
    }

    #[must_use]
    pub fn metadata(&self) -> StoredIdentityMetadata {
        StoredIdentityMetadata {
            device_id: self.device_id,
            device_fingerprint: self.device_fingerprint,
            identity_fingerprint: self.identity.fingerprint(),
            generation: self.generation,
            revoked: self.revoked,
        }
    }

    fn load_inner(
        path: &Path,
        password: &[u8],
        expected_device_id: Option<DeviceId>,
    ) -> AppResult<Self> {
        let file = read_crash_safe(path, "identity database cannot be read")?;
        if file.len() <= STORE_HEADER_SIZE {
            return Err(AppError::InvalidInput("identity database is truncated"));
        }
        let (header, ciphertext) = file.split_at(STORE_HEADER_SIZE);
        let (kdf_policy, salt, nonce) = decode_header(header)?;
        let key = derive_store_key(password, &salt, kdf_policy)?;
        let plaintext = RustCryptoBackend::aead_open(&key, nonce, header, ciphertext)?;
        let decoded = DecodedIdentityStore::decode(&plaintext)?;
        if let Some(expected) = expected_device_id {
            if decoded.device_id != expected {
                return Err(AppError::InvalidState(
                    "identity database belongs to a different device",
                ));
            }
        }
        let identity = AppIdentity::from_seed(*decoded.identity_seed.expose_secret())?;
        let public = identity.public_identity();
        if public.public_key().0 != decoded.verification_key
            || identity.fingerprint() != decoded.identity_fingerprint
            || derive_device_fingerprint(decoded.device_id, identity.fingerprint())
                != decoded.device_fingerprint
        {
            return Err(AppError::InvalidInput(
                "identity database failed internal consistency checks",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            device_id: decoded.device_id,
            device_fingerprint: decoded.device_fingerprint,
            generation: decoded.generation,
            revoked: decoded.revoked,
            identity,
            identity_seed: decoded.identity_seed,
        })
    }

    fn encode_plaintext(&self) -> AppResult<Vec<u8>> {
        let public = self.identity.public_identity();
        let mut out = Vec::with_capacity(
            PLAINTEXT_MAGIC.len() + 32 + 32 + 8 + 1 + 32 + ML_DSA_65_VK_SIZE + 32,
        );
        out.extend_from_slice(PLAINTEXT_MAGIC);
        out.extend_from_slice(&self.device_id.0);
        out.extend_from_slice(&self.device_fingerprint.0);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(u8::from(self.revoked));
        out.extend_from_slice(self.identity_seed.expose_secret());
        out.extend_from_slice(&public.public_key().0);
        out.extend_from_slice(&self.identity.fingerprint().0);
        Ok(out)
    }
}

struct DecodedIdentityStore {
    device_id: DeviceId,
    device_fingerprint: DeviceFingerprint,
    generation: u64,
    revoked: bool,
    identity_seed: SecretBytes<32>,
    verification_key: [u8; ML_DSA_65_VK_SIZE],
    identity_fingerprint: IdentityFingerprint,
}

impl DecodedIdentityStore {
    fn decode(input: &[u8]) -> AppResult<Self> {
        let expected = PLAINTEXT_MAGIC.len() + 32 + 32 + 8 + 1 + 32 + ML_DSA_65_VK_SIZE + 32;
        if input.len() != expected || &input[..PLAINTEXT_MAGIC.len()] != PLAINTEXT_MAGIC {
            return Err(AppError::InvalidInput(
                "identity database plaintext has invalid shape",
            ));
        }
        let mut offset = PLAINTEXT_MAGIC.len();
        let device_id = DeviceId(take_array(input, &mut offset)?);
        let device_fingerprint = DeviceFingerprint(take_array(input, &mut offset)?);
        let generation = u64::from_be_bytes(take_array(input, &mut offset)?);
        let revoked = match input[offset] {
            0 => false,
            1 => true,
            _ => {
                return Err(AppError::InvalidInput(
                    "identity database has invalid revocation flag",
                ))
            }
        };
        offset += 1;
        let identity_seed = SecretBytes::from_array(take_array(input, &mut offset)?);
        let verification_key = take_array(input, &mut offset)?;
        let identity_fingerprint = IdentityFingerprint(take_array(input, &mut offset)?);
        Ok(Self {
            device_id,
            device_fingerprint,
            generation,
            revoked,
            identity_seed,
            verification_key,
            identity_fingerprint,
        })
    }
}

fn encode_header(
    kdf_policy: StorageKdfPolicy,
    salt: &[u8; STORE_SALT_SIZE],
    nonce: &[u8; STORE_NONCE_SIZE],
) -> [u8; STORE_HEADER_SIZE] {
    let mut header = [0_u8; STORE_HEADER_SIZE];
    header[..8].copy_from_slice(STORE_MAGIC);
    header[8] = STORE_VERSION;
    header[9] = kdf_policy.kdf_id;
    header[10..14].copy_from_slice(&kdf_policy.parameter_code.to_be_bytes());
    header[14..46].copy_from_slice(salt);
    header[46..58].copy_from_slice(nonce);
    header
}

fn decode_header(
    header: &[u8],
) -> AppResult<(
    StorageKdfPolicy,
    [u8; STORE_SALT_SIZE],
    &[u8; STORE_NONCE_SIZE],
)> {
    if header.len() != STORE_HEADER_SIZE || &header[..8] != STORE_MAGIC {
        return Err(AppError::InvalidInput(
            "identity database header is invalid",
        ));
    }
    if header[8] != STORE_VERSION {
        return Err(AppError::InvalidInput(
            "identity database version is unsupported",
        ));
    }
    if header[9] != KDF_ID_SCRYPT {
        return Err(AppError::InvalidInput(
            "identity database KDF is unsupported",
        ));
    }
    let parameter_code = u32::from_be_bytes(
        header[10..14]
            .try_into()
            .expect("KDF parameter slice length"),
    );
    let salt = header[14..46].try_into().expect("salt slice length");
    let nonce = header[46..58].try_into().expect("nonce slice length");
    Ok((
        StorageKdfPolicy {
            kdf_id: header[9],
            parameter_code,
        },
        salt,
        nonce,
    ))
}

fn derive_store_key(
    password: &[u8],
    salt: &[u8; STORE_SALT_SIZE],
    kdf_policy: StorageKdfPolicy,
) -> AppResult<SecretBytes<32>> {
    derive_storage_key(
        b"HYDRA-MSG/app/identity-store-kdf" as &'static [u8],
        password,
        salt,
        kdf_policy.kdf_id,
        kdf_policy.parameter_code,
    )
}

pub(crate) fn derive_device_fingerprint(
    device_id: DeviceId,
    identity_fingerprint: IdentityFingerprint,
) -> DeviceFingerprint {
    let mut input = Vec::with_capacity(32 + 32 + 37);
    input.extend_from_slice(b"HYDRA-MSG/app/device-fingerprint");
    input.extend_from_slice(&device_id.0);
    input.extend_from_slice(&identity_fingerprint.0);
    DeviceFingerprint(RustCryptoBackend::sha3_256(&input))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> AppResult<()> {
    crash_safe_atomic_write(path, bytes, "identity database cannot be committed")
}

fn take_array<const N: usize>(input: &[u8], offset: &mut usize) -> AppResult<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(AppError::InvalidInput("identity database offset overflow"))?;
    let value = input
        .get(*offset..end)
        .ok_or(AppError::InvalidInput(
            "identity database plaintext is truncated",
        ))?
        .try_into()
        .map_err(|_| AppError::InvalidInput("identity database field has invalid length"))?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::AppErrorClass;

    use super::*;

    fn temp_store_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hydra-msg-{name}-{nonce}.hydraid"))
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn create_load_and_keep_private_seed_encrypted_on_disk() {
        let path = temp_store_path("create-load");
        let password = b"correct horse battery staple";
        let store = IdentityStore::create(&path, password).unwrap();
        let seed = *store.identity_seed.expose_secret();
        let metadata = store.metadata();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes[9], KDF_ID_SCRYPT);
        assert!(!contains(&bytes, &seed));
        assert!(!contains(&bytes, PLAINTEXT_MAGIC));

        let loaded = IdentityStore::load_for_device(&path, password, metadata.device_id).unwrap();
        assert_eq!(loaded.metadata(), metadata);
        assert_eq!(loaded.public_identity(), store.public_identity());
        fs::remove_file(path).ok();
    }

    #[test]
    fn missing_primary_file_recovers_last_committed_backup() {
        let path = temp_store_path("crash-recover");
        let password = b"crash recovery password";
        let store = IdentityStore::create(&path, password).unwrap();
        let backup = path.with_extension("hydraid.bak");
        fs::rename(&path, &backup).unwrap();
        assert!(!path.exists());
        let loaded = IdentityStore::load_for_device(&path, password, store.device_id()).unwrap();
        assert_eq!(loaded.public_identity(), store.public_identity());
        assert!(path.exists());
        fs::remove_file(path).ok();
        fs::remove_file(backup).ok();
    }

    #[test]
    fn wrong_password_wrong_device_and_corruption_reject() {
        let path = temp_store_path("reject");
        let password = b"strong local password";
        let store = IdentityStore::create(&path, password).unwrap();
        match IdentityStore::load(&path, b"wrong password") {
            Ok(_) => panic!("wrong password loaded identity database"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::Authentication),
        }
        match IdentityStore::load_for_device(&path, password, DeviceId([0xa5; 32])) {
            Ok(_) => panic!("wrong device loaded identity database"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::InvalidState),
        }
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        fs::write(&path, bytes).unwrap();
        match IdentityStore::load(&path, password) {
            Ok(_) => panic!("corrupted identity database loaded"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::Authentication),
        }
        drop(store);
        fs::remove_file(path).ok();
    }

    #[test]
    fn rotate_and_revoke_update_durable_state() {
        let path = temp_store_path("rotate-revoke");
        let password = b"rotation password";
        let mut store = IdentityStore::create(&path, password).unwrap();
        let old_public = store.public_identity();
        store.rotate(password).unwrap();
        assert_eq!(store.generation(), 1);
        assert_ne!(store.public_identity(), old_public);
        let loaded = IdentityStore::load_for_device(&path, password, store.device_id()).unwrap();
        assert_eq!(loaded.generation(), 1);
        assert_eq!(loaded.public_identity(), store.public_identity());

        store.revoke(password).unwrap();
        let revoked = IdentityStore::load(&path, password).unwrap();
        assert!(revoked.is_revoked());
        match revoked.identity() {
            Ok(_) => panic!("revoked identity store exposed signing identity"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::InvalidState),
        }
        fs::remove_file(path).ok();
    }
}
