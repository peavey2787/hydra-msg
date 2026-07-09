use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use hydra_crypto::CryptoError;

use crate::{
    import_identity_from_backup, random::random_array, AppError, AppResult, BackupSecret,
    EncryptedRecoveryBackup, IdentityImportPolicy, IdentityStore, StoredIdentityMetadata,
};

const VAULT_DIR: &str = "identities";
const REGISTRY_FILE: &str = "identity-vault.txt";
const REGISTRY_MAGIC: &str = "HYDRA-MSG-IDENTITY-VAULT-v1";
const IDENTITY_FILE_SUFFIX: &str = ".identity.db";
const MAX_LABEL_LEN: usize = 64;
pub const MAX_IDLE_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_REMEMBER_UNLOCK_SECONDS: u64 = 365 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultIdentitySummary {
    pub id: String,
    pub label: String,
    pub filename: String,
    pub identity_fingerprint_hex: String,
    pub device_id_hex: String,
    pub device_fingerprint_hex: String,
    pub generation: u64,
    pub revoked: bool,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VaultRecord {
    id: String,
    label: String,
    filename: String,
    identity_fingerprint_hex: String,
    device_id_hex: String,
    device_fingerprint_hex: String,
    generation: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct VaultRegistry {
    active_id: Option<String>,
    records: Vec<VaultRecord>,
}

/// Local multi-identity vault registry.
///
/// The registry contains only public identity metadata and file ownership. Each
/// actual identity private seed lives in a separate `IdentityStore` encrypted at
/// rest with the user's password. Passwords are never stored in this registry.
#[derive(Clone, Debug)]
pub struct IdentityVault {
    identities_dir: PathBuf,
    registry_path: PathBuf,
    registry: VaultRegistry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockedIdentityPublicMaterial {
    pub id: String,
    pub label: String,
    pub public_key_hex: String,
    pub identity_fingerprint_hex: String,
    pub device_id_hex: String,
    pub device_fingerprint_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSessionStatus {
    pub unlocked: bool,
    pub unlocked_identity_count: usize,
    pub active_identity_unlocked: bool,
    pub idle_timeout_seconds: Option<u64>,
    pub remember_expires_at_ms: Option<u64>,
    pub unlocked_identity_ids: Vec<String>,
}

struct UnlockedIdentity {
    id: String,
    store: IdentityStore,
}

/// Memory-only unlock cache for GUI/CLI app sessions.
///
/// This type never stores passwords. It holds decrypted `IdentityStore` values
/// only in process memory after a user explicitly unlocks the current app
/// session. Dropping or locking the session drops those stores and their
/// secret-bearing buffers.
pub struct IdentityUnlockSession {
    unlocked: Vec<UnlockedIdentity>,
    idle_timeout_seconds: Option<u64>,
    remember_expires_at: Option<SystemTime>,
    last_activity: Option<SystemTime>,
}

impl Default for IdentityUnlockSession {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityUnlockSession {
    #[must_use]
    pub fn new() -> Self {
        Self {
            unlocked: Vec::new(),
            idle_timeout_seconds: None,
            remember_expires_at: None,
            last_activity: None,
        }
    }

    pub fn unlock_with_password(
        &mut self,
        vault: &IdentityVault,
        password: &[u8],
    ) -> AppResult<VaultSessionStatus> {
        self.unlock_with_password_for(vault, password, None)
    }

    pub fn unlock_with_password_for(
        &mut self,
        vault: &IdentityVault,
        password: &[u8],
        remember_seconds: Option<u64>,
    ) -> AppResult<VaultSessionStatus> {
        validate_password(password)?;
        self.set_remember_duration(remember_seconds)?;
        self.apply_unlock_expiration();
        let mut unlocked = Vec::new();
        for record in &vault.registry.records {
            if record.revoked {
                continue;
            }
            if let Ok(store) = vault.load_identity_store(&record.id, password) {
                unlocked.push(UnlockedIdentity {
                    id: record.id.clone(),
                    store,
                });
            }
        }
        if unlocked.is_empty() {
            self.remember_expires_at = None;
            return Err(AppError::Crypto(CryptoError::AuthenticationFailed));
        }
        self.unlocked = unlocked;
        self.touch();
        Ok(self.status(vault))
    }

    pub fn lock_all(&mut self) -> VaultSessionStatus {
        self.unlocked.clear();
        self.remember_expires_at = None;
        self.last_activity = None;
        VaultSessionStatus {
            unlocked: false,
            unlocked_identity_count: 0,
            active_identity_unlocked: false,
            idle_timeout_seconds: self.idle_timeout_seconds,
            remember_expires_at_ms: None,
            unlocked_identity_ids: Vec::new(),
        }
    }

    pub fn set_idle_timeout_seconds(&mut self, seconds: Option<u64>) -> AppResult<()> {
        if let Some(seconds) = seconds {
            if seconds == 0 || seconds > MAX_IDLE_TIMEOUT_SECONDS {
                return Err(AppError::InvalidInput(
                    "identity idle timeout must be between 1 and 86400 seconds",
                ));
            }
        }
        self.idle_timeout_seconds = seconds;
        self.touch();
        Ok(())
    }

    pub fn status(&mut self, vault: &IdentityVault) -> VaultSessionStatus {
        self.apply_unlock_expiration();
        let active = vault.active_identity_id();
        let unlocked_identity_ids = self
            .unlocked
            .iter()
            .filter(|identity| !identity.store.is_revoked())
            .map(|identity| identity.id.clone())
            .collect::<Vec<_>>();
        VaultSessionStatus {
            unlocked: !self.unlocked.is_empty(),
            unlocked_identity_count: self.unlocked.len(),
            active_identity_unlocked: active
                .map(|active| {
                    self.unlocked
                        .iter()
                        .any(|identity| identity.id == active && !identity.store.is_revoked())
                })
                .unwrap_or(false),
            idle_timeout_seconds: self.idle_timeout_seconds,
            remember_expires_at_ms: self.remember_expires_at.and_then(system_time_ms),
            unlocked_identity_ids,
        }
    }

    pub fn touch_active(&mut self, vault: &IdentityVault) -> AppResult<VaultSessionStatus> {
        self.apply_unlock_expiration();
        let Some(active) = vault.active_identity_id() else {
            return Err(AppError::InvalidState("no active identity selected"));
        };
        if self.unlocked.iter().any(|identity| identity.id == active) {
            self.touch();
            Ok(self.status(vault))
        } else {
            Err(AppError::InvalidState("active identity is locked"))
        }
    }

    pub fn active_public_material(
        &mut self,
        vault: &IdentityVault,
    ) -> AppResult<UnlockedIdentityPublicMaterial> {
        self.apply_unlock_expiration();
        let active_id = vault
            .active_identity_id()
            .ok_or(AppError::InvalidState("no active identity selected"))?;
        let unlocked = self
            .unlocked
            .iter()
            .find(|identity| identity.id == active_id)
            .ok_or(AppError::InvalidState("active identity is locked"))?;
        let record = vault.record(active_id)?;
        let public = unlocked.store.public_identity();
        self.touch();
        Ok(UnlockedIdentityPublicMaterial {
            id: record.id.clone(),
            label: record.label.clone(),
            public_key_hex: encode_hex(&public.public_key().0),
            identity_fingerprint_hex: encode_hex(&public.fingerprint().0),
            device_id_hex: record.device_id_hex.clone(),
            device_fingerprint_hex: record.device_fingerprint_hex.clone(),
        })
    }

    fn touch(&mut self) {
        if !self.unlocked.is_empty() {
            self.last_activity = Some(SystemTime::now());
        }
    }

    fn set_remember_duration(&mut self, seconds: Option<u64>) -> AppResult<()> {
        self.remember_expires_at = match seconds {
            Some(seconds) => {
                if seconds == 0 || seconds > MAX_REMEMBER_UNLOCK_SECONDS {
                    return Err(AppError::InvalidInput(
                        "remember-me duration must be between 1 second and 1 year",
                    ));
                }
                Some(
                    SystemTime::now()
                        .checked_add(Duration::from_secs(seconds))
                        .ok_or(AppError::InvalidInput("remember-me duration is invalid"))?,
                )
            }
            None => None,
        };
        Ok(())
    }

    fn apply_unlock_expiration(&mut self) {
        self.apply_idle_timeout();
        let Some(expires_at) = self.remember_expires_at else {
            return;
        };
        if SystemTime::now() >= expires_at {
            self.unlocked.clear();
            self.remember_expires_at = None;
            self.last_activity = None;
        }
    }

    fn apply_idle_timeout(&mut self) {
        let Some(timeout) = self.idle_timeout_seconds else {
            return;
        };
        let Some(last_activity) = self.last_activity else {
            return;
        };
        if SystemTime::now()
            .duration_since(last_activity)
            .map(|elapsed| elapsed >= Duration::from_secs(timeout))
            .unwrap_or(false)
        {
            self.unlocked.clear();
            self.remember_expires_at = None;
            self.last_activity = None;
        }
    }

    #[cfg(test)]
    fn force_idle_for_tests(&mut self, elapsed: Duration) {
        self.last_activity = SystemTime::now().checked_sub(elapsed);
    }

    #[cfg(test)]
    fn force_remember_expired_for_tests(&mut self) {
        self.remember_expires_at = SystemTime::now().checked_sub(Duration::from_secs(1));
    }
}

fn system_time_ms(value: SystemTime) -> Option<u64> {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

impl IdentityVault {
    pub fn open(data_dir: impl AsRef<Path>) -> AppResult<Self> {
        let data_dir = data_dir.as_ref();
        let identities_dir = data_dir.join(VAULT_DIR);
        fs::create_dir_all(&identities_dir)
            .map_err(|_| AppError::InvalidInput("identity vault directory cannot be created"))?;
        let registry_path = identities_dir.join(REGISTRY_FILE);
        let registry =
            if registry_path.exists() {
                VaultRegistry::decode(&fs::read_to_string(&registry_path).map_err(|_| {
                    AppError::InvalidInput("identity vault registry cannot be read")
                })?)?
            } else {
                VaultRegistry::default()
            };
        Ok(Self {
            identities_dir,
            registry_path,
            registry,
        })
    }

    #[must_use]
    pub fn has_identities(&self) -> bool {
        !self.registry.records.is_empty()
    }

    #[must_use]
    pub fn active_identity_id(&self) -> Option<&str> {
        self.registry.active_id.as_deref()
    }

    #[must_use]
    pub fn identities(&self) -> Vec<VaultIdentitySummary> {
        self.registry
            .records
            .iter()
            .map(|record| record.summary(self.registry.active_id.as_deref()))
            .collect()
    }

    pub fn create_identity(
        &mut self,
        label: &str,
        password: &[u8],
    ) -> AppResult<VaultIdentitySummary> {
        validate_label(label)?;
        validate_password(password)?;
        self.reject_duplicate_label(label)?;
        let id = self.allocate_id()?;
        let filename = identity_filename(&id);
        let path = self.identities_dir.join(&filename);
        let store = IdentityStore::create(&path, password)?;
        let record = record_from_store(id, label.to_owned(), filename, store.metadata());
        self.add_record(record)
    }

    pub fn import_identity_store_file(
        &mut self,
        label: &str,
        source_path: impl AsRef<Path>,
        source_password: &[u8],
        new_password: &[u8],
        preserve_device_id: bool,
    ) -> AppResult<VaultIdentitySummary> {
        validate_label(label)?;
        validate_password(source_password)?;
        validate_password(new_password)?;
        self.reject_duplicate_label(label)?;
        let source = IdentityStore::load(source_path, source_password)?;
        let id = self.allocate_id()?;
        let filename = identity_filename(&id);
        let path = self.identities_dir.join(&filename);
        let store = source.copy_to_path(&path, new_password, preserve_device_id)?;
        let record = record_from_store(id, label.to_owned(), filename, store.metadata());
        self.add_record(record)
    }

    pub fn import_recovery_backup_file(
        &mut self,
        label: &str,
        backup_path: impl AsRef<Path>,
        backup_password: &[u8],
        identity_password: &[u8],
        policy: IdentityImportPolicy,
    ) -> AppResult<VaultIdentitySummary> {
        validate_label(label)?;
        validate_password(backup_password)?;
        validate_password(identity_password)?;
        self.reject_duplicate_label(label)?;
        let backup = EncryptedRecoveryBackup::read_from_file(backup_path)?;
        let id = self.allocate_id()?;
        let filename = identity_filename(&id);
        let path = self.identities_dir.join(&filename);
        let store = import_identity_from_backup(
            &backup,
            BackupSecret::Passphrase(backup_password),
            &path,
            identity_password,
            policy,
        )?;
        let record = record_from_store(id, label.to_owned(), filename, store.metadata());
        self.add_record(record)
    }

    pub fn verify_identity_password(
        &self,
        id: &str,
        password: &[u8],
    ) -> AppResult<StoredIdentityMetadata> {
        validate_password(password)?;
        let store = self.load_identity_store(id, password)?;
        Ok(store.metadata())
    }

    pub fn load_identity_store(&self, id: &str, password: &[u8]) -> AppResult<IdentityStore> {
        validate_password(password)?;
        let record = self.record(id)?;
        IdentityStore::load(self.identities_dir.join(&record.filename), password)
    }

    pub fn switch_active_identity(&mut self, id: &str) -> AppResult<VaultIdentitySummary> {
        let _ = self.record(id)?;
        self.registry.active_id = Some(id.to_owned());
        self.save_registry()?;
        Ok(self.record(id)?.summary(self.registry.active_id.as_deref()))
    }

    fn add_record(&mut self, record: VaultRecord) -> AppResult<VaultIdentitySummary> {
        let id = record.id.clone();
        self.registry.records.push(record);
        if self.registry.active_id.is_none() {
            self.registry.active_id = Some(id.clone());
        }
        self.save_registry()?;
        Ok(self
            .record(&id)?
            .summary(self.registry.active_id.as_deref()))
    }

    fn record(&self, id: &str) -> AppResult<&VaultRecord> {
        validate_id(id)?;
        self.registry
            .records
            .iter()
            .find(|record| record.id == id)
            .ok_or(AppError::InvalidInput("identity id is not in this vault"))
    }

    fn reject_duplicate_label(&self, label: &str) -> AppResult<()> {
        if self
            .registry
            .records
            .iter()
            .any(|record| record.label == label)
        {
            Err(AppError::InvalidInput("identity label already exists"))
        } else {
            Ok(())
        }
    }

    fn allocate_id(&self) -> AppResult<String> {
        for _ in 0..16 {
            let id = encode_hex(&random_array::<32>()?);
            if !self.registry.records.iter().any(|record| record.id == id) {
                return Ok(id);
            }
        }
        Err(AppError::EntropyUnavailable)
    }

    fn save_registry(&self) -> AppResult<()> {
        fs::write(&self.registry_path, self.registry.encode())
            .map_err(|_| AppError::InvalidInput("identity vault registry cannot be written"))
    }
}

impl VaultRecord {
    fn summary(&self, active_id: Option<&str>) -> VaultIdentitySummary {
        VaultIdentitySummary {
            id: self.id.clone(),
            label: self.label.clone(),
            filename: self.filename.clone(),
            identity_fingerprint_hex: self.identity_fingerprint_hex.clone(),
            device_id_hex: self.device_id_hex.clone(),
            device_fingerprint_hex: self.device_fingerprint_hex.clone(),
            generation: self.generation,
            revoked: self.revoked,
            active: active_id == Some(self.id.as_str()),
        }
    }
}

impl VaultRegistry {
    fn encode(&self) -> String {
        let mut out = String::from(REGISTRY_MAGIC);
        out.push('\n');
        if let Some(active) = &self.active_id {
            out.push_str("active=");
            out.push_str(active);
            out.push('\n');
        }
        for record in &self.records {
            out.push_str("identity=");
            out.push_str(&record.id);
            out.push('\t');
            out.push_str(&encode_label(&record.label));
            out.push('\t');
            out.push_str(&record.filename);
            out.push('\t');
            out.push_str(&record.identity_fingerprint_hex);
            out.push('\t');
            out.push_str(&record.device_id_hex);
            out.push('\t');
            out.push_str(&record.device_fingerprint_hex);
            out.push('\t');
            out.push_str(&record.generation.to_string());
            out.push('\t');
            out.push_str(if record.revoked { "1" } else { "0" });
            out.push('\n');
        }
        out
    }

    fn decode(text: &str) -> AppResult<Self> {
        let mut lines = text.lines();
        if lines.next() != Some(REGISTRY_MAGIC) {
            return Err(AppError::InvalidInput(
                "identity vault registry header is invalid",
            ));
        }
        let mut active_id = None;
        let mut records = Vec::new();
        for line in lines.map(str::trim).filter(|line| !line.is_empty()) {
            if let Some(active) = line.strip_prefix("active=") {
                validate_id(active)?;
                active_id = Some(active.to_owned());
            } else if let Some(raw) = line.strip_prefix("identity=") {
                let fields = raw.split('\t').collect::<Vec<_>>();
                if fields.len() != 8 {
                    return Err(AppError::InvalidInput(
                        "identity vault registry record has invalid shape",
                    ));
                }
                validate_id(fields[0])?;
                validate_identity_filename(fields[2])?;
                validate_hex_32(fields[3])?;
                validate_hex_32(fields[4])?;
                validate_hex_32(fields[5])?;
                let generation = fields[6].parse::<u64>().map_err(|_| {
                    AppError::InvalidInput("identity vault registry generation is invalid")
                })?;
                let revoked = match fields[7] {
                    "0" => false,
                    "1" => true,
                    _ => {
                        return Err(AppError::InvalidInput(
                            "identity vault registry revoked flag is invalid",
                        ))
                    }
                };
                records.push(VaultRecord {
                    id: fields[0].to_owned(),
                    label: decode_label(fields[1])?,
                    filename: fields[2].to_owned(),
                    identity_fingerprint_hex: fields[3].to_owned(),
                    device_id_hex: fields[4].to_owned(),
                    device_fingerprint_hex: fields[5].to_owned(),
                    generation,
                    revoked,
                });
            } else {
                return Err(AppError::InvalidInput(
                    "identity vault registry line is invalid",
                ));
            }
        }
        if let Some(active) = &active_id {
            if !records.iter().any(|record| &record.id == active) {
                return Err(AppError::InvalidInput(
                    "identity vault active id is missing",
                ));
            }
        }
        Ok(Self { active_id, records })
    }
}

fn record_from_store(
    id: String,
    label: String,
    filename: String,
    metadata: StoredIdentityMetadata,
) -> VaultRecord {
    VaultRecord {
        id,
        label,
        filename,
        identity_fingerprint_hex: encode_hex(&metadata.identity_fingerprint.0),
        device_id_hex: encode_hex(&metadata.device_id.0),
        device_fingerprint_hex: encode_hex(&metadata.device_fingerprint.0),
        generation: metadata.generation,
        revoked: metadata.revoked,
    }
}

fn validate_label(label: &str) -> AppResult<()> {
    let label = label.trim();
    if label.is_empty() {
        return Err(AppError::InvalidInput("identity label must not be empty"));
    }
    if label.len() > MAX_LABEL_LEN
        || label.contains('\n')
        || label.contains('\r')
        || label.contains('\t')
    {
        return Err(AppError::InvalidInput(
            "identity label has invalid characters or length",
        ));
    }
    Ok(())
}

fn validate_password(password: &[u8]) -> AppResult<()> {
    if password.is_empty() {
        Err(AppError::InvalidInput(
            "identity password must not be empty",
        ))
    } else {
        Ok(())
    }
}

fn validate_id(id: &str) -> AppResult<()> {
    if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AppError::InvalidInput("identity id is invalid"))
    }
}

fn identity_filename(id: &str) -> String {
    format!("{id}{IDENTITY_FILE_SUFFIX}")
}

fn validate_identity_filename(filename: &str) -> AppResult<()> {
    let Some(id) = filename.strip_suffix(IDENTITY_FILE_SUFFIX) else {
        return Err(AppError::InvalidInput("identity filename is invalid"));
    };
    validate_id(id)
}

fn validate_hex_32(text: &str) -> AppResult<()> {
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AppError::InvalidInput(
            "identity vault hex field is invalid",
        ))
    }
}

fn encode_label(label: &str) -> String {
    encode_hex(label.as_bytes())
}

fn decode_label(text: &str) -> AppResult<String> {
    String::from_utf8(decode_hex(text)?)
        .map_err(|_| AppError::InvalidInput("identity label is not utf-8"))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(text: &str) -> AppResult<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(AppError::InvalidInput("hex string has odd length"));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        out.push((hex_nibble(bytes[index])? << 4) | hex_nibble(bytes[index + 1])?);
        index += 2;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> AppResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AppError::InvalidInput(
            "hex string contains invalid character",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use crate::AppErrorClass;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hydra-vault-{name}-{nonce}"))
    }

    #[test]
    fn creates_multiple_encrypted_password_protected_identities() {
        let dir = temp_dir("create");
        let mut vault = IdentityVault::open(&dir).unwrap();
        let alice = vault.create_identity("Alice", b"alice-password").unwrap();
        let bob = vault.create_identity("Bob", b"bob-password").unwrap();
        assert_ne!(alice.id, bob.id);
        assert!(alice.active);
        assert_eq!(vault.identities().len(), 2);

        let reloaded = IdentityVault::open(&dir).unwrap();
        assert_eq!(reloaded.identities().len(), 2);
        assert_eq!(reloaded.active_identity_id(), Some(alice.id.as_str()));
        assert!(reloaded
            .verify_identity_password(&alice.id, b"alice-password")
            .is_ok());
        assert_eq!(
            reloaded
                .verify_identity_password(&alice.id, b"wrong-password")
                .unwrap_err()
                .class(),
            AppErrorClass::Authentication
        );

        let registry = fs::read_to_string(dir.join(VAULT_DIR).join(REGISTRY_FILE)).unwrap();
        assert!(!registry.contains("alice-password"));
        assert!(!registry.contains("bob-password"));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn imports_existing_identity_store_as_new_vault_member() {
        let source_dir = temp_dir("source");
        fs::create_dir_all(&source_dir).unwrap();
        let source_path = source_dir.join("source.identity.db");
        let source = IdentityStore::create(&source_path, b"source-password").unwrap();
        let target_dir = temp_dir("target");
        let mut vault = IdentityVault::open(&target_dir).unwrap();
        let imported = vault
            .import_identity_store_file(
                "Imported",
                &source_path,
                b"source-password",
                b"new-password",
                false,
            )
            .unwrap();
        assert_eq!(vault.identities().len(), 1);
        assert_eq!(
            imported.identity_fingerprint_hex,
            encode_hex(&source.metadata().identity_fingerprint.0)
        );
        assert!(vault
            .verify_identity_password(&imported.id, b"new-password")
            .is_ok());
        fs::remove_dir_all(source_dir).ok();
        fs::remove_dir_all(target_dir).ok();
    }

    #[test]
    fn corrupted_identity_file_rejects_password_verification() {
        let dir = temp_dir("corrupt");
        let mut vault = IdentityVault::open(&dir).unwrap();
        let identity = vault.create_identity("Alice", b"password").unwrap();
        let path = dir.join(VAULT_DIR).join(&identity.filename);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(path, bytes).unwrap();
        assert_eq!(
            vault
                .verify_identity_password(&identity.id, b"password")
                .unwrap_err()
                .class(),
            AppErrorClass::Authentication
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn switches_active_identity_without_reencrypting_private_state() {
        let dir = temp_dir("switch");
        let mut vault = IdentityVault::open(&dir).unwrap();
        let alice = vault.create_identity("Alice", b"password").unwrap();
        let bob = vault.create_identity("Bob", b"password").unwrap();
        assert_eq!(vault.active_identity_id(), Some(alice.id.as_str()));
        let switched = vault.switch_active_identity(&bob.id).unwrap();
        assert!(switched.active);
        assert_eq!(vault.active_identity_id(), Some(bob.id.as_str()));
        let reloaded = IdentityVault::open(&dir).unwrap();
        assert_eq!(reloaded.active_identity_id(), Some(bob.id.as_str()));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn unlock_session_caches_matching_identities_and_lock_clears_memory_state() {
        let dir = temp_dir("unlock");
        let mut vault = IdentityVault::open(&dir).unwrap();
        let alice = vault.create_identity("Alice", b"shared-password").unwrap();
        let bob = vault.create_identity("Bob", b"shared-password").unwrap();
        let _carol = vault.create_identity("Carol", b"other-password").unwrap();
        vault.switch_active_identity(&bob.id).unwrap();

        let mut session = IdentityUnlockSession::new();
        let status = session
            .unlock_with_password(&vault, b"shared-password")
            .unwrap();
        assert!(status.unlocked);
        assert_eq!(status.unlocked_identity_count, 2);
        assert!(status.active_identity_unlocked);
        assert!(status.unlocked_identity_ids.contains(&alice.id));
        assert!(status.unlocked_identity_ids.contains(&bob.id));

        let locked = session.lock_all();
        assert!(!locked.unlocked);
        assert_eq!(locked.unlocked_identity_count, 0);
        assert!(!locked.active_identity_unlocked);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn unlock_session_rejects_wrong_password_without_unlocking() {
        let dir = temp_dir("wrong-unlock");
        let mut vault = IdentityVault::open(&dir).unwrap();
        vault.create_identity("Alice", b"password").unwrap();
        let mut session = IdentityUnlockSession::new();
        assert_eq!(
            session
                .unlock_with_password(&vault, b"wrong-password")
                .unwrap_err()
                .class(),
            AppErrorClass::Authentication
        );
        assert!(!session.status(&vault).unlocked);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn idle_timeout_locks_memory_cache_at_boundary() {
        let dir = temp_dir("idle");
        let mut vault = IdentityVault::open(&dir).unwrap();
        vault.create_identity("Alice", b"password").unwrap();
        let mut session = IdentityUnlockSession::new();
        session.set_idle_timeout_seconds(Some(1)).unwrap();
        assert!(
            session
                .unlock_with_password(&vault, b"password")
                .unwrap()
                .unlocked
        );
        session.force_idle_for_tests(Duration::from_secs(0));
        assert!(session.status(&vault).unlocked);
        session.force_idle_for_tests(Duration::from_secs(1));
        assert!(!session.status(&vault).unlocked);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn remember_duration_locks_memory_cache_at_absolute_expiration() {
        let dir = temp_dir("remember");
        let mut vault = IdentityVault::open(&dir).unwrap();
        vault.create_identity("Alice", b"password").unwrap();
        let mut session = IdentityUnlockSession::new();
        let status = session
            .unlock_with_password_for(&vault, b"password", Some(60))
            .unwrap();
        assert!(status.unlocked);
        assert!(status.remember_expires_at_ms.is_some());
        session.force_remember_expired_for_tests();
        assert!(!session.status(&vault).unlocked);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn remember_duration_rejects_zero_and_too_large_values() {
        let dir = temp_dir("remember-bounds");
        let mut vault = IdentityVault::open(&dir).unwrap();
        vault.create_identity("Alice", b"password").unwrap();
        let mut session = IdentityUnlockSession::new();
        assert!(session
            .unlock_with_password_for(&vault, b"password", Some(0))
            .is_err());
        assert!(session
            .unlock_with_password_for(&vault, b"password", Some(MAX_REMEMBER_UNLOCK_SECONDS + 1))
            .is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn idle_timeout_rejects_zero_and_too_large_values() {
        let mut session = IdentityUnlockSession::new();
        assert!(session.set_idle_timeout_seconds(None).is_ok());
        assert!(session.set_idle_timeout_seconds(Some(1)).is_ok());
        assert!(session
            .set_idle_timeout_seconds(Some(MAX_IDLE_TIMEOUT_SECONDS))
            .is_ok());
        assert!(session.set_idle_timeout_seconds(Some(0)).is_err());
        assert!(session
            .set_idle_timeout_seconds(Some(MAX_IDLE_TIMEOUT_SECONDS + 1))
            .is_err());
    }
}
