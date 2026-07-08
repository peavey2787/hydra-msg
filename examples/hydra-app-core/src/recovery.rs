use std::path::Path;

use hydra_core::{types::IdentityFingerprint, ML_DSA_65_VK_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    identity_store::IdentityBackupRecord,
    message_store::MessageStoreBackupRecord,
    random::random_array,
    secret_handling::{
        crash_safe_atomic_write, derive_storage_key, read_crash_safe, StorageKdfPolicy,
        KDF_ID_SCRYPT,
    },
    AppError, AppResult, ConversationId, ConversationKind, DeviceFingerprint, DeviceId,
    IdentityStore, MessageDirection, MessageStore, PendingCommitRecord, ReplayCursorRecord,
    SkippedKeyPersistencePolicy, StoredConversation, StoredMember, StoredMessage,
};

const BACKUP_MAGIC: &[u8; 8] = b"HYDRABK1";
const BACKUP_VERSION: u8 = 1;
const BACKUP_SALT_SIZE: usize = 32;
const BACKUP_NONCE_SIZE: usize = 12;
const BACKUP_HEADER_SIZE: usize = 8 + 1 + 1 + 1 + 4 + BACKUP_SALT_SIZE + BACKUP_NONCE_SIZE;
const PLAINTEXT_MAGIC: &[u8; 15] = b"HYDRABK-PLAIN-1";
const PLAINTEXT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryKeyPolicy {
    UserPassphrase = 1,
    RandomRecoveryKey = 2,
}

impl TryFrom<u8> for RecoveryKeyPolicy {
    type Error = AppError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UserPassphrase),
            2 => Ok(Self::RandomRecoveryKey),
            _ => Err(AppError::InvalidInput(
                "recovery backup has invalid key policy",
            )),
        }
    }
}

/// Random backup key material for QR-code or printable recovery-key flows.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey {
    bytes: [u8; 32],
}

impl RecoveryKey {
    pub fn generate() -> AppResult<Self> {
        Ok(Self {
            bytes: random_array()?,
        })
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(32 + 37);
        input.extend_from_slice(b"HYDRA-MSG/app/recovery-key-fp/v1");
        input.extend_from_slice(&self.bytes);
        RustCryptoBackend::sha3_256(&input)
    }

    fn as_slice(&self) -> &[u8; 32] {
        &self.bytes
    }
}

pub enum BackupSecret<'a> {
    Passphrase(&'a [u8]),
    RecoveryKey(&'a RecoveryKey),
}

impl BackupSecret<'_> {
    fn policy(&self) -> RecoveryKeyPolicy {
        match self {
            Self::Passphrase(_) => RecoveryKeyPolicy::UserPassphrase,
            Self::RecoveryKey(_) => RecoveryKeyPolicy::RandomRecoveryKey,
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Passphrase(passphrase) => passphrase,
            Self::RecoveryKey(key) => key.as_slice(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryBackupOptions {
    /// When false, import defaults must create a fresh device ID. Preserving the
    /// source device ID requires this bit and an explicit PreserveDevice policy.
    pub allow_active_device_clone: bool,
    pub include_conversations: bool,
}

impl Default for RecoveryBackupOptions {
    fn default() -> Self {
        Self {
            allow_active_device_clone: false,
            include_conversations: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityImportPolicy {
    /// Recover the identity signing key but create a new device identifier and
    /// device fingerprint. This is the default safe policy.
    NewDevice,
    /// Preserve the source device identifier only when the backup explicitly
    /// allowed active-device cloning, or when the exported source was revoked.
    PreserveDeviceIfAllowed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryManifest {
    pub backup_id: [u8; 32],
    pub created_at_ms: u64,
    pub key_policy: RecoveryKeyPolicy,
    pub allow_active_device_clone: bool,
    pub source_device_id: DeviceId,
    pub source_device_fingerprint: DeviceFingerprint,
    pub source_identity_fingerprint: IdentityFingerprint,
    pub source_identity_generation: u64,
    pub source_device_revoked: bool,
    pub includes_identity: bool,
    pub includes_conversations: bool,
    pub conversation_count: u32,
    pub message_count: u32,
    pub pending_commit_count: u32,
    pub replay_cursor_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecoveryBackup {
    bytes: Vec<u8>,
}

impl EncryptedRecoveryBackup {
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn write_to_file(&self, path: impl AsRef<Path>) -> AppResult<()> {
        atomic_write(path.as_ref(), &self.bytes)
    }

    pub fn read_from_file(path: impl AsRef<Path>) -> AppResult<Self> {
        let bytes = read_crash_safe(path.as_ref(), "recovery backup cannot be read")?;
        Ok(Self { bytes })
    }
}

pub fn export_recovery_backup(
    identity_store: &IdentityStore,
    message_store: Option<&MessageStore>,
    secret: BackupSecret<'_>,
    options: RecoveryBackupOptions,
    created_at_ms: u64,
) -> AppResult<EncryptedRecoveryBackup> {
    if matches!(secret, BackupSecret::Passphrase(passphrase) if passphrase.is_empty()) {
        return Err(AppError::InvalidInput(
            "recovery passphrase must not be empty",
        ));
    }
    let backup_id = random_array()?;
    let identity = identity_store.export_backup_record();
    let conversations = if options.include_conversations {
        message_store.map(|store| {
            let mut record = store.export_backup_record();
            if identity.revoked {
                // A revoked source may recover historical conversations, but
                // not pending/future commit material from this device.
                record.pending_commits.clear();
            }
            record
        })
    } else {
        None
    };
    let conversation_count = conversations.as_ref().map_or(Ok(0), |record| {
        checked_u32_len(record.conversations.len(), "conversation count")
    })?;
    let message_count = conversations.as_ref().map_or(Ok(0), |record| {
        checked_u32_len(record.messages.len(), "message count")
    })?;
    let pending_commit_count = conversations.as_ref().map_or(Ok(0), |record| {
        checked_u32_len(record.pending_commits.len(), "pending commit count")
    })?;
    let replay_cursor_count = conversations.as_ref().map_or(Ok(0), |record| {
        checked_u32_len(record.replay_cursors.len(), "replay cursor count")
    })?;
    let plaintext = RecoveryBackupPlaintext {
        manifest: RecoveryManifest {
            backup_id,
            created_at_ms,
            key_policy: secret.policy(),
            allow_active_device_clone: options.allow_active_device_clone,
            source_device_id: identity.device_id,
            source_device_fingerprint: identity.device_fingerprint,
            source_identity_fingerprint: identity.identity_fingerprint,
            source_identity_generation: identity.generation,
            source_device_revoked: identity.revoked,
            includes_identity: true,
            includes_conversations: conversations.is_some(),
            conversation_count,
            message_count,
            pending_commit_count,
            replay_cursor_count,
        },
        identity: Some(identity),
        conversations,
    };
    let plaintext = plaintext.encode()?;
    let mut salt = random_array::<BACKUP_SALT_SIZE>()?;
    let nonce = random_array::<BACKUP_NONCE_SIZE>()?;
    let kdf_policy = StorageKdfPolicy::scrypt_interactive();
    let header = encode_header(secret.policy(), kdf_policy, &salt, &nonce);
    let key = derive_backup_key(secret, &salt, kdf_policy)?;
    let ciphertext = RustCryptoBackend::aead_seal(&key, &nonce, &header, &plaintext)?;
    salt.zeroize();
    let mut bytes = Vec::with_capacity(header.len() + ciphertext.len());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&ciphertext);
    Ok(EncryptedRecoveryBackup { bytes })
}

pub fn inspect_recovery_backup(
    backup: &EncryptedRecoveryBackup,
    secret: BackupSecret<'_>,
) -> AppResult<RecoveryManifest> {
    Ok(open_backup(backup, secret)?.manifest)
}

pub fn import_identity_from_backup(
    backup: &EncryptedRecoveryBackup,
    secret: BackupSecret<'_>,
    identity_path: impl AsRef<Path>,
    identity_password: &[u8],
    policy: IdentityImportPolicy,
) -> AppResult<IdentityStore> {
    let decoded = open_backup(backup, secret)?;
    let preserve_device_id = match policy {
        IdentityImportPolicy::NewDevice => false,
        IdentityImportPolicy::PreserveDeviceIfAllowed => {
            if decoded.manifest.allow_active_device_clone || decoded.manifest.source_device_revoked
            {
                true
            } else {
                return Err(AppError::InvalidState(
                    "backup does not allow preserving an active source device ID",
                ));
            }
        }
    };
    let identity = decoded.identity.ok_or(AppError::InvalidInput(
        "recovery backup does not contain an identity",
    ))?;
    IdentityStore::import_backup_record(
        identity_path,
        identity_password,
        identity,
        preserve_device_id,
    )
}

pub fn import_message_store_from_backup(
    backup: &EncryptedRecoveryBackup,
    secret: BackupSecret<'_>,
    message_store_path: impl AsRef<Path>,
    message_store_password: &[u8],
) -> AppResult<MessageStore> {
    let decoded = open_backup(backup, secret)?;
    let conversations = decoded.conversations.ok_or(AppError::InvalidInput(
        "recovery backup does not contain conversations",
    ))?;
    MessageStore::import_backup_record(message_store_path, message_store_password, conversations)
}

struct RecoveryBackupPlaintext {
    manifest: RecoveryManifest,
    identity: Option<IdentityBackupRecord>,
    conversations: Option<MessageStoreBackupRecord>,
}

impl RecoveryBackupPlaintext {
    fn encode(mut self) -> AppResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(PLAINTEXT_MAGIC);
        put_u32(&mut out, PLAINTEXT_SCHEMA_VERSION);
        encode_manifest(&mut out, &self.manifest)?;
        match self.identity.take() {
            Some(identity) => {
                out.push(1);
                encode_identity_backup_record(&mut out, &identity);
            }
            None => out.push(0),
        }
        match &self.conversations {
            Some(conversations) => {
                out.push(1);
                encode_message_store_backup_record(&mut out, conversations)?;
            }
            None => out.push(0),
        }
        Ok(out)
    }

    fn decode(input: &[u8]) -> AppResult<Self> {
        if input.len() < PLAINTEXT_MAGIC.len() + 4
            || &input[..PLAINTEXT_MAGIC.len()] != PLAINTEXT_MAGIC
        {
            return Err(AppError::InvalidInput(
                "recovery backup plaintext has invalid shape",
            ));
        }
        let mut offset = PLAINTEXT_MAGIC.len();
        let schema = take_u32(input, &mut offset)?;
        if schema != PLAINTEXT_SCHEMA_VERSION {
            return Err(AppError::InvalidInput(
                "recovery backup schema is unsupported",
            ));
        }
        let manifest = decode_manifest(input, &mut offset)?;
        let identity = match take_u8(input, &mut offset)? {
            0 => None,
            1 => Some(decode_identity_backup_record(input, &mut offset)?),
            _ => {
                return Err(AppError::InvalidInput(
                    "recovery backup has invalid identity flag",
                ))
            }
        };
        let conversations = match take_u8(input, &mut offset)? {
            0 => None,
            1 => Some(decode_message_store_backup_record(input, &mut offset)?),
            _ => {
                return Err(AppError::InvalidInput(
                    "recovery backup has invalid conversation flag",
                ))
            }
        };
        if offset != input.len() {
            return Err(AppError::InvalidInput(
                "recovery backup has trailing plaintext",
            ));
        }
        validate_manifest_payload_counts(&manifest, identity.as_ref(), conversations.as_ref())?;
        Ok(Self {
            manifest,
            identity,
            conversations,
        })
    }
}

fn open_backup(
    backup: &EncryptedRecoveryBackup,
    secret: BackupSecret<'_>,
) -> AppResult<RecoveryBackupPlaintext> {
    if backup.bytes.len() <= BACKUP_HEADER_SIZE {
        return Err(AppError::InvalidInput("recovery backup is truncated"));
    }
    let (header, ciphertext) = backup.bytes.split_at(BACKUP_HEADER_SIZE);
    let (policy, kdf_policy, salt, nonce) = decode_header(header)?;
    if policy != secret.policy() {
        return Err(AppError::InvalidInput(
            "recovery backup key policy does not match secret",
        ));
    }
    let key = derive_backup_key(secret, &salt, kdf_policy)?;
    let plaintext = RustCryptoBackend::aead_open(&key, nonce, header, ciphertext)?;
    let decoded = RecoveryBackupPlaintext::decode(&plaintext)?;
    if decoded.manifest.key_policy != policy {
        return Err(AppError::InvalidInput(
            "recovery backup manifest key policy mismatch",
        ));
    }
    Ok(decoded)
}

fn encode_header(
    key_policy: RecoveryKeyPolicy,
    kdf_policy: StorageKdfPolicy,
    salt: &[u8; BACKUP_SALT_SIZE],
    nonce: &[u8; BACKUP_NONCE_SIZE],
) -> [u8; BACKUP_HEADER_SIZE] {
    let mut header = [0_u8; BACKUP_HEADER_SIZE];
    header[..8].copy_from_slice(BACKUP_MAGIC);
    header[8] = BACKUP_VERSION;
    header[9] = kdf_policy.kdf_id;
    header[10] = key_policy as u8;
    header[11..15].copy_from_slice(&kdf_policy.parameter_code.to_be_bytes());
    header[15..47].copy_from_slice(salt);
    header[47..59].copy_from_slice(nonce);
    header
}

fn decode_header(
    header: &[u8],
) -> AppResult<(
    RecoveryKeyPolicy,
    StorageKdfPolicy,
    [u8; BACKUP_SALT_SIZE],
    &[u8; BACKUP_NONCE_SIZE],
)> {
    if header.len() != BACKUP_HEADER_SIZE || &header[..8] != BACKUP_MAGIC {
        return Err(AppError::InvalidInput("recovery backup header is invalid"));
    }
    if header[8] != BACKUP_VERSION {
        return Err(AppError::InvalidInput(
            "recovery backup version is unsupported",
        ));
    }
    if header[9] != KDF_ID_SCRYPT {
        return Err(AppError::InvalidInput("recovery backup KDF is unsupported"));
    }
    let policy = RecoveryKeyPolicy::try_from(header[10])?;
    let parameter_code = u32::from_be_bytes(
        header[11..15]
            .try_into()
            .expect("KDF parameter slice length"),
    );
    let salt = header[15..47].try_into().expect("salt slice length");
    let nonce = header[47..59].try_into().expect("nonce slice length");
    Ok((
        policy,
        StorageKdfPolicy {
            kdf_id: header[9],
            parameter_code,
        },
        salt,
        nonce,
    ))
}

fn derive_backup_key(
    secret: BackupSecret<'_>,
    salt: &[u8; BACKUP_SALT_SIZE],
    kdf_policy: StorageKdfPolicy,
) -> AppResult<SecretBytes<32>> {
    let label = match secret.policy() {
        RecoveryKeyPolicy::UserPassphrase => {
            b"HYDRA-MSG/app/recovery-backup-passphrase-kdf/v2" as &'static [u8]
        }
        RecoveryKeyPolicy::RandomRecoveryKey => {
            b"HYDRA-MSG/app/recovery-backup-random-key-kdf/v2" as &'static [u8]
        }
    };
    derive_storage_key(
        label,
        secret.bytes(),
        salt,
        kdf_policy.kdf_id,
        kdf_policy.parameter_code,
    )
}

fn encode_manifest(out: &mut Vec<u8>, manifest: &RecoveryManifest) -> AppResult<()> {
    out.extend_from_slice(&manifest.backup_id);
    put_u64(out, manifest.created_at_ms);
    out.push(manifest.key_policy as u8);
    out.push(u8::from(manifest.allow_active_device_clone));
    out.extend_from_slice(&manifest.source_device_id.0);
    out.extend_from_slice(&manifest.source_device_fingerprint.0);
    out.extend_from_slice(&manifest.source_identity_fingerprint.0);
    put_u64(out, manifest.source_identity_generation);
    out.push(u8::from(manifest.source_device_revoked));
    out.push(u8::from(manifest.includes_identity));
    out.push(u8::from(manifest.includes_conversations));
    put_u32(out, manifest.conversation_count);
    put_u32(out, manifest.message_count);
    put_u32(out, manifest.pending_commit_count);
    put_u32(out, manifest.replay_cursor_count);
    Ok(())
}

fn decode_manifest(input: &[u8], offset: &mut usize) -> AppResult<RecoveryManifest> {
    Ok(RecoveryManifest {
        backup_id: take_array(input, offset)?,
        created_at_ms: take_u64(input, offset)?,
        key_policy: RecoveryKeyPolicy::try_from(take_u8(input, offset)?)?,
        allow_active_device_clone: take_bool(input, offset, "allow clone")?,
        source_device_id: DeviceId(take_array(input, offset)?),
        source_device_fingerprint: DeviceFingerprint(take_array(input, offset)?),
        source_identity_fingerprint: IdentityFingerprint(take_array(input, offset)?),
        source_identity_generation: take_u64(input, offset)?,
        source_device_revoked: take_bool(input, offset, "source revoked")?,
        includes_identity: take_bool(input, offset, "includes identity")?,
        includes_conversations: take_bool(input, offset, "includes conversations")?,
        conversation_count: take_u32(input, offset)?,
        message_count: take_u32(input, offset)?,
        pending_commit_count: take_u32(input, offset)?,
        replay_cursor_count: take_u32(input, offset)?,
    })
}

fn encode_identity_backup_record(out: &mut Vec<u8>, record: &IdentityBackupRecord) {
    out.extend_from_slice(&record.device_id.0);
    out.extend_from_slice(&record.device_fingerprint.0);
    put_u64(out, record.generation);
    out.push(u8::from(record.revoked));
    out.extend_from_slice(&record.identity_seed);
    out.extend_from_slice(&record.verification_key);
    out.extend_from_slice(&record.identity_fingerprint.0);
}

fn decode_identity_backup_record(
    input: &[u8],
    offset: &mut usize,
) -> AppResult<IdentityBackupRecord> {
    Ok(IdentityBackupRecord {
        device_id: DeviceId(take_array(input, offset)?),
        device_fingerprint: DeviceFingerprint(take_array(input, offset)?),
        generation: take_u64(input, offset)?,
        revoked: take_bool(input, offset, "identity revoked")?,
        identity_seed: take_array(input, offset)?,
        verification_key: take_array::<ML_DSA_65_VK_SIZE>(input, offset)?,
        identity_fingerprint: IdentityFingerprint(take_array(input, offset)?),
    })
}

fn encode_message_store_backup_record(
    out: &mut Vec<u8>,
    record: &MessageStoreBackupRecord,
) -> AppResult<()> {
    out.push(record.skipped_key_policy as u8);
    put_vec(out, &record.conversations, encode_conversation)?;
    put_vec(out, &record.messages, encode_message)?;
    put_vec(out, &record.pending_commits, encode_pending_commit)?;
    put_vec(out, &record.replay_cursors, encode_replay_cursor)?;
    Ok(())
}

fn decode_message_store_backup_record(
    input: &[u8],
    offset: &mut usize,
) -> AppResult<MessageStoreBackupRecord> {
    Ok(MessageStoreBackupRecord {
        skipped_key_policy: SkippedKeyPersistencePolicy::try_from(take_u8(input, offset)?)?,
        conversations: take_vec(input, offset, decode_conversation)?,
        messages: take_vec(input, offset, decode_message)?,
        pending_commits: take_vec(input, offset, decode_pending_commit)?,
        replay_cursors: take_vec(input, offset, decode_replay_cursor)?,
    })
}

fn encode_conversation(out: &mut Vec<u8>, conversation: &StoredConversation) -> AppResult<()> {
    out.extend_from_slice(&conversation.id.0);
    out.push(conversation.kind as u8);
    put_u64(out, conversation.created_at_ms);
    put_u64(out, conversation.current_epoch);
    put_u64(out, conversation.current_state_version);
    put_vec(out, &conversation.members, encode_member)
}

fn decode_conversation(input: &[u8], offset: &mut usize) -> AppResult<StoredConversation> {
    Ok(StoredConversation {
        id: ConversationId(take_array(input, offset)?),
        kind: ConversationKind::try_from(take_u8(input, offset)?)?,
        created_at_ms: take_u64(input, offset)?,
        current_epoch: take_u64(input, offset)?,
        current_state_version: take_u64(input, offset)?,
        members: take_vec(input, offset, decode_member)?,
    })
}

fn encode_member(out: &mut Vec<u8>, member: &StoredMember) -> AppResult<()> {
    out.extend_from_slice(&member.member_id);
    out.extend_from_slice(&member.identity_fingerprint.0);
    out.push(member.role);
    out.push(u8::from(member.active));
    Ok(())
}

fn decode_member(input: &[u8], offset: &mut usize) -> AppResult<StoredMember> {
    Ok(StoredMember {
        member_id: take_array(input, offset)?,
        identity_fingerprint: IdentityFingerprint(take_array(input, offset)?),
        role: take_u8(input, offset)?,
        active: take_bool(input, offset, "member active")?,
    })
}

fn encode_message(out: &mut Vec<u8>, message: &StoredMessage) -> AppResult<()> {
    out.extend_from_slice(&message.conversation_id.0);
    out.push(message.direction as u8);
    out.extend_from_slice(&message.sender_id);
    put_u64(out, message.epoch);
    put_u64(out, message.state_version);
    put_u64(out, message.message_index);
    put_u64(out, message.received_at_ms);
    put_bytes(out, &message.content)
}

fn decode_message(input: &[u8], offset: &mut usize) -> AppResult<StoredMessage> {
    Ok(StoredMessage {
        conversation_id: ConversationId(take_array(input, offset)?),
        direction: MessageDirection::try_from(take_u8(input, offset)?)?,
        sender_id: take_array(input, offset)?,
        epoch: take_u64(input, offset)?,
        state_version: take_u64(input, offset)?,
        message_index: take_u64(input, offset)?,
        received_at_ms: take_u64(input, offset)?,
        content: take_bytes(input, offset)?,
    })
}

fn encode_pending_commit(out: &mut Vec<u8>, commit: &PendingCommitRecord) -> AppResult<()> {
    out.extend_from_slice(&commit.conversation_id.0);
    put_u64(out, commit.epoch);
    put_u64(out, commit.state_version);
    out.extend_from_slice(&commit.parent_commit_hash);
    put_bytes(out, &commit.commit_bytes)
}

fn decode_pending_commit(input: &[u8], offset: &mut usize) -> AppResult<PendingCommitRecord> {
    Ok(PendingCommitRecord {
        conversation_id: ConversationId(take_array(input, offset)?),
        epoch: take_u64(input, offset)?,
        state_version: take_u64(input, offset)?,
        parent_commit_hash: take_array(input, offset)?,
        commit_bytes: take_bytes(input, offset)?,
    })
}

fn encode_replay_cursor(out: &mut Vec<u8>, cursor: &ReplayCursorRecord) -> AppResult<()> {
    out.extend_from_slice(&cursor.conversation_id.0);
    out.extend_from_slice(&cursor.stream_id);
    match cursor.highest_seen {
        Some(value) => {
            out.push(1);
            put_u64(out, value);
        }
        None => out.push(0),
    }
    put_u32(
        out,
        checked_u32_len(cursor.window_words.len(), "replay window word count")?,
    );
    for word in &cursor.window_words {
        put_u64(out, *word);
    }
    Ok(())
}

fn decode_replay_cursor(input: &[u8], offset: &mut usize) -> AppResult<ReplayCursorRecord> {
    let conversation_id = ConversationId(take_array(input, offset)?);
    let stream_id = take_array(input, offset)?;
    let highest_seen = match take_u8(input, offset)? {
        0 => None,
        1 => Some(take_u64(input, offset)?),
        _ => {
            return Err(AppError::InvalidInput(
                "recovery backup has invalid replay flag",
            ))
        }
    };
    let word_count = take_u32(input, offset)? as usize;
    let mut window_words = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        window_words.push(take_u64(input, offset)?);
    }
    Ok(ReplayCursorRecord {
        conversation_id,
        stream_id,
        highest_seen,
        window_words,
    })
}

fn validate_manifest_payload_counts(
    manifest: &RecoveryManifest,
    identity: Option<&IdentityBackupRecord>,
    conversations: Option<&MessageStoreBackupRecord>,
) -> AppResult<()> {
    if manifest.includes_identity != identity.is_some() {
        return Err(AppError::InvalidInput(
            "recovery backup identity flag mismatch",
        ));
    }
    if let Some(identity) = identity {
        if manifest.source_device_id != identity.device_id
            || manifest.source_device_fingerprint != identity.device_fingerprint
            || manifest.source_identity_fingerprint != identity.identity_fingerprint
            || manifest.source_identity_generation != identity.generation
            || manifest.source_device_revoked != identity.revoked
        {
            return Err(AppError::InvalidInput(
                "recovery backup identity manifest mismatch",
            ));
        }
    }
    if manifest.includes_conversations != conversations.is_some() {
        return Err(AppError::InvalidInput(
            "recovery backup conversation flag mismatch",
        ));
    }
    if let Some(record) = conversations {
        if checked_u32_len(record.conversations.len(), "conversation count")?
            != manifest.conversation_count
            || checked_u32_len(record.messages.len(), "message count")? != manifest.message_count
            || checked_u32_len(record.pending_commits.len(), "pending commit count")?
                != manifest.pending_commit_count
            || checked_u32_len(record.replay_cursors.len(), "replay cursor count")?
                != manifest.replay_cursor_count
        {
            return Err(AppError::InvalidInput(
                "recovery backup manifest counts mismatch",
            ));
        }
    } else if manifest.conversation_count != 0
        || manifest.message_count != 0
        || manifest.pending_commit_count != 0
        || manifest.replay_cursor_count != 0
    {
        return Err(AppError::InvalidInput(
            "recovery backup manifest has nonzero empty counts",
        ));
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> AppResult<()> {
    crash_safe_atomic_write(path, bytes, "recovery backup cannot be committed")
}

fn put_vec<T>(
    out: &mut Vec<u8>,
    items: &[T],
    mut encode: impl FnMut(&mut Vec<u8>, &T) -> AppResult<()>,
) -> AppResult<()> {
    put_u32(out, checked_u32_len(items.len(), "item count")?);
    for item in items {
        encode(out, item)?;
    }
    Ok(())
}

fn take_vec<T>(
    input: &[u8],
    offset: &mut usize,
    mut decode: impl FnMut(&[u8], &mut usize) -> AppResult<T>,
) -> AppResult<Vec<T>> {
    let count = take_u32(input, offset)? as usize;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(decode(input, offset)?);
    }
    Ok(items)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> AppResult<()> {
    put_u32(out, checked_u32_len(bytes.len(), "byte string")?);
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_bytes(input: &[u8], offset: &mut usize) -> AppResult<Vec<u8>> {
    let len = take_u32(input, offset)? as usize;
    let end = offset
        .checked_add(len)
        .ok_or(AppError::InvalidInput("recovery backup offset overflow"))?;
    let bytes = input
        .get(*offset..end)
        .ok_or(AppError::InvalidInput(
            "recovery backup byte string is truncated",
        ))?
        .to_vec();
    *offset = end;
    Ok(bytes)
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn take_u8(input: &[u8], offset: &mut usize) -> AppResult<u8> {
    let value = *input
        .get(*offset)
        .ok_or(AppError::InvalidInput("recovery backup field is truncated"))?;
    *offset += 1;
    Ok(value)
}

fn take_bool(input: &[u8], offset: &mut usize, label: &'static str) -> AppResult<bool> {
    match take_u8(input, offset)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AppError::InvalidInput(label)),
    }
}

fn take_u32(input: &[u8], offset: &mut usize) -> AppResult<u32> {
    Ok(u32::from_be_bytes(take_array(input, offset)?))
}

fn take_u64(input: &[u8], offset: &mut usize) -> AppResult<u64> {
    Ok(u64::from_be_bytes(take_array(input, offset)?))
}

fn take_array<const N: usize>(input: &[u8], offset: &mut usize) -> AppResult<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(AppError::InvalidInput("recovery backup offset overflow"))?;
    let value = input
        .get(*offset..end)
        .ok_or(AppError::InvalidInput("recovery backup field is truncated"))?
        .try_into()
        .map_err(|_| AppError::InvalidInput("recovery backup field has invalid length"))?;
    *offset = end;
    Ok(value)
}

fn checked_u32_len(len: usize, label: &'static str) -> AppResult<u32> {
    u32::try_from(len).map_err(|_| AppError::InvalidInput(label))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::AppErrorClass;

    use super::*;

    fn temp_path(name: &str, suffix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hydra-msg-{name}-{nonce}.{suffix}"))
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn backup_imports_identity_as_new_device_by_default() {
        let source_path = temp_path("recovery-source", "hydraid");
        let import_path = temp_path("recovery-import", "hydraid");
        let source = IdentityStore::create(&source_path, b"source password").unwrap();
        let source_metadata = source.metadata();
        let backup = export_recovery_backup(
            &source,
            None,
            BackupSecret::Passphrase(b"recovery phrase words"),
            RecoveryBackupOptions::default(),
            42,
        )
        .unwrap();
        assert_eq!(backup.as_bytes()[9], KDF_ID_SCRYPT);
        assert!(!contains(backup.as_bytes(), PLAINTEXT_MAGIC));
        assert!(!contains(
            backup.as_bytes(),
            source.export_backup_record().identity_seed.as_slice()
        ));

        let imported = import_identity_from_backup(
            &backup,
            BackupSecret::Passphrase(b"recovery phrase words"),
            &import_path,
            b"new local password",
            IdentityImportPolicy::NewDevice,
        )
        .unwrap();
        assert_eq!(imported.public_identity(), source.public_identity());
        assert_ne!(imported.device_id(), source_metadata.device_id);
        assert_ne!(
            imported.device_fingerprint(),
            source_metadata.device_fingerprint
        );
        match IdentityStore::load_for_device(
            &import_path,
            b"new local password",
            source_metadata.device_id,
        ) {
            Ok(_) => panic!("recovery silently cloned the source active device ID"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::InvalidState),
        }
        fs::remove_file(source_path).ok();
        fs::remove_file(import_path).ok();
    }

    #[test]
    fn preserving_active_device_requires_explicit_backup_policy() {
        let source_path = temp_path("recovery-clone-source", "hydraid");
        let import_path = temp_path("recovery-clone-import", "hydraid");
        let source = IdentityStore::create(&source_path, b"source password").unwrap();
        let backup = export_recovery_backup(
            &source,
            None,
            BackupSecret::Passphrase(b"clone recovery"),
            RecoveryBackupOptions::default(),
            43,
        )
        .unwrap();
        match import_identity_from_backup(
            &backup,
            BackupSecret::Passphrase(b"clone recovery"),
            &import_path,
            b"new local password",
            IdentityImportPolicy::PreserveDeviceIfAllowed,
        ) {
            Ok(_) => panic!("preserved active device without explicit backup allowance"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::InvalidState),
        }

        let allowed = export_recovery_backup(
            &source,
            None,
            BackupSecret::Passphrase(b"clone recovery"),
            RecoveryBackupOptions {
                allow_active_device_clone: true,
                include_conversations: false,
            },
            44,
        )
        .unwrap();
        let imported = import_identity_from_backup(
            &allowed,
            BackupSecret::Passphrase(b"clone recovery"),
            &import_path,
            b"new local password",
            IdentityImportPolicy::PreserveDeviceIfAllowed,
        )
        .unwrap();
        assert_eq!(imported.device_id(), source.device_id());
        fs::remove_file(source_path).ok();
        fs::remove_file(import_path).ok();
    }

    #[test]
    fn backup_exports_and_imports_conversations_without_plaintext_on_backup_disk() {
        let identity_path = temp_path("recovery-msg-id", "hydraid");
        let message_path = temp_path("recovery-msg-db", "hydramsgdb");
        let import_message_path = temp_path("recovery-msg-import", "hydramsgdb");
        let identity = IdentityStore::create(&identity_path, b"id password").unwrap();
        let mut messages = MessageStore::create(&message_path, b"db password").unwrap();
        let conversation_id = messages
            .create_conversation(ConversationKind::Direct, 1000)
            .unwrap();
        messages
            .append_message(StoredMessage {
                conversation_id,
                direction: MessageDirection::Outbound,
                sender_id: [7; 32],
                epoch: 1,
                state_version: 2,
                message_index: 3,
                received_at_ms: 1001,
                content: b"secret recovery message".to_vec(),
            })
            .unwrap();
        messages
            .record_replay_cursor(ReplayCursorRecord {
                conversation_id,
                stream_id: [9; 32],
                highest_seen: Some(3),
                window_words: vec![1],
            })
            .unwrap();
        messages.save(b"db password").unwrap();
        let key = RecoveryKey::from_bytes([0x42; 32]);
        let backup = export_recovery_backup(
            &identity,
            Some(&messages),
            BackupSecret::RecoveryKey(&key),
            RecoveryBackupOptions::default(),
            45,
        )
        .unwrap();
        assert!(!contains(backup.as_bytes(), b"secret recovery message"));
        let manifest = inspect_recovery_backup(&backup, BackupSecret::RecoveryKey(&key)).unwrap();
        assert_eq!(manifest.key_policy, RecoveryKeyPolicy::RandomRecoveryKey);
        assert_eq!(manifest.conversation_count, 1);
        assert_eq!(manifest.message_count, 1);
        assert_eq!(manifest.replay_cursor_count, 1);

        let imported = import_message_store_from_backup(
            &backup,
            BackupSecret::RecoveryKey(&key),
            &import_message_path,
            b"import db password",
        )
        .unwrap();
        assert_eq!(imported.conversations().len(), 1);
        assert_eq!(
            imported.messages()[0].content,
            b"secret recovery message".to_vec()
        );
        assert_eq!(imported.replay_cursors().len(), 1);
        fs::remove_file(identity_path).ok();
        fs::remove_file(message_path).ok();
        fs::remove_file(import_message_path).ok();
    }

    #[test]
    fn wrong_secret_and_corruption_reject() {
        let identity_path = temp_path("recovery-reject-id", "hydraid");
        let identity = IdentityStore::create(&identity_path, b"id password").unwrap();
        let backup = export_recovery_backup(
            &identity,
            None,
            BackupSecret::Passphrase(b"right phrase"),
            RecoveryBackupOptions::default(),
            46,
        )
        .unwrap();
        match inspect_recovery_backup(&backup, BackupSecret::Passphrase(b"wrong phrase")) {
            Ok(_) => panic!("wrong recovery phrase opened backup"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::Authentication),
        }
        let mut corrupted = backup.as_bytes().to_vec();
        *corrupted.last_mut().unwrap() ^= 1;
        match inspect_recovery_backup(
            &EncryptedRecoveryBackup::from_bytes(corrupted),
            BackupSecret::Passphrase(b"right phrase"),
        ) {
            Ok(_) => panic!("corrupted recovery backup opened"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::Authentication),
        }
        fs::remove_file(identity_path).ok();
    }

    #[test]
    fn revoked_device_imports_as_revoked_and_cannot_sign_after_recovery() {
        let source_path = temp_path("recovery-revoked-source", "hydraid");
        let import_path = temp_path("recovery-revoked-import", "hydraid");
        let mut source = IdentityStore::create(&source_path, b"source password").unwrap();
        source.revoke(b"source password").unwrap();
        let backup = export_recovery_backup(
            &source,
            None,
            BackupSecret::Passphrase(b"revoked phrase"),
            RecoveryBackupOptions::default(),
            47,
        )
        .unwrap();
        let imported = import_identity_from_backup(
            &backup,
            BackupSecret::Passphrase(b"revoked phrase"),
            &import_path,
            b"new local password",
            IdentityImportPolicy::PreserveDeviceIfAllowed,
        )
        .unwrap();
        assert!(imported.is_revoked());
        match imported.identity() {
            Ok(_) => panic!("revoked recovered device exposed signing identity"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::InvalidState),
        }
        fs::remove_file(source_path).ok();
        fs::remove_file(import_path).ok();
    }
}
