use std::path::{Path, PathBuf};

use hydra_core::types::IdentityFingerprint;
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use zeroize::Zeroize;

use crate::{
    random::random_array,
    secret_handling::{
        crash_safe_atomic_write, derive_storage_key, read_crash_safe, StorageKdfPolicy,
        KDF_ID_SCRYPT,
    },
    AppError, AppResult,
};

const STORE_MAGIC: &[u8; 8] = b"HYDRADB1";
const STORE_VERSION: u8 = 1;
const STORE_SALT_SIZE: usize = 32;
const STORE_NONCE_SIZE: usize = 12;
const STORE_HEADER_SIZE: usize = 8 + 1 + 1 + 4 + STORE_SALT_SIZE + STORE_NONCE_SIZE;
const PLAINTEXT_MAGIC: &[u8; 15] = b"HYDRADB-PLAIN-1";
const PLAINTEXT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConversationId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationKind {
    Direct = 1,
    GroupLite = 2,
    GroupInteractive = 3,
    GroupBroadcast = 4,
}

impl TryFrom<u8> for ConversationKind {
    type Error = AppError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Direct),
            2 => Ok(Self::GroupLite),
            3 => Ok(Self::GroupInteractive),
            4 => Ok(Self::GroupBroadcast),
            _ => Err(AppError::InvalidInput(
                "message database has invalid conversation kind",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDirection {
    Outbound = 1,
    Inbound = 2,
}

impl TryFrom<u8> for MessageDirection {
    type Error = AppError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Outbound),
            2 => Ok(Self::Inbound),
            _ => Err(AppError::InvalidInput(
                "message database has invalid message direction",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkippedKeyPersistencePolicy {
    /// Skipped message keys are not persisted by this app database. Replay
    /// cursors and message metadata still persist. Apps that need resumable
    /// out-of-order decryption should persist encrypted skipped-key material in
    /// a later, explicitly audited key-state store.
    Disabled = 0,
    /// Reserved policy bit for a later encrypted skipped-key state store.
    PersistEncrypted = 1,
}

impl TryFrom<u8> for SkippedKeyPersistencePolicy {
    type Error = AppError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::PersistEncrypted),
            _ => Err(AppError::InvalidInput(
                "message database has invalid skipped-key policy",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredConversation {
    pub id: ConversationId,
    pub kind: ConversationKind,
    pub created_at_ms: u64,
    pub current_epoch: u64,
    pub current_state_version: u64,
    pub members: Vec<StoredMember>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMember {
    pub member_id: [u8; 32],
    pub identity_fingerprint: IdentityFingerprint,
    pub role: u8,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMessage {
    pub conversation_id: ConversationId,
    pub direction: MessageDirection,
    pub sender_id: [u8; 32],
    pub epoch: u64,
    pub state_version: u64,
    pub message_index: u64,
    pub received_at_ms: u64,
    /// Decrypted app content or raw protocol envelope, depending on the app's
    /// retention policy. This field is stored only inside the encrypted DB.
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCommitRecord {
    pub conversation_id: ConversationId,
    pub epoch: u64,
    pub state_version: u64,
    pub parent_commit_hash: [u8; 64],
    pub commit_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayCursorRecord {
    pub conversation_id: ConversationId,
    pub stream_id: [u8; 32],
    pub highest_seen: Option<u64>,
    pub window_words: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MessageStoreBackupRecord {
    pub(crate) skipped_key_policy: SkippedKeyPersistencePolicy,
    pub(crate) conversations: Vec<StoredConversation>,
    pub(crate) messages: Vec<StoredMessage>,
    pub(crate) pending_commits: Vec<PendingCommitRecord>,
    pub(crate) replay_cursors: Vec<ReplayCursorRecord>,
}

/// Encrypted local message database.
///
/// The file is an authenticated ciphertext containing conversations, members,
/// messages, pending commits, replay cursors, and the skipped-key persistence
/// policy. The store writes via temp-file + rename and rejects wrong passwords,
/// corruption, and unsupported versions before returning any decoded state.
pub struct MessageStore {
    path: PathBuf,
    skipped_key_policy: SkippedKeyPersistencePolicy,
    conversations: Vec<StoredConversation>,
    messages: Vec<StoredMessage>,
    pending_commits: Vec<PendingCommitRecord>,
    replay_cursors: Vec<ReplayCursorRecord>,
}

impl MessageStore {
    pub fn create(path: impl AsRef<Path>, password: &[u8]) -> AppResult<Self> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
            skipped_key_policy: SkippedKeyPersistencePolicy::Disabled,
            conversations: Vec::new(),
            messages: Vec::new(),
            pending_commits: Vec::new(),
            replay_cursors: Vec::new(),
        };
        store.save(password)?;
        Ok(store)
    }

    pub fn load(path: impl AsRef<Path>, password: &[u8]) -> AppResult<Self> {
        let path = path.as_ref();
        let file = read_crash_safe(path, "message database cannot be read")?;
        if file.len() <= STORE_HEADER_SIZE {
            return Err(AppError::InvalidInput("message database is truncated"));
        }
        let (header, ciphertext) = file.split_at(STORE_HEADER_SIZE);
        let (kdf_policy, salt, nonce) = decode_header(header)?;
        let key = derive_store_key(password, &salt, kdf_policy)?;
        let plaintext = RustCryptoBackend::aead_open(&key, nonce, header, ciphertext)?;
        let decoded = DecodedMessageStore::decode(&plaintext)?;
        Ok(Self {
            path: path.to_path_buf(),
            skipped_key_policy: decoded.skipped_key_policy,
            conversations: decoded.conversations,
            messages: decoded.messages,
            pending_commits: decoded.pending_commits,
            replay_cursors: decoded.replay_cursors,
        })
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

    pub fn create_conversation(
        &mut self,
        kind: ConversationKind,
        created_at_ms: u64,
    ) -> AppResult<ConversationId> {
        let id = ConversationId(random_array()?);
        self.insert_conversation(StoredConversation {
            id,
            kind,
            created_at_ms,
            current_epoch: 0,
            current_state_version: 0,
            members: Vec::new(),
        })?;
        Ok(id)
    }

    pub fn insert_conversation(&mut self, conversation: StoredConversation) -> AppResult<()> {
        if self
            .conversations
            .iter()
            .any(|existing| existing.id == conversation.id)
        {
            return Err(AppError::InvalidState("conversation already exists"));
        }
        self.conversations.push(conversation);
        Ok(())
    }

    pub fn upsert_member(
        &mut self,
        conversation_id: ConversationId,
        member: StoredMember,
    ) -> AppResult<()> {
        let conversation = self.conversation_mut(conversation_id)?;
        match conversation
            .members
            .iter_mut()
            .find(|existing| existing.member_id == member.member_id)
        {
            Some(existing) => *existing = member,
            None => conversation.members.push(member),
        }
        Ok(())
    }

    pub fn set_conversation_epoch(
        &mut self,
        conversation_id: ConversationId,
        epoch: u64,
        state_version: u64,
    ) -> AppResult<()> {
        let conversation = self.conversation_mut(conversation_id)?;
        conversation.current_epoch = epoch;
        conversation.current_state_version = state_version;
        Ok(())
    }

    pub fn append_message(&mut self, message: StoredMessage) -> AppResult<()> {
        self.conversation(message.conversation_id)?;
        if self.messages.iter().any(|existing| {
            existing.conversation_id == message.conversation_id
                && existing.sender_id == message.sender_id
                && existing.epoch == message.epoch
                && existing.message_index == message.message_index
        }) {
            return Err(AppError::InvalidState("message already exists"));
        }
        self.messages.push(message);
        Ok(())
    }

    pub fn store_pending_commit(&mut self, commit: PendingCommitRecord) -> AppResult<()> {
        self.conversation(commit.conversation_id)?;
        self.pending_commits.retain(|existing| {
            !(existing.conversation_id == commit.conversation_id
                && existing.epoch == commit.epoch
                && existing.state_version == commit.state_version)
        });
        self.pending_commits.push(commit);
        Ok(())
    }

    pub fn clear_pending_commit(
        &mut self,
        conversation_id: ConversationId,
        epoch: u64,
        state_version: u64,
    ) -> AppResult<()> {
        self.conversation(conversation_id)?;
        self.pending_commits.retain(|existing| {
            !(existing.conversation_id == conversation_id
                && existing.epoch == epoch
                && existing.state_version == state_version)
        });
        Ok(())
    }

    pub fn record_replay_cursor(&mut self, cursor: ReplayCursorRecord) -> AppResult<()> {
        self.conversation(cursor.conversation_id)?;
        self.replay_cursors.retain(|existing| {
            !(existing.conversation_id == cursor.conversation_id
                && existing.stream_id == cursor.stream_id)
        });
        self.replay_cursors.push(cursor);
        Ok(())
    }

    pub(crate) fn export_backup_record(&self) -> MessageStoreBackupRecord {
        MessageStoreBackupRecord {
            skipped_key_policy: self.skipped_key_policy,
            conversations: self.conversations.clone(),
            messages: self.messages.clone(),
            pending_commits: self.pending_commits.clone(),
            replay_cursors: self.replay_cursors.clone(),
        }
    }

    pub(crate) fn import_backup_record(
        path: impl AsRef<Path>,
        password: &[u8],
        record: MessageStoreBackupRecord,
    ) -> AppResult<Self> {
        validate_decoded_store(
            &record.conversations,
            &record.messages,
            &record.pending_commits,
            &record.replay_cursors,
        )?;
        let store = Self {
            path: path.as_ref().to_path_buf(),
            skipped_key_policy: record.skipped_key_policy,
            conversations: record.conversations,
            messages: record.messages,
            pending_commits: record.pending_commits,
            replay_cursors: record.replay_cursors,
        };
        store.save(password)?;
        Ok(store)
    }

    #[must_use]
    pub const fn skipped_key_policy(&self) -> SkippedKeyPersistencePolicy {
        self.skipped_key_policy
    }

    pub fn set_skipped_key_policy(&mut self, policy: SkippedKeyPersistencePolicy) {
        self.skipped_key_policy = policy;
    }

    #[must_use]
    pub fn conversations(&self) -> &[StoredConversation] {
        &self.conversations
    }

    #[must_use]
    pub fn messages(&self) -> &[StoredMessage] {
        &self.messages
    }

    #[must_use]
    pub fn pending_commits(&self) -> &[PendingCommitRecord] {
        &self.pending_commits
    }

    #[must_use]
    pub fn replay_cursors(&self) -> &[ReplayCursorRecord] {
        &self.replay_cursors
    }

    pub fn messages_for(&self, conversation_id: ConversationId) -> AppResult<Vec<&StoredMessage>> {
        self.conversation(conversation_id)?;
        Ok(self
            .messages
            .iter()
            .filter(|message| message.conversation_id == conversation_id)
            .collect())
    }

    fn conversation(&self, id: ConversationId) -> AppResult<&StoredConversation> {
        self.conversations
            .iter()
            .find(|conversation| conversation.id == id)
            .ok_or(AppError::InvalidInput("conversation does not exist"))
    }

    fn conversation_mut(&mut self, id: ConversationId) -> AppResult<&mut StoredConversation> {
        self.conversations
            .iter_mut()
            .find(|conversation| conversation.id == id)
            .ok_or(AppError::InvalidInput("conversation does not exist"))
    }

    fn encode_plaintext(&self) -> AppResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(PLAINTEXT_MAGIC);
        put_u32(&mut out, PLAINTEXT_SCHEMA_VERSION);
        out.push(self.skipped_key_policy as u8);
        put_vec(&mut out, &self.conversations, encode_conversation)?;
        put_vec(&mut out, &self.messages, encode_message)?;
        put_vec(&mut out, &self.pending_commits, encode_pending_commit)?;
        put_vec(&mut out, &self.replay_cursors, encode_replay_cursor)?;
        Ok(out)
    }
}

struct DecodedMessageStore {
    skipped_key_policy: SkippedKeyPersistencePolicy,
    conversations: Vec<StoredConversation>,
    messages: Vec<StoredMessage>,
    pending_commits: Vec<PendingCommitRecord>,
    replay_cursors: Vec<ReplayCursorRecord>,
}

impl DecodedMessageStore {
    fn decode(input: &[u8]) -> AppResult<Self> {
        if input.len() < PLAINTEXT_MAGIC.len() + 5
            || &input[..PLAINTEXT_MAGIC.len()] != PLAINTEXT_MAGIC
        {
            return Err(AppError::InvalidInput(
                "message database plaintext has invalid shape",
            ));
        }
        let mut offset = PLAINTEXT_MAGIC.len();
        let schema = take_u32(input, &mut offset)?;
        if schema != PLAINTEXT_SCHEMA_VERSION {
            return Err(AppError::InvalidInput(
                "message database schema is unsupported",
            ));
        }
        let skipped_key_policy =
            SkippedKeyPersistencePolicy::try_from(take_u8(input, &mut offset)?)?;
        let conversations = take_vec(input, &mut offset, decode_conversation)?;
        let messages = take_vec(input, &mut offset, decode_message)?;
        let pending_commits = take_vec(input, &mut offset, decode_pending_commit)?;
        let replay_cursors = take_vec(input, &mut offset, decode_replay_cursor)?;
        if offset != input.len() {
            return Err(AppError::InvalidInput(
                "message database has trailing bytes",
            ));
        }
        validate_decoded_store(&conversations, &messages, &pending_commits, &replay_cursors)?;
        Ok(Self {
            skipped_key_policy,
            conversations,
            messages,
            pending_commits,
            replay_cursors,
        })
    }
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
    let id = ConversationId(take_array(input, offset)?);
    let kind = ConversationKind::try_from(take_u8(input, offset)?)?;
    let created_at_ms = take_u64(input, offset)?;
    let current_epoch = take_u64(input, offset)?;
    let current_state_version = take_u64(input, offset)?;
    let members = take_vec(input, offset, decode_member)?;
    Ok(StoredConversation {
        id,
        kind,
        created_at_ms,
        current_epoch,
        current_state_version,
        members,
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
    let member_id = take_array(input, offset)?;
    let identity_fingerprint = IdentityFingerprint(take_array(input, offset)?);
    let role = take_u8(input, offset)?;
    let active = match take_u8(input, offset)? {
        0 => false,
        1 => true,
        _ => {
            return Err(AppError::InvalidInput(
                "message database has invalid member active flag",
            ))
        }
    };
    Ok(StoredMember {
        member_id,
        identity_fingerprint,
        role,
        active,
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
    let conversation_id = ConversationId(take_array(input, offset)?);
    let direction = MessageDirection::try_from(take_u8(input, offset)?)?;
    let sender_id = take_array(input, offset)?;
    let epoch = take_u64(input, offset)?;
    let state_version = take_u64(input, offset)?;
    let message_index = take_u64(input, offset)?;
    let received_at_ms = take_u64(input, offset)?;
    let content = take_bytes(input, offset)?;
    Ok(StoredMessage {
        conversation_id,
        direction,
        sender_id,
        epoch,
        state_version,
        message_index,
        received_at_ms,
        content,
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
    let conversation_id = ConversationId(take_array(input, offset)?);
    let epoch = take_u64(input, offset)?;
    let state_version = take_u64(input, offset)?;
    let parent_commit_hash = take_array(input, offset)?;
    let commit_bytes = take_bytes(input, offset)?;
    Ok(PendingCommitRecord {
        conversation_id,
        epoch,
        state_version,
        parent_commit_hash,
        commit_bytes,
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
                "message database has invalid replay flag",
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

fn validate_decoded_store(
    conversations: &[StoredConversation],
    messages: &[StoredMessage],
    pending_commits: &[PendingCommitRecord],
    replay_cursors: &[ReplayCursorRecord],
) -> AppResult<()> {
    for (index, conversation) in conversations.iter().enumerate() {
        if conversations[index + 1..]
            .iter()
            .any(|other| other.id == conversation.id)
        {
            return Err(AppError::InvalidInput(
                "message database has duplicate conversation ID",
            ));
        }
        for (member_index, member) in conversation.members.iter().enumerate() {
            if conversation.members[member_index + 1..]
                .iter()
                .any(|other| other.member_id == member.member_id)
            {
                return Err(AppError::InvalidInput(
                    "message database has duplicate member ID",
                ));
            }
        }
    }
    for message in messages {
        ensure_conversation_exists(conversations, message.conversation_id)?;
    }
    for commit in pending_commits {
        ensure_conversation_exists(conversations, commit.conversation_id)?;
    }
    for cursor in replay_cursors {
        ensure_conversation_exists(conversations, cursor.conversation_id)?;
    }
    Ok(())
}

fn ensure_conversation_exists(
    conversations: &[StoredConversation],
    id: ConversationId,
) -> AppResult<()> {
    if conversations
        .iter()
        .any(|conversation| conversation.id == id)
    {
        Ok(())
    } else {
        Err(AppError::InvalidInput(
            "message database references missing conversation",
        ))
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
        return Err(AppError::InvalidInput("message database header is invalid"));
    }
    if header[8] != STORE_VERSION {
        return Err(AppError::InvalidInput(
            "message database version is unsupported",
        ));
    }
    if header[9] != KDF_ID_SCRYPT {
        return Err(AppError::InvalidInput(
            "message database KDF is unsupported",
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
        b"HYDRA-MSG/app/message-store-kdf/v1" as &'static [u8],
        password,
        salt,
        kdf_policy.kdf_id,
        kdf_policy.parameter_code,
    )
}

fn atomic_write(path: &Path, bytes: &[u8]) -> AppResult<()> {
    crash_safe_atomic_write(path, bytes, "message database cannot be committed")
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
        .ok_or(AppError::InvalidInput("message database offset overflow"))?;
    let bytes = input
        .get(*offset..end)
        .ok_or(AppError::InvalidInput(
            "message database byte string is truncated",
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
    let value = *input.get(*offset).ok_or(AppError::InvalidInput(
        "message database field is truncated",
    ))?;
    *offset += 1;
    Ok(value)
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
        .ok_or(AppError::InvalidInput("message database offset overflow"))?;
    let value = input
        .get(*offset..end)
        .ok_or(AppError::InvalidInput(
            "message database field is truncated",
        ))?
        .try_into()
        .map_err(|_| AppError::InvalidInput("message database field has invalid length"))?;
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

    fn temp_store_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hydra-msg-{name}-{nonce}.hydramsgdb"))
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn create_save_load_and_keep_messages_encrypted_on_disk() {
        let path = temp_store_path("message-create-load");
        let password = b"correct message database password";
        let mut store = MessageStore::create(&path, password).unwrap();
        let conversation_id = store
            .create_conversation(ConversationKind::GroupLite, 1_234)
            .unwrap();
        store
            .upsert_member(
                conversation_id,
                StoredMember {
                    member_id: [0x11; 32],
                    identity_fingerprint: IdentityFingerprint([0x22; 32]),
                    role: 1,
                    active: true,
                },
            )
            .unwrap();
        store
            .append_message(StoredMessage {
                conversation_id,
                direction: MessageDirection::Inbound,
                sender_id: [0x11; 32],
                epoch: 7,
                state_version: 9,
                message_index: 3,
                received_at_ms: 5_678,
                content: b"private local message body".to_vec(),
            })
            .unwrap();
        store.save(password).unwrap();

        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes[9], KDF_ID_SCRYPT);
        assert!(!contains(&bytes, b"private local message body"));
        assert!(!contains(&bytes, PLAINTEXT_MAGIC));

        let loaded = MessageStore::load(&path, password).unwrap();
        assert_eq!(loaded.conversations().len(), 1);
        assert_eq!(
            loaded.messages_for(conversation_id).unwrap()[0].content,
            b"private local message body"
        );
        assert_eq!(
            loaded.skipped_key_policy(),
            SkippedKeyPersistencePolicy::Disabled
        );
        let temp = path.with_extension("tmp");
        assert!(!temp.exists());
        fs::remove_file(path).ok();
    }

    #[test]
    fn missing_primary_file_recovers_last_committed_backup() {
        let path = temp_store_path("message-crash-recover");
        let password = b"message crash recovery password";
        let mut store = MessageStore::create(&path, password).unwrap();
        let conversation_id = store
            .create_conversation(ConversationKind::Direct, 1)
            .unwrap();
        store.save(password).unwrap();
        let backup = path.with_extension("hydramsgdb.bak");
        fs::rename(&path, &backup).unwrap();
        assert!(!path.exists());
        let loaded = MessageStore::load(&path, password).unwrap();
        assert_eq!(loaded.conversations()[0].id, conversation_id);
        assert!(path.exists());
        fs::remove_file(path).ok();
        fs::remove_file(backup).ok();
    }

    #[test]
    fn pending_commits_replay_cursors_and_policy_persist() {
        let path = temp_store_path("message-commit-replay");
        let password = b"commit replay password";
        let mut store = MessageStore::create(&path, password).unwrap();
        let conversation_id = store
            .create_conversation(ConversationKind::Direct, 0)
            .unwrap();
        store.set_skipped_key_policy(SkippedKeyPersistencePolicy::PersistEncrypted);
        store
            .store_pending_commit(PendingCommitRecord {
                conversation_id,
                epoch: 1,
                state_version: 2,
                parent_commit_hash: [0xa5; 64],
                commit_bytes: b"pending commit bytes".to_vec(),
            })
            .unwrap();
        store
            .record_replay_cursor(ReplayCursorRecord {
                conversation_id,
                stream_id: [0x77; 32],
                highest_seen: Some(42),
                window_words: vec![1, 2, 3, 4],
            })
            .unwrap();
        store.save(password).unwrap();

        let loaded = MessageStore::load(&path, password).unwrap();
        assert_eq!(
            loaded.skipped_key_policy(),
            SkippedKeyPersistencePolicy::PersistEncrypted
        );
        assert_eq!(
            loaded.pending_commits()[0].commit_bytes,
            b"pending commit bytes"
        );
        assert_eq!(loaded.replay_cursors()[0].highest_seen, Some(42));
        assert_eq!(loaded.replay_cursors()[0].window_words, vec![1, 2, 3, 4]);
        fs::remove_file(path).ok();
    }

    #[test]
    fn wrong_password_corruption_and_unsupported_version_reject() {
        let path = temp_store_path("message-reject");
        let password = b"message database password";
        MessageStore::create(&path, password).unwrap();
        match MessageStore::load(&path, b"wrong password") {
            Ok(_) => panic!("wrong password loaded message database"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::Authentication),
        }

        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, &bytes).unwrap();
        match MessageStore::load(&path, password) {
            Ok(_) => panic!("corrupted message database loaded"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::Authentication),
        }

        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        bytes[8] = STORE_VERSION + 1;
        fs::write(&path, bytes).unwrap();
        match MessageStore::load(&path, password) {
            Ok(_) => panic!("unsupported message database version loaded"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::InvalidInput),
        }
        fs::remove_file(path).ok();
    }
}
