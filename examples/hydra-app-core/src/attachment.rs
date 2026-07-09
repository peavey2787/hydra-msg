use std::collections::BTreeMap;

use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use zeroize::Zeroizing;

use crate::{
    message_store::ConversationKind, random::random_array, transport::AttachmentHandle, AppError,
    AppResult,
};

const ATTACHMENT_KEY_LABEL: &[u8] = b"HYDRA-MSG/app/attachment/key-commitment";
const ATTACHMENT_NONCE_LABEL: &[u8] = b"HYDRA-MSG/app/attachment/chunk-nonce";
const ATTACHMENT_AAD_LABEL: &[u8] = b"HYDRA-MSG/app/attachment/chunk-aad";

pub const DEFAULT_ATTACHMENT_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_ATTACHMENT_CHUNK_SIZE: usize = 1024 * 1024;
pub const MAX_ATTACHMENT_PLAINTEXT_SIZE: usize = 512 * 1024 * 1024;
pub const MAX_ATTACHMENT_CHUNKS: u32 = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AttachmentObjectId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentEncryptionOptions {
    pub chunk_size: usize,
    pub max_plaintext_size: usize,
}

impl Default for AttachmentEncryptionOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_ATTACHMENT_CHUNK_SIZE,
            max_plaintext_size: MAX_ATTACHMENT_PLAINTEXT_SIZE,
        }
    }
}

/// Local file encryption key for one detached attachment.
///
/// The key is intentionally non-cloneable and zeroizes on drop through
/// `SecretBytes`. Relays and detached object stores receive only the handle and
/// encrypted chunks, not this key.
pub struct AttachmentKey {
    key: SecretBytes<32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAttachmentManifest {
    pub object_id: AttachmentObjectId,
    pub plaintext_size: u64,
    pub encrypted_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub content_hash: [u8; 32],
    pub key_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAttachmentChunk {
    pub index: u32,
    pub offset: u64,
    pub plaintext_size: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub struct EncryptedAttachment {
    key: AttachmentKey,
    manifest: EncryptedAttachmentManifest,
    chunks: Vec<EncryptedAttachmentChunk>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedAttachmentObject {
    pub manifest: EncryptedAttachmentManifest,
    pub chunks: Vec<EncryptedAttachmentChunk>,
}

#[derive(Default)]
pub struct InMemoryAttachmentStore {
    objects: BTreeMap<AttachmentObjectId, DetachedAttachmentObject>,
}

pub struct AttachmentPolicy;

impl AttachmentKey {
    pub fn generate() -> AppResult<Self> {
        Ok(Self {
            key: SecretBytes::from_array(random_array()?),
        })
    }

    #[must_use]
    pub fn key_commitment(&self) -> [u8; 32] {
        key_commitment(&self.key)
    }
}

impl AttachmentEncryptionOptions {
    pub fn validate(self) -> AppResult<()> {
        if self.chunk_size == 0 {
            return Err(AppError::InvalidInput(
                "attachment chunk size must be nonzero",
            ));
        }
        if self.chunk_size > MAX_ATTACHMENT_CHUNK_SIZE {
            return Err(AppError::InvalidInput(
                "attachment chunk size exceeds maximum",
            ));
        }
        if self.max_plaintext_size == 0 {
            return Err(AppError::InvalidInput(
                "attachment max plaintext size must be nonzero",
            ));
        }
        if self.max_plaintext_size > MAX_ATTACHMENT_PLAINTEXT_SIZE {
            return Err(AppError::InvalidInput(
                "attachment max plaintext size exceeds app maximum",
            ));
        }
        Ok(())
    }
}

impl EncryptedAttachmentManifest {
    #[must_use]
    pub fn handle(&self) -> AttachmentHandle {
        AttachmentHandle {
            object_id: self.object_id.0,
            encrypted_size: self.encrypted_size,
            content_hash: self.content_hash,
            key_commitment: self.key_commitment,
        }
    }
}

impl EncryptedAttachment {
    #[must_use]
    pub const fn key(&self) -> &AttachmentKey {
        &self.key
    }

    #[must_use]
    pub const fn manifest(&self) -> &EncryptedAttachmentManifest {
        &self.manifest
    }

    #[must_use]
    pub fn chunks(&self) -> &[EncryptedAttachmentChunk] {
        &self.chunks
    }

    #[must_use]
    pub fn handle(&self) -> AttachmentHandle {
        self.manifest.handle()
    }

    #[must_use]
    pub fn detached_object(&self) -> DetachedAttachmentObject {
        DetachedAttachmentObject {
            manifest: self.manifest.clone(),
            chunks: self.chunks.clone(),
        }
    }
}

impl InMemoryAttachmentStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_encrypted(
        &mut self,
        attachment: &EncryptedAttachment,
    ) -> AppResult<AttachmentHandle> {
        self.put_object(attachment.detached_object())
    }

    pub fn put_object(&mut self, object: DetachedAttachmentObject) -> AppResult<AttachmentHandle> {
        validate_object(&object)?;
        let object_id = object.manifest.object_id;
        let handle = object.manifest.handle();
        if let Some(existing) = self.objects.get(&object_id) {
            if existing != &object {
                return Err(AppError::InvalidState("attachment object ID collision"));
            }
            return Ok(handle);
        }
        self.objects.insert(object_id, object);
        Ok(handle)
    }

    #[must_use]
    pub fn contains(&self, object_id: AttachmentObjectId) -> bool {
        self.objects.contains_key(&object_id)
    }

    pub fn get(&self, object_id: AttachmentObjectId) -> AppResult<&DetachedAttachmentObject> {
        self.objects
            .get(&object_id)
            .ok_or(AppError::InvalidInput("attachment object is absent"))
    }

    pub fn open(
        &self,
        key: &AttachmentKey,
        handle: &AttachmentHandle,
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        let object = self.get(AttachmentObjectId(handle.object_id))?;
        if object.manifest.handle() != handle.clone() {
            return Err(AppError::InvalidInput(
                "attachment handle does not match stored object",
            ));
        }
        decrypt_attachment(key, &object.manifest, &object.chunks)
    }
}

impl AttachmentPolicy {
    pub fn require_allowed_for_conversation(
        kind: ConversationKind,
        attachment_count: usize,
    ) -> AppResult<()> {
        if attachment_count == 0 {
            return Ok(());
        }
        match kind {
            ConversationKind::GroupLite => Err(AppError::InvalidInput(
                "Lite conversations reject attachments; use Standard or Full envelopes",
            )),
            ConversationKind::Direct
            | ConversationKind::GroupInteractive
            | ConversationKind::GroupBroadcast => Ok(()),
        }
    }
}

pub fn encrypt_attachment(plaintext: &[u8]) -> AppResult<EncryptedAttachment> {
    encrypt_attachment_with_options(plaintext, AttachmentEncryptionOptions::default())
}

pub fn encrypt_attachment_with_options(
    plaintext: &[u8],
    options: AttachmentEncryptionOptions,
) -> AppResult<EncryptedAttachment> {
    encrypt_attachment_with_key(plaintext, AttachmentKey::generate()?, options)
}

pub fn encrypt_attachment_with_key(
    plaintext: &[u8],
    key: AttachmentKey,
    options: AttachmentEncryptionOptions,
) -> AppResult<EncryptedAttachment> {
    options.validate()?;
    if plaintext.is_empty() {
        return Err(AppError::InvalidInput(
            "attachment plaintext must be nonempty",
        ));
    }
    if plaintext.len() > options.max_plaintext_size {
        return Err(AppError::InvalidInput(
            "attachment plaintext exceeds configured limit",
        ));
    }
    let plaintext_size = u64::try_from(plaintext.len())
        .map_err(|_| AppError::InvalidInput("attachment plaintext length exceeds u64"))?;
    let chunk_size_u32 = u32::try_from(options.chunk_size)
        .map_err(|_| AppError::InvalidInput("attachment chunk size exceeds u32"))?;
    let chunk_count = expected_chunk_count(plaintext_size, chunk_size_u32)?;
    if chunk_count > MAX_ATTACHMENT_CHUNKS {
        return Err(AppError::InvalidInput(
            "attachment chunk count exceeds maximum",
        ));
    }

    let object_id = AttachmentObjectId(random_array()?);
    let content_hash = RustCryptoBackend::sha3_256(plaintext);
    let key_commitment = key.key_commitment();
    let aad_context = AttachmentAadContext {
        object_id,
        plaintext_size,
        chunk_size: chunk_size_u32,
        chunk_count,
        content_hash,
        key_commitment,
    };
    let mut chunks = Vec::with_capacity(chunk_count as usize);
    let mut encrypted_size = 0_u64;

    for (index, chunk) in plaintext.chunks(options.chunk_size).enumerate() {
        let index = u32::try_from(index)
            .map_err(|_| AppError::InvalidInput("attachment chunk index exceeds u32"))?;
        let offset = u64::from(index)
            .checked_mul(u64::from(chunk_size_u32))
            .ok_or(AppError::InvalidInput("attachment chunk offset overflow"))?;
        let chunk_plaintext_size = u32::try_from(chunk.len())
            .map_err(|_| AppError::InvalidInput("attachment chunk length exceeds u32"))?;
        let nonce = chunk_nonce(object_id, index);
        let aad = chunk_aad(&aad_context, index, offset, chunk_plaintext_size);
        let ciphertext = RustCryptoBackend::aead_seal(&key.key, &nonce, &aad, chunk)?;
        encrypted_size =
            encrypted_size
                .checked_add(u64::try_from(ciphertext.len()).map_err(|_| {
                    AppError::InvalidInput("attachment ciphertext length exceeds u64")
                })?)
                .ok_or(AppError::InvalidInput("attachment encrypted size overflow"))?;
        chunks.push(EncryptedAttachmentChunk {
            index,
            offset,
            plaintext_size: chunk_plaintext_size,
            nonce,
            ciphertext,
        });
    }

    let manifest = EncryptedAttachmentManifest {
        object_id,
        plaintext_size,
        encrypted_size,
        chunk_size: chunk_size_u32,
        chunk_count,
        content_hash,
        key_commitment,
    };
    validate_chunks(&manifest, &chunks)?;
    Ok(EncryptedAttachment {
        key,
        manifest,
        chunks,
    })
}

pub fn decrypt_attachment(
    key: &AttachmentKey,
    manifest: &EncryptedAttachmentManifest,
    chunks: &[EncryptedAttachmentChunk],
) -> AppResult<Zeroizing<Vec<u8>>> {
    validate_manifest(manifest)?;
    validate_chunks(manifest, chunks)?;
    if key.key_commitment() != manifest.key_commitment {
        return Err(AppError::Crypto(
            hydra_crypto::CryptoError::AuthenticationFailed,
        ));
    }
    let aad_context = AttachmentAadContext {
        object_id: manifest.object_id,
        plaintext_size: manifest.plaintext_size,
        chunk_size: manifest.chunk_size,
        chunk_count: manifest.chunk_count,
        content_hash: manifest.content_hash,
        key_commitment: manifest.key_commitment,
    };
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        usize::try_from(manifest.plaintext_size)
            .map_err(|_| AppError::InvalidInput("attachment plaintext size exceeds usize"))?,
    ));
    for chunk in chunks {
        let aad = chunk_aad(
            &aad_context,
            chunk.index,
            chunk.offset,
            chunk.plaintext_size,
        );
        let opened = RustCryptoBackend::aead_open(&key.key, &chunk.nonce, &aad, &chunk.ciphertext)?;
        if opened.len() != chunk.plaintext_size as usize {
            return Err(AppError::Crypto(
                hydra_crypto::CryptoError::AuthenticationFailed,
            ));
        }
        plaintext.extend_from_slice(&opened);
    }
    if plaintext.len()
        != usize::try_from(manifest.plaintext_size)
            .map_err(|_| AppError::InvalidInput("attachment plaintext size exceeds usize"))?
    {
        return Err(AppError::Crypto(
            hydra_crypto::CryptoError::AuthenticationFailed,
        ));
    }
    let actual_hash = RustCryptoBackend::sha3_256(plaintext.as_slice());
    if actual_hash != manifest.content_hash {
        return Err(AppError::Crypto(
            hydra_crypto::CryptoError::AuthenticationFailed,
        ));
    }
    Ok(plaintext)
}

#[derive(Clone, Copy)]
struct AttachmentAadContext {
    object_id: AttachmentObjectId,
    plaintext_size: u64,
    chunk_size: u32,
    chunk_count: u32,
    content_hash: [u8; 32],
    key_commitment: [u8; 32],
}

fn validate_object(object: &DetachedAttachmentObject) -> AppResult<()> {
    validate_manifest(&object.manifest)?;
    validate_chunks(&object.manifest, &object.chunks)
}

fn validate_manifest(manifest: &EncryptedAttachmentManifest) -> AppResult<()> {
    if manifest.plaintext_size == 0 {
        return Err(AppError::InvalidInput(
            "attachment plaintext size must be nonzero",
        ));
    }
    if manifest.plaintext_size
        > u64::try_from(MAX_ATTACHMENT_PLAINTEXT_SIZE)
            .map_err(|_| AppError::InvalidInput("attachment max size exceeds u64"))?
    {
        return Err(AppError::InvalidInput(
            "attachment plaintext size exceeds app maximum",
        ));
    }
    if manifest.chunk_size == 0 {
        return Err(AppError::InvalidInput(
            "attachment manifest chunk size must be nonzero",
        ));
    }
    if usize::try_from(manifest.chunk_size)
        .map_err(|_| AppError::InvalidInput("attachment chunk size exceeds usize"))?
        > MAX_ATTACHMENT_CHUNK_SIZE
    {
        return Err(AppError::InvalidInput(
            "attachment manifest chunk size exceeds maximum",
        ));
    }
    let expected = expected_chunk_count(manifest.plaintext_size, manifest.chunk_size)?;
    if manifest.chunk_count != expected {
        return Err(AppError::InvalidInput(
            "attachment manifest chunk count is inconsistent",
        ));
    }
    if manifest.chunk_count == 0 || manifest.chunk_count > MAX_ATTACHMENT_CHUNKS {
        return Err(AppError::InvalidInput(
            "attachment manifest chunk count exceeds maximum",
        ));
    }
    Ok(())
}

fn validate_chunks(
    manifest: &EncryptedAttachmentManifest,
    chunks: &[EncryptedAttachmentChunk],
) -> AppResult<()> {
    if chunks.len() != manifest.chunk_count as usize {
        return Err(AppError::InvalidInput("attachment chunk count mismatch"));
    }
    let mut encrypted_size = 0_u64;
    for (position, chunk) in chunks.iter().enumerate() {
        let expected_index = u32::try_from(position)
            .map_err(|_| AppError::InvalidInput("attachment chunk index exceeds u32"))?;
        if chunk.index != expected_index {
            return Err(AppError::InvalidInput(
                "attachment chunks must be ordered and contiguous",
            ));
        }
        let expected_offset = u64::from(chunk.index)
            .checked_mul(u64::from(manifest.chunk_size))
            .ok_or(AppError::InvalidInput("attachment chunk offset overflow"))?;
        if chunk.offset != expected_offset {
            return Err(AppError::InvalidInput("attachment chunk offset mismatch"));
        }
        let remaining =
            manifest
                .plaintext_size
                .checked_sub(chunk.offset)
                .ok_or(AppError::InvalidInput(
                    "attachment chunk offset exceeds plaintext",
                ))?;
        let max_chunk = remaining.min(u64::from(manifest.chunk_size));
        if u64::from(chunk.plaintext_size) != max_chunk {
            return Err(AppError::InvalidInput(
                "attachment chunk plaintext size mismatch",
            ));
        }
        if chunk.nonce != chunk_nonce(manifest.object_id, chunk.index) {
            return Err(AppError::InvalidInput("attachment chunk nonce mismatch"));
        }
        if chunk.ciphertext.len() < 16 {
            return Err(AppError::InvalidInput(
                "attachment chunk ciphertext too short",
            ));
        }
        encrypted_size = encrypted_size
            .checked_add(u64::try_from(chunk.ciphertext.len()).map_err(|_| {
                AppError::InvalidInput("attachment chunk ciphertext length exceeds u64")
            })?)
            .ok_or(AppError::InvalidInput("attachment encrypted size overflow"))?;
    }
    if encrypted_size != manifest.encrypted_size {
        return Err(AppError::InvalidInput("attachment encrypted size mismatch"));
    }
    Ok(())
}

fn expected_chunk_count(plaintext_size: u64, chunk_size: u32) -> AppResult<u32> {
    if chunk_size == 0 {
        return Err(AppError::InvalidInput(
            "attachment chunk size must be nonzero",
        ));
    }
    let chunk_size = u64::from(chunk_size);
    let count = plaintext_size
        .checked_add(chunk_size - 1)
        .ok_or(AppError::InvalidInput("attachment chunk count overflow"))?
        / chunk_size;
    u32::try_from(count).map_err(|_| AppError::InvalidInput("attachment chunk count exceeds u32"))
}

fn key_commitment(key: &SecretBytes<32>) -> [u8; 32] {
    let mut input = Zeroizing::new(Vec::with_capacity(ATTACHMENT_KEY_LABEL.len() + 32));
    input.extend_from_slice(ATTACHMENT_KEY_LABEL);
    input.extend_from_slice(key.expose_secret());
    RustCryptoBackend::sha3_256(&input)
}

fn chunk_nonce(object_id: AttachmentObjectId, index: u32) -> [u8; 12] {
    let mut input = Vec::with_capacity(ATTACHMENT_NONCE_LABEL.len() + 32 + 4);
    input.extend_from_slice(ATTACHMENT_NONCE_LABEL);
    input.extend_from_slice(&object_id.0);
    input.extend_from_slice(&index.to_be_bytes());
    let hash = RustCryptoBackend::sha3_256(&input);
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&hash[..12]);
    nonce
}

fn chunk_aad(
    context: &AttachmentAadContext,
    index: u32,
    offset: u64,
    plaintext_size: u32,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(ATTACHMENT_AAD_LABEL.len() + 32 + 8 + 4 + 4 + 32 + 32 + 4 + 8 + 4);
    out.extend_from_slice(ATTACHMENT_AAD_LABEL);
    out.extend_from_slice(&context.object_id.0);
    out.extend_from_slice(&context.plaintext_size.to_be_bytes());
    out.extend_from_slice(&context.chunk_size.to_be_bytes());
    out.extend_from_slice(&context.chunk_count.to_be_bytes());
    out.extend_from_slice(&context.content_hash);
    out.extend_from_slice(&context.key_commitment);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&plaintext_size.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppErrorClass;

    #[test]
    fn encrypted_attachment_round_trips_with_chunking() {
        let plaintext = b"abcdefghijklmnopqrstuvwxyz0123456789".repeat(4);
        let encrypted = encrypt_attachment_with_options(
            &plaintext,
            AttachmentEncryptionOptions {
                chunk_size: 17,
                max_plaintext_size: 1024,
            },
        )
        .unwrap();
        assert!(encrypted.chunks().len() > 1);
        assert_eq!(
            encrypted.manifest().content_hash,
            RustCryptoBackend::sha3_256(&plaintext)
        );

        let opened =
            decrypt_attachment(encrypted.key(), encrypted.manifest(), encrypted.chunks()).unwrap();
        assert_eq!(&opened[..], plaintext.as_slice());
    }

    #[test]
    fn detached_store_keeps_ciphertext_and_opens_by_handle() {
        let plaintext = b"detached attachment plaintext".repeat(8);
        let encrypted = encrypt_attachment_with_options(
            &plaintext,
            AttachmentEncryptionOptions {
                chunk_size: 23,
                max_plaintext_size: 4096,
            },
        )
        .unwrap();
        let handle = encrypted.handle();
        let mut store = InMemoryAttachmentStore::new();
        store.put_encrypted(&encrypted).unwrap();
        assert!(store.contains(AttachmentObjectId(handle.object_id)));

        let object = store.get(AttachmentObjectId(handle.object_id)).unwrap();
        let flattened = object
            .chunks
            .iter()
            .flat_map(|chunk| chunk.ciphertext.iter().copied())
            .collect::<Vec<_>>();
        assert!(!flattened
            .windows(plaintext.len())
            .any(|window| window == plaintext.as_slice()));

        let opened = store.open(encrypted.key(), &handle).unwrap();
        assert_eq!(&opened[..], plaintext.as_slice());
    }

    #[test]
    fn wrong_attachment_key_is_rejected() {
        let encrypted = encrypt_attachment(b"secret file bytes").unwrap();
        let wrong_key = AttachmentKey::generate().unwrap();
        assert_eq!(
            decrypt_attachment(&wrong_key, encrypted.manifest(), encrypted.chunks())
                .unwrap_err()
                .class(),
            AppErrorClass::Authentication
        );
    }

    #[test]
    fn wrong_attachment_hash_is_rejected() {
        let encrypted = encrypt_attachment(b"secret file bytes").unwrap();
        let mut manifest = encrypted.manifest().clone();
        manifest.content_hash[0] ^= 0x80;
        assert_eq!(
            decrypt_attachment(encrypted.key(), &manifest, encrypted.chunks())
                .unwrap_err()
                .class(),
            AppErrorClass::Authentication
        );
    }

    #[test]
    fn size_limits_are_enforced() {
        let error = match encrypt_attachment_with_options(
            b"too large",
            AttachmentEncryptionOptions {
                chunk_size: 4,
                max_plaintext_size: 3,
            },
        ) {
            Ok(_) => panic!("oversized attachment unexpectedly encrypted"),
            Err(error) => error,
        };
        assert_eq!(error.class(), AppErrorClass::InvalidInput);
    }

    #[test]
    fn lite_conversations_reject_attachment_handles() {
        assert_eq!(
            AttachmentPolicy::require_allowed_for_conversation(ConversationKind::GroupLite, 1)
                .unwrap_err()
                .class(),
            AppErrorClass::InvalidInput
        );
        AttachmentPolicy::require_allowed_for_conversation(ConversationKind::GroupLite, 0).unwrap();
        AttachmentPolicy::require_allowed_for_conversation(ConversationKind::Direct, 1).unwrap();
        AttachmentPolicy::require_allowed_for_conversation(ConversationKind::GroupInteractive, 1)
            .unwrap();
        AttachmentPolicy::require_allowed_for_conversation(ConversationKind::GroupBroadcast, 1)
            .unwrap();
    }
}
