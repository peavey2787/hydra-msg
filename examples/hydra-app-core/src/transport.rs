use std::collections::{BTreeMap, BTreeSet};

use hydra_core::{FULL_ENVELOPE_SIZE, LITE_ENVELOPE_SIZE, STANDARD_ENVELOPE_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

use crate::{AppError, AppResult};

const MAX_TRANSPORT_ATTACHMENTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MailboxId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportMessageId(pub [u8; 32]);

/// Detached encrypted attachment object reference.
///
/// The transport layer only accepts object handles and commitments. It has no
/// field for plaintext attachment bytes, so servers/relays can queue messages
/// without receiving attachment content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentHandle {
    pub object_id: [u8; 32],
    pub encrypted_size: u64,
    pub content_hash: [u8; 32],
    pub key_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportUploadRequest {
    pub sender: MailboxId,
    pub recipient: MailboxId,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub envelope: Vec<u8>,
    pub attachments: Vec<AttachmentHandle>,
}

impl TransportUploadRequest {
    pub fn new(
        sender: MailboxId,
        recipient: MailboxId,
        created_at_ms: u64,
        expires_at_ms: Option<u64>,
        envelope: Vec<u8>,
    ) -> Self {
        Self {
            sender,
            recipient,
            created_at_ms,
            expires_at_ms,
            envelope,
            attachments: Vec::new(),
        }
    }

    pub fn with_attachments(mut self, attachments: Vec<AttachmentHandle>) -> Self {
        self.attachments = attachments;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedTransportEnvelope {
    pub message_id: TransportMessageId,
    pub sender: MailboxId,
    pub recipient: MailboxId,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub envelope: Vec<u8>,
    pub attachments: Vec<AttachmentHandle>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadStatus {
    Stored,
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadReceipt {
    pub message_id: TransportMessageId,
    pub status: UploadStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailboxStats {
    pub queued: usize,
    pub expired: usize,
}

pub trait TransportRateLimiter {
    fn check_upload(&mut self, request: &TransportUploadRequest) -> AppResult<()>;
}

#[derive(Default)]
pub struct AllowAllRateLimiter;

impl TransportRateLimiter for AllowAllRateLimiter {
    fn check_upload(&mut self, _request: &TransportUploadRequest) -> AppResult<()> {
        Ok(())
    }
}

pub trait TransportApi {
    fn upload_envelope(&mut self, request: TransportUploadRequest) -> AppResult<UploadReceipt>;

    fn download_envelopes(
        &mut self,
        mailbox: MailboxId,
        now_ms: u64,
        limit: usize,
    ) -> AppResult<Vec<QueuedTransportEnvelope>>;

    fn acknowledge(
        &mut self,
        mailbox: MailboxId,
        message_ids: &[TransportMessageId],
    ) -> AppResult<()>;

    fn purge_expired(&mut self, now_ms: u64) -> usize;
}

struct StoredTransportItem {
    request_commitment: [u8; 32],
    envelope: Option<QueuedTransportEnvelope>,
}

/// In-memory relay model for app integration and tests.
///
/// This relay queues opaque HYDRA envelopes by recipient mailbox. It never asks
/// for plaintext message content and attachment uploads are represented only by
/// detached object handles. Production deployments can implement `TransportApi`
/// against HTTP, QUIC, WebSocket, or a store-and-forward service while retaining
/// these app-facing semantics.
pub struct InMemoryTransport {
    rate_limiter: Box<dyn TransportRateLimiter>,
    items: BTreeMap<TransportMessageId, StoredTransportItem>,
    queues: BTreeMap<MailboxId, Vec<TransportMessageId>>,
}

impl Default for InMemoryTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::with_rate_limiter(Box::<AllowAllRateLimiter>::default())
    }

    #[must_use]
    pub fn with_rate_limiter(rate_limiter: Box<dyn TransportRateLimiter>) -> Self {
        Self {
            rate_limiter,
            items: BTreeMap::new(),
            queues: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn mailbox_stats(&self, mailbox: MailboxId, now_ms: u64) -> MailboxStats {
        let Some(queue) = self.queues.get(&mailbox) else {
            return MailboxStats {
                queued: 0,
                expired: 0,
            };
        };
        let mut queued = 0;
        let mut expired = 0;
        for id in queue {
            if let Some(envelope) = self.items.get(id).and_then(|item| item.envelope.as_ref()) {
                if is_expired(envelope.expires_at_ms, now_ms) {
                    expired += 1;
                } else {
                    queued += 1;
                }
            }
        }
        MailboxStats { queued, expired }
    }

    #[must_use]
    pub fn contains_message(&self, message_id: TransportMessageId) -> bool {
        self.items.contains_key(&message_id)
    }
}

impl TransportApi for InMemoryTransport {
    fn upload_envelope(&mut self, request: TransportUploadRequest) -> AppResult<UploadReceipt> {
        validate_upload_request(&request)?;
        self.rate_limiter.check_upload(&request)?;

        let request_commitment = request_commitment(&request)?;
        let message_id = TransportMessageId(request_commitment);
        if let Some(existing) = self.items.get(&message_id) {
            if existing.request_commitment != request_commitment {
                return Err(AppError::InvalidState("transport message ID collision"));
            }
            return Ok(UploadReceipt {
                message_id,
                status: UploadStatus::Duplicate,
            });
        }

        let envelope = QueuedTransportEnvelope {
            message_id,
            sender: request.sender,
            recipient: request.recipient,
            created_at_ms: request.created_at_ms,
            expires_at_ms: request.expires_at_ms,
            envelope: request.envelope,
            attachments: request.attachments,
        };
        self.queues
            .entry(envelope.recipient)
            .or_default()
            .push(message_id);
        self.items.insert(
            message_id,
            StoredTransportItem {
                request_commitment,
                envelope: Some(envelope),
            },
        );
        Ok(UploadReceipt {
            message_id,
            status: UploadStatus::Stored,
        })
    }

    fn download_envelopes(
        &mut self,
        mailbox: MailboxId,
        now_ms: u64,
        limit: usize,
    ) -> AppResult<Vec<QueuedTransportEnvelope>> {
        if limit == 0 {
            return Err(AppError::InvalidInput("download limit must be nonzero"));
        }
        self.remove_expired_from_mailbox(mailbox, now_ms);
        let Some(queue) = self.queues.get(&mailbox) else {
            return Ok(Vec::new());
        };
        Ok(queue
            .iter()
            .filter_map(|id| self.items.get(id).and_then(|item| item.envelope.clone()))
            .take(limit)
            .collect())
    }

    fn acknowledge(
        &mut self,
        mailbox: MailboxId,
        message_ids: &[TransportMessageId],
    ) -> AppResult<()> {
        let requested = message_ids.iter().copied().collect::<BTreeSet<_>>();
        if let Some(queue) = self.queues.get_mut(&mailbox) {
            queue.retain(|id| !requested.contains(id));
        }
        for id in requested {
            if let Some(item) = self.items.get_mut(&id) {
                if item
                    .envelope
                    .as_ref()
                    .is_some_and(|envelope| envelope.recipient == mailbox)
                {
                    // Keep the commitment tombstone for idempotent resend, but
                    // drop the queued ciphertext after acknowledgement.
                    item.envelope = None;
                }
            }
        }
        Ok(())
    }

    fn purge_expired(&mut self, now_ms: u64) -> usize {
        let mailboxes = self.queues.keys().copied().collect::<Vec<_>>();
        let mut removed = 0;
        for mailbox in mailboxes {
            removed += self.remove_expired_from_mailbox(mailbox, now_ms);
        }
        removed
    }
}

impl InMemoryTransport {
    fn remove_expired_from_mailbox(&mut self, mailbox: MailboxId, now_ms: u64) -> usize {
        let Some(queue) = self.queues.get_mut(&mailbox) else {
            return 0;
        };
        let mut removed = 0;
        queue.retain(|id| {
            let expired = self
                .items
                .get(id)
                .and_then(|item| item.envelope.as_ref())
                .is_some_and(|envelope| is_expired(envelope.expires_at_ms, now_ms));
            if expired {
                if let Some(item) = self.items.get_mut(id) {
                    item.envelope = None;
                }
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }
}

fn validate_upload_request(request: &TransportUploadRequest) -> AppResult<()> {
    if request.sender == request.recipient {
        return Err(AppError::InvalidInput(
            "transport sender and recipient must differ",
        ));
    }
    if !matches!(
        request.envelope.len(),
        LITE_ENVELOPE_SIZE | STANDARD_ENVELOPE_SIZE | FULL_ENVELOPE_SIZE
    ) {
        return Err(AppError::InvalidInput(
            "transport upload must be an exact HYDRA envelope size",
        ));
    }
    if let Some(expires_at_ms) = request.expires_at_ms {
        if expires_at_ms <= request.created_at_ms {
            return Err(AppError::InvalidInput(
                "transport expiration must be after creation time",
            ));
        }
    }
    if request.attachments.len() > MAX_TRANSPORT_ATTACHMENTS {
        return Err(AppError::InvalidInput(
            "transport attachment handle count exceeds limit",
        ));
    }
    for attachment in &request.attachments {
        if attachment.encrypted_size == 0 {
            return Err(AppError::InvalidInput(
                "transport attachment size must be nonzero",
            ));
        }
    }
    Ok(())
}

fn request_commitment(request: &TransportUploadRequest) -> AppResult<[u8; 32]> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/app/transport/upload");
    input.extend_from_slice(&request.sender.0);
    input.extend_from_slice(&request.recipient.0);
    input.extend_from_slice(&request.created_at_ms.to_be_bytes());
    match request.expires_at_ms {
        Some(value) => {
            input.push(1);
            input.extend_from_slice(&value.to_be_bytes());
        }
        None => input.push(0),
    }
    put_bytes(&mut input, &request.envelope)?;
    put_u32(
        &mut input,
        checked_u32_len(request.attachments.len(), "attachment count")?,
    );
    for attachment in &request.attachments {
        input.extend_from_slice(&attachment.object_id);
        input.extend_from_slice(&attachment.encrypted_size.to_be_bytes());
        input.extend_from_slice(&attachment.content_hash);
        input.extend_from_slice(&attachment.key_commitment);
    }
    Ok(RustCryptoBackend::sha3_256(&input))
}

fn is_expired(expires_at_ms: Option<u64>, now_ms: u64) -> bool {
    expires_at_ms.is_some_and(|expiry| now_ms >= expiry)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> AppResult<()> {
    put_u32(out, checked_u32_len(bytes.len(), "transport byte string")?);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn checked_u32_len(len: usize, label: &'static str) -> AppResult<u32> {
    u32::try_from(len).map_err(|_| AppError::InvalidInput(label))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DenyAllLimiter;

    impl TransportRateLimiter for DenyAllLimiter {
        fn check_upload(&mut self, _request: &TransportUploadRequest) -> AppResult<()> {
            Err(AppError::InvalidState("rate limit exceeded"))
        }
    }

    fn mailbox(byte: u8) -> MailboxId {
        MailboxId([byte; 32])
    }

    fn envelope(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    fn request() -> TransportUploadRequest {
        TransportUploadRequest::new(
            mailbox(1),
            mailbox(2),
            1_000,
            Some(10_000),
            envelope(0xa5, LITE_ENVELOPE_SIZE),
        )
    }

    #[test]
    fn upload_download_ack_and_offline_delivery_work() {
        let mut relay = InMemoryTransport::new();
        let receipt = relay.upload_envelope(request()).unwrap();
        assert_eq!(receipt.status, UploadStatus::Stored);
        assert_eq!(relay.mailbox_stats(mailbox(2), 2_000).queued, 1);

        let downloaded = relay.download_envelopes(mailbox(2), 2_000, 8).unwrap();
        assert_eq!(downloaded.len(), 1);
        assert_eq!(downloaded[0].message_id, receipt.message_id);
        assert_eq!(downloaded[0].envelope, envelope(0xa5, LITE_ENVELOPE_SIZE));

        relay
            .acknowledge(mailbox(2), &[receipt.message_id])
            .unwrap();
        assert!(relay
            .download_envelopes(mailbox(2), 2_000, 8)
            .unwrap()
            .is_empty());
        assert!(relay.contains_message(receipt.message_id));
    }

    #[test]
    fn idempotent_resend_does_not_duplicate_queue_entries() {
        let mut relay = InMemoryTransport::new();
        let first = relay.upload_envelope(request()).unwrap();
        let second = relay.upload_envelope(request()).unwrap();
        assert_eq!(second.message_id, first.message_id);
        assert_eq!(second.status, UploadStatus::Duplicate);
        assert_eq!(
            relay
                .download_envelopes(mailbox(2), 2_000, 8)
                .unwrap()
                .len(),
            1
        );

        relay.acknowledge(mailbox(2), &[first.message_id]).unwrap();
        let after_ack = relay.upload_envelope(request()).unwrap();
        assert_eq!(after_ack.status, UploadStatus::Duplicate);
        assert!(relay
            .download_envelopes(mailbox(2), 2_000, 8)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn expiration_hides_and_purges_messages() {
        let mut relay = InMemoryTransport::new();
        let receipt = relay.upload_envelope(request()).unwrap();
        assert_eq!(relay.mailbox_stats(mailbox(2), 9_999).queued, 1);
        assert_eq!(
            relay.download_envelopes(mailbox(2), 10_000, 8).unwrap(),
            Vec::new()
        );
        assert!(relay.contains_message(receipt.message_id));
    }

    #[test]
    fn rate_limit_hook_can_reject_uploads() {
        let mut relay = InMemoryTransport::with_rate_limiter(Box::new(DenyAllLimiter));
        let error = relay.upload_envelope(request()).unwrap_err();
        assert_eq!(error.class(), crate::AppErrorClass::InvalidState);
        assert!(relay
            .download_envelopes(mailbox(2), 2_000, 8)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn attachment_handles_are_detached_metadata_only() {
        let attachment = AttachmentHandle {
            object_id: [0x11; 32],
            encrypted_size: 4096,
            content_hash: [0x22; 32],
            key_commitment: [0x33; 32],
        };
        let mut relay = InMemoryTransport::new();
        relay
            .upload_envelope(request().with_attachments(vec![attachment.clone()]))
            .unwrap();
        let downloaded = relay.download_envelopes(mailbox(2), 2_000, 1).unwrap();
        assert_eq!(downloaded[0].attachments, vec![attachment]);
    }

    #[test]
    fn upload_validation_rejects_non_envelope_plaintext_shape() {
        let mut relay = InMemoryTransport::new();
        let mut bad = request();
        bad.envelope = b"plaintext pretending to be an envelope".to_vec();
        assert_eq!(
            relay.upload_envelope(bad).unwrap_err().class(),
            crate::AppErrorClass::InvalidInput
        );
    }

    #[test]
    fn standard_and_full_envelopes_are_accepted() {
        let mut relay = InMemoryTransport::new();
        let standard = TransportUploadRequest::new(
            mailbox(1),
            mailbox(2),
            1,
            None,
            envelope(0x55, STANDARD_ENVELOPE_SIZE),
        );
        let full = TransportUploadRequest::new(
            mailbox(3),
            mailbox(4),
            2,
            None,
            envelope(0x66, FULL_ENVELOPE_SIZE),
        );
        assert_eq!(
            relay.upload_envelope(standard).unwrap().status,
            UploadStatus::Stored
        );
        assert_eq!(
            relay.upload_envelope(full).unwrap().status,
            UploadStatus::Stored
        );
    }
}
