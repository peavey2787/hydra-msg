//! App-facing HYDRA-MSG facade.
//!
//! This crate is intentionally thin: it gives applications stable, safe entry
//! points for identity creation, established 1:1 sessions, and Lite group
//! create/join/message flows without exposing raw private keys or epoch secrets.
//! Persistent storage, transport, recovery, and multi-device policy live here as
//! app-hardening layers over the protocol crates.

#![forbid(unsafe_code)]

mod abuse;
mod attachment;
mod backup_history;
mod chat_bootstrap;
mod chat_shell;
mod contact_trust;
mod device_link;
mod error;
mod group;
mod identity;
mod identity_store;
mod identity_vault;
mod live_state;
mod message_store;
mod random;
mod recovery;
mod secret_handling;
mod session;
mod storage_recovery;
mod transport;

pub use abuse::{CommitDeliveryAttempt, CommitDeliveryGuard, CommitDeliveryStatus};
pub use attachment::{
    decrypt_attachment, encrypt_attachment, encrypt_attachment_with_key,
    encrypt_attachment_with_options, AttachmentEncryptionOptions, AttachmentKey,
    AttachmentObjectId, AttachmentPolicy, DetachedAttachmentObject, EncryptedAttachment,
    EncryptedAttachmentChunk, EncryptedAttachmentManifest, InMemoryAttachmentStore,
    DEFAULT_ATTACHMENT_CHUNK_SIZE, MAX_ATTACHMENT_CHUNKS, MAX_ATTACHMENT_CHUNK_SIZE,
    MAX_ATTACHMENT_PLAINTEXT_SIZE,
};
pub use backup_history::{
    check_live_state_against_signed_history, export_signed_checkpoint,
    load_exported_signed_checkpoints, read_signed_checkpoint_history,
    write_signed_checkpoint_history, BackupHistoryStatus, SignedBackupCheckpoint,
    POSSIBLE_ROLLBACK_WARNING,
};
pub use chat_bootstrap::{
    current_time_ms as current_chat_bootstrap_time_ms, ChatBootstrapInvite, CHAT_BOOTSTRAP_PREFIX,
    DEFAULT_INVITE_TTL_SECONDS, MAX_INVITE_TTL_SECONDS, MAX_JOIN_CODE_LEN, MIN_INVITE_TTL_SECONDS,
};
pub use chat_shell::{
    conversation_id_hex, conversation_kind_from_label, conversation_kind_label,
    message_direction_label, now_ms as current_chat_shell_time_ms, parse_conversation_id_hex,
    ChatConversationSummary, ChatMessageSummary, ChatShell,
};
pub use contact_trust::{
    contact_hex_decode, contact_hex_encode, ContactAddOutcome, ContactKeyChangeWarning,
    ContactTrustStore, PublicContactCard, TrustedContact,
};
pub use device_link::{
    DeviceLinkApproval, DeviceLinkPolicy, DeviceLinkRequest, DeviceRegistry, DeviceRevocation,
    DeviceStatus, LinkedDeviceRecord,
};
pub use error::{AppError, AppErrorClass, AppResult};
pub use group::{
    AppGroup, AppGroupMembershipChange, AppGroupMessage, AppGroupPolicyRekey, AppGroupPolicySend,
    AppGroupRekeyNotice, AppGroupRekeyReason, AppGroupSnapshot, AppGroupWelcome,
    AppSignedGroupEnvelope, GroupRekeyPolicy,
};
pub use identity::{AppIdentity, PublicIdentity};
pub use identity_store::{DeviceFingerprint, DeviceId, IdentityStore, StoredIdentityMetadata};
pub use identity_vault::{
    IdentityUnlockSession, IdentityVault, UnlockedIdentityPublicMaterial, VaultIdentitySummary,
    VaultSessionStatus, MAX_IDLE_TIMEOUT_SECONDS, MAX_REMEMBER_UNLOCK_SECONDS,
};
pub use live_state::{LiveStateStore, StoredLiveGroupState, StoredLiveSessionState};
pub use message_store::{
    ConversationId, ConversationKind, MessageDirection, MessageStore, PendingCommitRecord,
    ReplayCursorRecord, SkippedKeyPersistencePolicy, StoredConversation, StoredMember,
    StoredMessage,
};
pub use recovery::{
    export_recovery_backup, import_identity_from_backup, import_message_store_from_backup,
    inspect_recovery_backup, BackupSecret, EncryptedRecoveryBackup, IdentityImportPolicy,
    RecoveryBackupOptions, RecoveryKey, RecoveryKeyPolicy, RecoveryManifest,
};
pub use secret_handling::{OsKeychainSecretProvider, StorageKdfPolicy, UnsupportedOsKeychain};
pub use session::{
    AppDirectRekeyNotice, AppSession, AppSessionMessage, AppSessionPolicySend, AppSessionRole,
    AppSessionSnapshot, AppSessionWireMessage, DirectRekeyPolicy, SessionHandshakeExport,
};
pub use storage_recovery::{
    check_signed_backup_history, current_recovery_time_ms, export_active_identity_recovery_backup,
    export_signed_backup_checkpoint_for_active_identity, inspect_recovery_backup_file,
    storage_recovery_status, ActiveIdentityRecoveryBackupExport, RecoveryBackupExportSummary,
    RecoveryBackupInspection, SignedCheckpointExportSummary, StorageRecoveryStatus,
    LIVE_STATE_FILE, MESSAGE_STORE_FILE, SIGNED_BACKUP_HISTORY_FILE,
};
pub use transport::{
    AllowAllRateLimiter, AttachmentHandle, InMemoryTransport, MailboxId, MailboxStats,
    QueuedTransportEnvelope, TransportApi, TransportMessageId, TransportRateLimiter,
    TransportUploadRequest, UploadReceipt, UploadStatus,
};
