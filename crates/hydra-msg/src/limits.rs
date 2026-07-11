//! Production resource-exhaustion limits for the HYDRA facade.
//!
//! These are hard safety ceilings, not transport recommendations. Inputs that
//! exceed them are rejected before allocation-heavy parsing, cryptography, or
//! state mutation whenever the public API makes that possible.

/// Maximum encrypted local-state envelope accepted from disk or WASM storage.
pub const MAX_ENCRYPTED_STATE_BYTES: usize = MAX_STATE_SNAPSHOT_BYTES * 2 + 512 * 1024;
/// Maximum portable encrypted backup envelope accepted by import/verify.
pub const MAX_BACKUP_BYTES: usize = MAX_STATE_SNAPSHOT_BYTES * 2 + 512 * 1024;
/// Maximum authenticated plaintext snapshot encoded inside state or a backup.
pub const MAX_STATE_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum identities retained in one HYDRA state.
pub const MAX_IDENTITIES: usize = 256;
/// Maximum contacts retained in one HYDRA state.
pub const MAX_CONTACTS: usize = 1_024;
/// Maximum lobbies retained in one HYDRA state.
pub const MAX_LOBBIES: usize = 256;
/// Maximum stored messages retained in one HYDRA state.
pub const MAX_MESSAGES: usize = 100_000;
/// Maximum stored messages associated with one contact.
pub const MAX_MESSAGES_PER_CONTACT: usize = 10_000;
/// Maximum spent anonymous-authorization nullifiers retained in state.
pub const MAX_ANONYMOUS_AUTH_SPENT: usize = 100_000;

/// Maximum contact-card byte length.
pub const MAX_CONTACT_CARD_BYTES: usize = 16 * 1024;
/// Maximum contacts-export byte length accepted by `import_contacts`.
pub const MAX_CONTACT_IMPORT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of records accepted by one contacts import.
pub const MAX_IMPORTED_CONTACTS: usize = MAX_CONTACTS;
/// Maximum messages-export byte length accepted by `import_messages`.
pub const MAX_MESSAGE_IMPORT_BYTES: usize = MAX_STATE_SNAPSHOT_BYTES;
/// Maximum lobby-invite byte length.
pub const MAX_LOBBY_INVITE_BYTES: usize = 64 * 1024;
/// Maximum anonymous-authorization token byte length.
pub const MAX_ANONYMOUS_AUTH_TOKEN_BYTES: usize = 4 * 1024;
/// Maximum identity-export byte length.
pub const MAX_IDENTITY_EXPORT_BYTES: usize = 1024;

/// Maximum UTF-8 bytes accepted for a password before invoking the KDF.
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Maximum UTF-8 bytes in identity, contact, or lobby labels.
pub const MAX_LABEL_BYTES: usize = 256;
/// Maximum UTF-8 bytes in an attachment filename.
pub const MAX_ATTACHMENT_FILENAME_BYTES: usize = 255;
/// Maximum plaintext bytes in one message.
pub const MAX_MESSAGE_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum attachment count in one message.
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 16;
/// Maximum bytes in one attachment.
pub const MAX_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum encoded message payload before packet fragmentation.
pub const MAX_PACKED_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum logical payload accepted by packet fragmentation, including lobby framing.
pub const MAX_FRAGMENTED_PAYLOAD_BYTES: usize = MAX_PACKED_MESSAGE_BYTES + 64 * 1024;
/// Maximum total encoded bytes retained in local message history.
pub const MAX_STORED_MESSAGE_BYTES: usize = 256 * 1024 * 1024;
/// Maximum total encoded bytes retained for one contact's message history.
pub const MAX_STORED_MESSAGE_BYTES_PER_CONTACT: usize = 64 * 1024 * 1024;
/// Maximum number of encrypted packets one lobby send may return.
pub const MAX_LOBBY_OUTBOUND_PACKETS: usize = 4_096;
/// Maximum aggregate encrypted envelope bytes one lobby send may return.
pub const MAX_LOBBY_OUTBOUND_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum handshake offer byte length.
pub const MAX_HANDSHAKE_OFFER_BYTES: usize = 16 * 1024;
/// Maximum handshake answer byte length.
pub const MAX_HANDSHAKE_ANSWER_BYTES: usize = 16 * 1024;
/// Maximum locally pending initiator handshakes.
pub const MAX_PENDING_HANDSHAKES: usize = 64;
/// Pending handshakes older than this are discarded.
pub const MAX_PENDING_HANDSHAKE_AGE_SECS: u64 = 10 * 60;
/// Maximum receive-route tags indexed for one active session.
pub const MAX_SESSION_ROUTE_TAGS_PER_SESSION: usize = hydra_core::MAX_SKIP + 1;
/// Maximum receive-route index entries across all active sessions.
pub const MAX_SESSION_ROUTE_TAGS: usize = MAX_CONTACTS * MAX_SESSION_ROUTE_TAGS_PER_SESSION;

/// Maximum number of fragments declared for one logical message.
pub const MAX_FRAGMENTS_PER_MESSAGE: usize = 16_384;
/// Maximum number of received fragment parts retained globally.
pub const MAX_PENDING_FRAGMENTS: usize = 16_384;
/// Maximum incomplete fragmented messages retained globally.
pub const MAX_INCOMPLETE_MESSAGES: usize = 128;
/// Maximum incomplete fragmented messages retained for one contact.
pub const MAX_INCOMPLETE_MESSAGES_PER_CONTACT: usize = 8;
/// Maximum incomplete fragmented messages retained for one lobby.
pub const MAX_INCOMPLETE_MESSAGES_PER_LOBBY: usize = 8;
/// Maximum aggregate fragment payload bytes retained globally.
pub const MAX_PENDING_FRAGMENT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum age of an incomplete fragmented message.
pub const MAX_FRAGMENT_AGE_SECS: u64 = 10 * 60;

pub(crate) fn reject_input_size(
    len: usize,
    max: usize,
    description: &'static str,
) -> crate::HydraResult<()> {
    if len > max {
        return Err(crate::HydraMsgError::InvalidInput(description));
    }
    Ok(())
}

pub(crate) fn reject_encoded_size(
    len: usize,
    max: usize,
    description: &'static str,
) -> crate::HydraResult<()> {
    if len > max {
        return Err(crate::HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(crate) fn reject_collection_growth(
    current: usize,
    additional: usize,
    max: usize,
    description: &'static str,
) -> crate::HydraResult<()> {
    if current
        .checked_add(additional)
        .is_none_or(|total| total > max)
    {
        return Err(crate::HydraMsgError::InvalidInput(description));
    }
    Ok(())
}

pub(crate) fn reject_decoded_collection_growth(
    current: usize,
    additional: usize,
    max: usize,
    description: &'static str,
) -> crate::HydraResult<()> {
    if current
        .checked_add(additional)
        .is_none_or(|total| total > max)
    {
        return Err(crate::HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(crate) fn validate_label_input(
    value: &str,
    description: &'static str,
) -> crate::HydraResult<()> {
    reject_input_size(value.len(), MAX_LABEL_BYTES, description)
}

pub(crate) fn validate_label_encoding(
    value: &str,
    description: &'static str,
) -> crate::HydraResult<()> {
    reject_encoded_size(value.len(), MAX_LABEL_BYTES, description)
}
