//! Parser hooks compiled only under cargo-fuzz's `--cfg fuzzing` build.
//!
//! This module does not exist in normal, release, or application builds. It keeps
//! fuzz harnesses fast and in-memory without expanding the supported v1 facade.

use crate::{
    codec::{decode_message_line, pack_message, unpack_message},
    ContactId, HydraMessage, HydraResult, MessageId, ReceivedHydraMessage,
};

/// Attempts to decode an arbitrary packed message without touching persistent state.
pub fn decode_message_payload(bytes: &[u8]) -> HydraResult<ReceivedHydraMessage> {
    unpack_message(
        bytes,
        ContactId::from_bytes([0; hydra_core::HASH_SIZE]),
        MessageId::from_u64(0),
        None,
    )
}

/// Attempts to decode an arbitrary exported-message record without opening a profile.
pub fn decode_message_state_line(bytes: &[u8]) -> HydraResult<()> {
    let line = std::str::from_utf8(bytes)
        .map_err(|_| crate::HydraMsgError::InvalidEncoding("message state utf-8"))?;
    decode_message_line(line).map(|_| ())
}

/// Encodes a message through the production binary codec for fast round-trip fuzzing.
pub fn encode_message_payload(message: &HydraMessage) -> HydraResult<Vec<u8>> {
    pack_message(message)
}
