use super::*;

mod binary;
mod line_codec;
mod validation;

fn contact() -> ContactId {
    ContactId::from_bytes([0x11; hydra_core::HASH_SIZE])
}

fn lobby() -> LobbyId {
    LobbyId::from_bytes([0x22; hydra_core::HASH_SIZE])
}

fn attachment(
    source: HydraAttachmentSource,
    filename: impl Into<String>,
    bytes: Vec<u8>,
) -> HydraAttachment {
    HydraAttachment {
        filename: filename.into(),
        bytes,
        source,
    }
}

fn message_line(direction: &str, attachment_count: &str) -> String {
    format!(
        "message\t1\t{}\t{direction}\t\t{attachment_count}",
        contact().hex()
    )
}

fn packed_prefix(plaintext: &[u8], attachment_count: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PAYLOAD_MAGIC);
    write_u64(&mut bytes, plaintext.len() as u64);
    bytes.extend_from_slice(plaintext);
    write_u32(&mut bytes, attachment_count);
    bytes
}
