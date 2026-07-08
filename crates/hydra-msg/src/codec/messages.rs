use super::{exact_array_from_vec, hex_decode, hex_encode, write_u32, write_u64, BytesReader};
use crate::{
    ContactId, HydraAttachment, HydraAttachmentSource, HydraMessage, HydraMsgError, HydraResult,
    LobbyId, MessageId, ReceivedHydraMessage, StoredMessage, PAYLOAD_MAGIC,
};

pub(crate) fn encode_message_line(message: &StoredMessage) -> String {
    let mut parts = vec![
        "message".to_string(),
        message.id.0.to_string(),
        message.contact_id.hex(),
        if message.inbound { "in" } else { "out" }.to_string(),
        hex_encode(&message.plaintext),
        message.attachments.len().to_string(),
    ];
    for attachment in &message.attachments {
        let source = match attachment.source {
            HydraAttachmentSource::File => "file",
            HydraAttachmentSource::Bytes => "bytes",
        };
        parts.push(source.to_string());
        parts.push(hex_encode(attachment.filename.as_bytes()));
        parts.push(hex_encode(&attachment.bytes));
    }
    parts.join("	")
}

pub(crate) fn decode_message_line(line: &str) -> HydraResult<StoredMessage> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() < 6 || parts[0] != "message" {
        return Err(HydraMsgError::InvalidEncoding("message state record"));
    }
    let id = MessageId(
        parts[1]
            .parse()
            .map_err(|_| HydraMsgError::InvalidEncoding("message id"))?,
    );
    let contact_id = ContactId(exact_array_from_vec(hex_decode(parts[2])?)?);
    let inbound = match parts[3] {
        "in" => true,
        "out" => false,
        _ => return Err(HydraMsgError::InvalidEncoding("message direction")),
    };
    let plaintext = hex_decode(parts[4])?;
    let attachment_count: usize = parts[5]
        .parse()
        .map_err(|_| HydraMsgError::InvalidEncoding("attachment count"))?;
    if parts.len() != 6 + attachment_count * 3 {
        return Err(HydraMsgError::InvalidEncoding("attachment record length"));
    }
    let mut attachments = Vec::with_capacity(attachment_count);
    let mut offset = 6;
    for _ in 0..attachment_count {
        let source = match parts[offset] {
            "file" => HydraAttachmentSource::File,
            "bytes" => HydraAttachmentSource::Bytes,
            _ => return Err(HydraMsgError::InvalidEncoding("attachment source")),
        };
        let filename = String::from_utf8(hex_decode(parts[offset + 1])?)
            .map_err(|_| HydraMsgError::InvalidEncoding("attachment filename"))?;
        let bytes = hex_decode(parts[offset + 2])?;
        attachments.push(HydraAttachment {
            filename,
            bytes,
            source,
        });
        offset += 3;
    }
    Ok(StoredMessage {
        id,
        contact_id,
        inbound,
        plaintext,
        attachments,
    })
}

pub(crate) fn pack_message(message: &HydraMessage) -> HydraResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(PAYLOAD_MAGIC);
    write_u64(&mut out, message.plaintext.len() as u64);
    out.extend_from_slice(&message.plaintext);
    write_u32(&mut out, message.attachments.len() as u32);
    for attachment in &message.attachments {
        out.push(match attachment.source {
            HydraAttachmentSource::File => 1,
            HydraAttachmentSource::Bytes => 2,
        });
        let name = attachment.filename.as_bytes();
        write_u32(&mut out, name.len() as u32);
        out.extend_from_slice(name);
        write_u64(&mut out, attachment.bytes.len() as u64);
        out.extend_from_slice(&attachment.bytes);
    }
    Ok(out)
}

pub(crate) fn unpack_message(
    bytes: &[u8],
    from: ContactId,
    message_id: MessageId,
    lobby_id: Option<LobbyId>,
) -> HydraResult<ReceivedHydraMessage> {
    let mut reader = BytesReader::new(bytes);
    reader.expect(PAYLOAD_MAGIC)?;
    let plaintext_len = reader.read_u64()? as usize;
    let plaintext = reader.read_vec(plaintext_len)?;
    let attachment_count = reader.read_u32()? as usize;
    let mut attachments = Vec::with_capacity(attachment_count);
    for _ in 0..attachment_count {
        let source = match reader.read_u8()? {
            1 => HydraAttachmentSource::File,
            2 => HydraAttachmentSource::Bytes,
            _ => return Err(HydraMsgError::InvalidEncoding("attachment source")),
        };
        let name_len = reader.read_u32()? as usize;
        let filename = String::from_utf8(reader.read_vec(name_len)?)
            .map_err(|_| HydraMsgError::InvalidEncoding("attachment filename"))?;
        let bytes_len = reader.read_u64()? as usize;
        let content = reader.read_vec(bytes_len)?;
        attachments.push(HydraAttachment {
            filename,
            bytes: content,
            source,
        });
    }
    Ok(ReceivedHydraMessage {
        from,
        message_id,
        lobby_id,
        plaintext,
        attachments,
    })
}
