use super::{exact_array_from_vec, hex_decode, hex_encode, write_u32, write_u64, BytesReader};
use crate::{
    limits::{
        reject_encoded_size, MAX_ATTACHMENTS_PER_MESSAGE, MAX_ATTACHMENT_BYTES,
        MAX_ATTACHMENT_FILENAME_BYTES, MAX_MESSAGE_PLAINTEXT_BYTES, MAX_PACKED_MESSAGE_BYTES,
    },
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
    parts.join("\t")
}

pub(crate) fn decode_message_line(line: &str) -> HydraResult<StoredMessage> {
    const MAX_MESSAGE_LINE_FIELDS: usize = 6 + MAX_ATTACHMENTS_PER_MESSAGE * 3;
    let parts = line
        .split('\t')
        .take(MAX_MESSAGE_LINE_FIELDS + 1)
        .collect::<Vec<_>>();
    if parts.len() > MAX_MESSAGE_LINE_FIELDS {
        return Err(HydraMsgError::InvalidEncoding("message state record"));
    }
    if parts.len() < 6 || parts[0] != "message" {
        return Err(HydraMsgError::InvalidEncoding("message state record"));
    }
    let id = MessageId(
        parts[1]
            .parse()
            .map_err(|_| HydraMsgError::InvalidEncoding("message id"))?,
    );
    if parts[2].len() != hydra_core::HASH_SIZE * 2 {
        return Err(HydraMsgError::InvalidEncoding("message contact id size"));
    }
    let contact_id = ContactId(exact_array_from_vec(hex_decode(parts[2])?)?);
    let inbound = match parts[3] {
        "in" => true,
        "out" => false,
        _ => return Err(HydraMsgError::InvalidEncoding("message direction")),
    };
    reject_hex_decoded_size(
        parts[4],
        MAX_MESSAGE_PLAINTEXT_BYTES,
        "message plaintext size",
    )?;
    let plaintext = hex_decode(parts[4])?;
    let attachment_count: usize = parts[5]
        .parse()
        .map_err(|_| HydraMsgError::InvalidEncoding("attachment count"))?;
    if attachment_count > MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(HydraMsgError::InvalidEncoding("attachment count"));
    }
    let expected_parts = attachment_count
        .checked_mul(3)
        .and_then(|value| value.checked_add(6))
        .ok_or(HydraMsgError::InvalidEncoding("attachment record length"))?;
    if parts.len() != expected_parts {
        return Err(HydraMsgError::InvalidEncoding("attachment record length"));
    }
    let mut attachments = Vec::with_capacity(attachment_count);
    let mut offset = 6;
    let mut decoded_size = PAYLOAD_MAGIC.len() + 8 + plaintext.len() + 4;
    for _ in 0..attachment_count {
        let source = match parts[offset] {
            "file" => HydraAttachmentSource::File,
            "bytes" => HydraAttachmentSource::Bytes,
            _ => return Err(HydraMsgError::InvalidEncoding("attachment source")),
        };
        reject_hex_decoded_size(
            parts[offset + 1],
            MAX_ATTACHMENT_FILENAME_BYTES,
            "attachment filename size",
        )?;
        let filename = String::from_utf8(hex_decode(parts[offset + 1])?)
            .map_err(|_| HydraMsgError::InvalidEncoding("attachment filename"))?;
        validate_decoded_filename(&filename)?;
        reject_hex_decoded_size(parts[offset + 2], MAX_ATTACHMENT_BYTES, "attachment size")?;
        let bytes = hex_decode(parts[offset + 2])?;
        decoded_size = decoded_size
            .checked_add(1 + 4 + filename.len() + 8 + bytes.len())
            .ok_or(HydraMsgError::InvalidEncoding("message size"))?;
        reject_encoded_size(decoded_size, MAX_PACKED_MESSAGE_BYTES, "message size")?;
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
    validate_message(message, false)?;
    let encoded_len = encoded_message_len(message, false)?;
    let mut out = Vec::with_capacity(encoded_len);
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
    reject_encoded_size(bytes.len(), MAX_PACKED_MESSAGE_BYTES, "message size")?;
    let mut reader = BytesReader::new(bytes);
    reader.expect(PAYLOAD_MAGIC)?;
    let plaintext_len = usize::try_from(reader.read_u64()?)
        .map_err(|_| HydraMsgError::InvalidEncoding("message plaintext size"))?;
    reject_encoded_size(
        plaintext_len,
        MAX_MESSAGE_PLAINTEXT_BYTES,
        "message plaintext size",
    )?;
    let plaintext = reader.read_vec(plaintext_len)?;
    let attachment_count = reader.read_u32()? as usize;
    if attachment_count > MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(HydraMsgError::InvalidEncoding("attachment count"));
    }
    let mut attachments = Vec::with_capacity(attachment_count);
    for _ in 0..attachment_count {
        let source = match reader.read_u8()? {
            1 => HydraAttachmentSource::File,
            2 => HydraAttachmentSource::Bytes,
            _ => return Err(HydraMsgError::InvalidEncoding("attachment source")),
        };
        let name_len = reader.read_u32()? as usize;
        reject_encoded_size(
            name_len,
            MAX_ATTACHMENT_FILENAME_BYTES,
            "attachment filename size",
        )?;
        let filename = String::from_utf8(reader.read_vec(name_len)?)
            .map_err(|_| HydraMsgError::InvalidEncoding("attachment filename"))?;
        validate_decoded_filename(&filename)?;
        let bytes_len = usize::try_from(reader.read_u64()?)
            .map_err(|_| HydraMsgError::InvalidEncoding("attachment size"))?;
        reject_encoded_size(bytes_len, MAX_ATTACHMENT_BYTES, "attachment size")?;
        let content = reader.read_vec(bytes_len)?;
        attachments.push(HydraAttachment {
            filename,
            bytes: content,
            source,
        });
    }
    if !reader.is_finished() {
        return Err(HydraMsgError::InvalidEncoding("message trailing bytes"));
    }
    Ok(ReceivedHydraMessage {
        from,
        message_id,
        lobby_id,
        plaintext,
        attachments,
    })
}

pub(crate) fn stored_message_size(
    plaintext: &[u8],
    attachments: &[HydraAttachment],
) -> HydraResult<usize> {
    if plaintext.len() > MAX_MESSAGE_PLAINTEXT_BYTES {
        return Err(HydraMsgError::InvalidEncoding("message plaintext size"));
    }
    if attachments.len() > MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(HydraMsgError::InvalidEncoding("attachment count"));
    }
    let mut total = PAYLOAD_MAGIC
        .len()
        .checked_add(8 + 4)
        .and_then(|value| value.checked_add(plaintext.len()))
        .ok_or(HydraMsgError::InvalidEncoding("message size"))?;
    for attachment in attachments {
        validate_attachment(attachment, true)?;
        total = total
            .checked_add(1 + 4 + 8)
            .and_then(|value| value.checked_add(attachment.filename.len()))
            .and_then(|value| value.checked_add(attachment.bytes.len()))
            .ok_or(HydraMsgError::InvalidEncoding("message size"))?;
    }
    reject_encoded_size(total, MAX_PACKED_MESSAGE_BYTES, "message size")?;
    Ok(total)
}

fn validate_message(message: &HydraMessage, encoded: bool) -> HydraResult<()> {
    let size_error = if encoded {
        HydraMsgError::InvalidEncoding("message plaintext size")
    } else {
        HydraMsgError::InvalidInput("message plaintext size")
    };
    if message.plaintext.len() > MAX_MESSAGE_PLAINTEXT_BYTES {
        return Err(size_error);
    }
    if message.attachments.len() > MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(if encoded {
            HydraMsgError::InvalidEncoding("attachment count")
        } else {
            HydraMsgError::InvalidInput("attachment count")
        });
    }
    for attachment in &message.attachments {
        validate_attachment(attachment, encoded)?;
    }
    encoded_message_len(message, encoded).map(|_| ())
}

fn validate_attachment(attachment: &HydraAttachment, encoded: bool) -> HydraResult<()> {
    if attachment.filename.is_empty() {
        return Err(if encoded {
            HydraMsgError::InvalidEncoding("attachment filename is empty")
        } else {
            HydraMsgError::InvalidInput("attachment filename is empty")
        });
    }
    if attachment.filename.len() > MAX_ATTACHMENT_FILENAME_BYTES {
        return Err(if encoded {
            HydraMsgError::InvalidEncoding("attachment filename size")
        } else {
            HydraMsgError::InvalidInput("attachment filename size")
        });
    }
    if attachment.bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(if encoded {
            HydraMsgError::InvalidEncoding("attachment size")
        } else {
            HydraMsgError::InvalidInput("attachment size")
        });
    }
    Ok(())
}

fn encoded_message_len(message: &HydraMessage, encoded: bool) -> HydraResult<usize> {
    let mut total = PAYLOAD_MAGIC
        .len()
        .checked_add(8 + 4)
        .and_then(|value| value.checked_add(message.plaintext.len()))
        .ok_or_else(|| message_size_error(encoded))?;
    for attachment in &message.attachments {
        total = total
            .checked_add(1 + 4 + 8)
            .and_then(|value| value.checked_add(attachment.filename.len()))
            .and_then(|value| value.checked_add(attachment.bytes.len()))
            .ok_or_else(|| message_size_error(encoded))?;
    }
    if total > MAX_PACKED_MESSAGE_BYTES {
        return Err(message_size_error(encoded));
    }
    Ok(total)
}

fn message_size_error(encoded: bool) -> HydraMsgError {
    if encoded {
        HydraMsgError::InvalidEncoding("message size")
    } else {
        HydraMsgError::InvalidInput("message size")
    }
}

fn reject_hex_decoded_size(value: &str, max: usize, description: &'static str) -> HydraResult<()> {
    let max_hex = max
        .checked_mul(2)
        .ok_or(HydraMsgError::InvalidEncoding(description))?;
    if value.len() > max_hex {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

fn validate_decoded_filename(filename: &str) -> HydraResult<()> {
    if filename.is_empty() {
        return Err(HydraMsgError::InvalidEncoding(
            "attachment filename is empty",
        ));
    }
    reject_encoded_size(
        filename.len(),
        MAX_ATTACHMENT_FILENAME_BYTES,
        "attachment filename size",
    )
}

#[cfg(test)]
mod tests;
