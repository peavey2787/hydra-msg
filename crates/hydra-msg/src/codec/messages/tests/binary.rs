use super::*;

#[test]
fn binary_message_roundtrips_all_variants_and_minimum_payload() {
    let empty = HydraMessage::default();
    let packed = pack_message(&empty).unwrap();
    let unpacked = unpack_message(&packed, contact(), MessageId::from_u64(1), None).unwrap();
    assert!(unpacked.plaintext().is_empty());
    assert!(unpacked.attachments().is_empty());
    assert_eq!(unpacked.lobby_id(), None);

    let message = HydraMessage {
        plaintext: b"binary message".to_vec(),
        attachments: vec![
            attachment(HydraAttachmentSource::File, "file.bin", vec![1, 2, 3]),
            attachment(HydraAttachmentSource::Bytes, "bytes.bin", vec![4, 5, 6]),
        ],
    };
    let packed = pack_message(&message).unwrap();
    let unpacked = unpack_message(
        &packed,
        contact(),
        MessageId::from_u64(2),
        Some(lobby()),
    )
    .unwrap();
    assert_eq!(unpacked.plaintext(), message.plaintext());
    assert_eq!(unpacked.attachments(), message.attachments());
    assert_eq!(unpacked.lobby_id(), Some(lobby()));
}

#[test]
fn binary_message_rejects_truncation_invalid_discriminants_and_trailing_data() {
    assert!(unpack_message(b"bad", contact(), MessageId::from_u64(1), None).is_err());

    let mut bytes = Vec::new();
    bytes.extend_from_slice(PAYLOAD_MAGIC);
    write_u64(&mut bytes, (MAX_MESSAGE_PLAINTEXT_BYTES + 1) as u64);
    assert_eq!(
        unpack_message(&bytes, contact(), MessageId::from_u64(1), None),
        Err(HydraMsgError::InvalidEncoding("message plaintext size"))
    );

    let mut truncated_plaintext = Vec::new();
    truncated_plaintext.extend_from_slice(PAYLOAD_MAGIC);
    write_u64(&mut truncated_plaintext, 1);
    assert!(unpack_message(
        &truncated_plaintext,
        contact(),
        MessageId::from_u64(1),
        None
    )
    .is_err());

    let too_many = packed_prefix(&[], (MAX_ATTACHMENTS_PER_MESSAGE + 1) as u32);
    assert_eq!(
        unpack_message(&too_many, contact(), MessageId::from_u64(1), None),
        Err(HydraMsgError::InvalidEncoding("attachment count"))
    );

    let mut invalid_source = packed_prefix(&[], 1);
    invalid_source.push(0xff);
    assert_eq!(
        unpack_message(&invalid_source, contact(), MessageId::from_u64(1), None),
        Err(HydraMsgError::InvalidEncoding("attachment source"))
    );

    let mut oversized_name = packed_prefix(&[], 1);
    oversized_name.push(2);
    write_u32(
        &mut oversized_name,
        (MAX_ATTACHMENT_FILENAME_BYTES + 1) as u32,
    );
    assert_eq!(
        unpack_message(&oversized_name, contact(), MessageId::from_u64(1), None),
        Err(HydraMsgError::InvalidEncoding("attachment filename size"))
    );

    let mut invalid_utf8 = packed_prefix(&[], 1);
    invalid_utf8.push(2);
    write_u32(&mut invalid_utf8, 1);
    invalid_utf8.push(0xff);
    write_u64(&mut invalid_utf8, 0);
    assert_eq!(
        unpack_message(&invalid_utf8, contact(), MessageId::from_u64(1), None),
        Err(HydraMsgError::InvalidEncoding("attachment filename"))
    );

    let mut empty_name = packed_prefix(&[], 1);
    empty_name.push(2);
    write_u32(&mut empty_name, 0);
    write_u64(&mut empty_name, 0);
    assert_eq!(
        unpack_message(&empty_name, contact(), MessageId::from_u64(1), None),
        Err(HydraMsgError::InvalidEncoding(
            "attachment filename is empty"
        ))
    );

    let mut oversized_attachment = packed_prefix(&[], 1);
    oversized_attachment.push(2);
    write_u32(&mut oversized_attachment, 1);
    oversized_attachment.push(b'a');
    write_u64(
        &mut oversized_attachment,
        (MAX_ATTACHMENT_BYTES + 1) as u64,
    );
    assert_eq!(
        unpack_message(
            &oversized_attachment,
            contact(),
            MessageId::from_u64(1),
            None
        ),
        Err(HydraMsgError::InvalidEncoding("attachment size"))
    );

    let mut truncated_attachment = packed_prefix(&[], 1);
    truncated_attachment.push(2);
    write_u32(&mut truncated_attachment, 1);
    truncated_attachment.push(b'a');
    write_u64(&mut truncated_attachment, 1);
    assert!(unpack_message(
        &truncated_attachment,
        contact(),
        MessageId::from_u64(1),
        None
    )
    .is_err());

    let mut trailing = pack_message(&HydraMessage::text("ok")).unwrap();
    trailing.push(0);
    assert_eq!(
        unpack_message(&trailing, contact(), MessageId::from_u64(1), None),
        Err(HydraMsgError::InvalidEncoding("message trailing bytes"))
    );
}
