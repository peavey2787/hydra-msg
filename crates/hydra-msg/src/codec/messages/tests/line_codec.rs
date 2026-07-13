use super::*;

#[test]
fn message_state_line_roundtrips_directions_and_attachment_sources() {
    for inbound in [false, true] {
        let stored = StoredMessage {
            id: MessageId::from_u64(7),
            contact_id: contact(),
            inbound,
            plaintext: b"state message".to_vec(),
            attachments: vec![
                attachment(HydraAttachmentSource::File, "from-file.bin", vec![1, 2]),
                attachment(HydraAttachmentSource::Bytes, "from-bytes.bin", vec![3, 4]),
            ],
        };
        let encoded = encode_message_line(&stored);
        assert_eq!(decode_message_line(&encoded), Ok(stored));
    }
}

#[test]
fn message_state_line_rejects_malformed_records() {
    let too_many_fields = vec!["field"; 6 + MAX_ATTACHMENTS_PER_MESSAGE * 3 + 1].join("\t");
    assert_eq!(
        decode_message_line(&too_many_fields),
        Err(HydraMsgError::InvalidEncoding("message state record"))
    );
    assert_eq!(
        decode_message_line("message\t1"),
        Err(HydraMsgError::InvalidEncoding("message state record"))
    );
    assert_eq!(
        decode_message_line(&message_line("in", "0").replacen("message", "other", 1)),
        Err(HydraMsgError::InvalidEncoding("message state record"))
    );
    assert_eq!(
        decode_message_line(&message_line("in", "0").replacen("\t1\t", "\tnot-id\t", 1)),
        Err(HydraMsgError::InvalidEncoding("message id"))
    );
    assert_eq!(
        decode_message_line("message\t1\t00\tin\t\t0"),
        Err(HydraMsgError::InvalidEncoding("message contact id size"))
    );
    assert_eq!(
        decode_message_line(&format!(
            "message\t1\t{}\tin\t\t0",
            "zz".repeat(hydra_core::HASH_SIZE)
        )),
        Err(HydraMsgError::InvalidEncoding("hex character"))
    );
    assert_eq!(
        decode_message_line(&message_line("sideways", "0")),
        Err(HydraMsgError::InvalidEncoding("message direction"))
    );
    let oversized_plaintext = "00".repeat(MAX_MESSAGE_PLAINTEXT_BYTES + 1);
    assert_eq!(
        decode_message_line(&format!(
            "message\t1\t{}\tin\t{oversized_plaintext}\t0",
            contact().hex()
        )),
        Err(HydraMsgError::InvalidEncoding("message plaintext size"))
    );
    assert_eq!(
        decode_message_line(&message_line("in", "not-count")),
        Err(HydraMsgError::InvalidEncoding("attachment count"))
    );
    assert_eq!(
        decode_message_line(&message_line(
            "in",
            &(MAX_ATTACHMENTS_PER_MESSAGE + 1).to_string()
        )),
        Err(HydraMsgError::InvalidEncoding("attachment count"))
    );
    assert_eq!(
        decode_message_line(&message_line("in", "1")),
        Err(HydraMsgError::InvalidEncoding("attachment record length"))
    );

    let invalid_source = format!("{}\tunknown\t61\t00", message_line("out", "1"));
    assert_eq!(
        decode_message_line(&invalid_source),
        Err(HydraMsgError::InvalidEncoding("attachment source"))
    );
    let oversized_name = "00".repeat(MAX_ATTACHMENT_FILENAME_BYTES + 1);
    let oversized_name_record = format!(
        "{}\tbytes\t{oversized_name}\t00",
        message_line("out", "1")
    );
    assert_eq!(
        decode_message_line(&oversized_name_record),
        Err(HydraMsgError::InvalidEncoding("attachment filename size"))
    );
    let invalid_utf8_name = format!("{}\tbytes\tff\t00", message_line("out", "1"));
    assert_eq!(
        decode_message_line(&invalid_utf8_name),
        Err(HydraMsgError::InvalidEncoding("attachment filename"))
    );
    let empty_name = format!("{}\tbytes\t\t00", message_line("out", "1"));
    assert_eq!(
        decode_message_line(&empty_name),
        Err(HydraMsgError::InvalidEncoding(
            "attachment filename is empty"
        ))
    );
    let invalid_attachment_hex = format!("{}\tbytes\t61\tzz", message_line("out", "1"));
    assert_eq!(
        decode_message_line(&invalid_attachment_hex),
        Err(HydraMsgError::InvalidEncoding("hex character"))
    );
}
