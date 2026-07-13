use super::*;

#[test]
fn validation_covers_boundaries_error_classes_and_checked_sizes() {
    let maximum_plaintext = HydraMessage::bytes(vec![0; MAX_MESSAGE_PLAINTEXT_BYTES]);
    assert_eq!(validate_message(&maximum_plaintext, false), Ok(()));

    let maximum_count = HydraMessage {
        plaintext: Vec::new(),
        attachments: vec![
            attachment(HydraAttachmentSource::Bytes, "a", Vec::new());
            MAX_ATTACHMENTS_PER_MESSAGE
        ],
    };
    assert_eq!(validate_message(&maximum_count, false), Ok(()));

    let maximum_name = attachment(
        HydraAttachmentSource::Bytes,
        "n".repeat(MAX_ATTACHMENT_FILENAME_BYTES),
        Vec::new(),
    );
    assert_eq!(validate_attachment(&maximum_name, false), Ok(()));

    {
        let maximum_attachment = attachment(
            HydraAttachmentSource::Bytes,
            "maximum.bin",
            vec![0; MAX_ATTACHMENT_BYTES],
        );
        assert_eq!(validate_attachment(&maximum_attachment, true), Ok(()));
    }

    let oversized_plaintext = HydraMessage::bytes(vec![0; MAX_MESSAGE_PLAINTEXT_BYTES + 1]);
    assert_eq!(
        validate_message(&oversized_plaintext, false),
        Err(HydraMsgError::InvalidInput("message plaintext size"))
    );
    assert_eq!(
        validate_message(&oversized_plaintext, true),
        Err(HydraMsgError::InvalidEncoding("message plaintext size"))
    );
    assert_eq!(
        stored_message_size(&oversized_plaintext.plaintext, &[]),
        Err(HydraMsgError::InvalidEncoding("message plaintext size"))
    );

    let too_many_attachments = HydraMessage {
        plaintext: Vec::new(),
        attachments: vec![
            attachment(HydraAttachmentSource::Bytes, "a", Vec::new());
            MAX_ATTACHMENTS_PER_MESSAGE + 1
        ],
    };
    assert_eq!(
        validate_message(&too_many_attachments, false),
        Err(HydraMsgError::InvalidInput("attachment count"))
    );
    assert_eq!(
        validate_message(&too_many_attachments, true),
        Err(HydraMsgError::InvalidEncoding("attachment count"))
    );
    assert_eq!(
        stored_message_size(&[], &too_many_attachments.attachments),
        Err(HydraMsgError::InvalidEncoding("attachment count"))
    );

    for invalid in [
        attachment(HydraAttachmentSource::Bytes, "", Vec::new()),
        attachment(
            HydraAttachmentSource::Bytes,
            "n".repeat(MAX_ATTACHMENT_FILENAME_BYTES + 1),
            Vec::new(),
        ),
        attachment(
            HydraAttachmentSource::Bytes,
            "oversized.bin",
            vec![0; MAX_ATTACHMENT_BYTES + 1],
        ),
    ] {
        assert!(matches!(
            validate_attachment(&invalid, false),
            Err(HydraMsgError::InvalidInput(_))
        ));
        assert!(matches!(
            validate_attachment(&invalid, true),
            Err(HydraMsgError::InvalidEncoding(_))
        ));
    }

    let oversized_total = HydraMessage {
        plaintext: Vec::new(),
        attachments: vec![
            attachment(
                HydraAttachmentSource::Bytes,
                "first.bin",
                vec![0; MAX_ATTACHMENT_BYTES],
            ),
            attachment(
                HydraAttachmentSource::Bytes,
                "second.bin",
                vec![0; MAX_ATTACHMENT_BYTES],
            ),
        ],
    };
    assert_eq!(
        validate_message(&oversized_total, false),
        Err(HydraMsgError::InvalidInput("message size"))
    );
    assert_eq!(
        validate_message(&oversized_total, true),
        Err(HydraMsgError::InvalidEncoding("message size"))
    );
    assert_eq!(
        stored_message_size(&[], &oversized_total.attachments),
        Err(HydraMsgError::InvalidEncoding("message size"))
    );

    assert_eq!(
        reject_hex_decoded_size("00", 0, "hex boundary"),
        Err(HydraMsgError::InvalidEncoding("hex boundary"))
    );
    assert_eq!(
        reject_hex_decoded_size("", usize::MAX, "hex overflow"),
        Err(HydraMsgError::InvalidEncoding("hex overflow"))
    );
    assert_eq!(
        validate_decoded_filename(""),
        Err(HydraMsgError::InvalidEncoding(
            "attachment filename is empty"
        ))
    );
    assert_eq!(
        validate_decoded_filename(&"n".repeat(MAX_ATTACHMENT_FILENAME_BYTES + 1)),
        Err(HydraMsgError::InvalidEncoding("attachment filename size"))
    );
    assert_eq!(
        message_size_error(false),
        HydraMsgError::InvalidInput("message size")
    );
    assert_eq!(
        message_size_error(true),
        HydraMsgError::InvalidEncoding("message size")
    );
}
