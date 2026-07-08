use hydra_app_core::{
    encrypt_attachment_with_options, AttachmentEncryptionOptions, AttachmentObjectId,
    AttachmentPolicy, ConversationKind, InMemoryAttachmentStore,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_bytes = b"example encrypted attachment bytes".repeat(32);
    AttachmentPolicy::require_allowed_for_conversation(ConversationKind::GroupInteractive, 1)?;

    let encrypted = encrypt_attachment_with_options(
        &file_bytes,
        AttachmentEncryptionOptions {
            chunk_size: 64,
            max_plaintext_size: 4096,
        },
    )?;
    let handle = encrypted.handle();

    let mut store = InMemoryAttachmentStore::new();
    store.put_encrypted(&encrypted)?;

    let opened = store.open(encrypted.key(), &handle)?;
    assert_eq!(&opened[..], file_bytes.as_slice());
    assert!(store.contains(AttachmentObjectId(handle.object_id)));
    assert!(
        AttachmentPolicy::require_allowed_for_conversation(ConversationKind::GroupLite, 1).is_err()
    );

    println!(
        "encrypted attachment: object={:02x?} chunks={} plaintext={} encrypted={}",
        &handle.object_id[..4],
        encrypted.manifest().chunk_count,
        encrypted.manifest().plaintext_size,
        encrypted.manifest().encrypted_size
    );
    Ok(())
}
