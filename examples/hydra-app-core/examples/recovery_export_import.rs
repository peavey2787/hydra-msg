use std::fs;

use hydra_app_core::{
    export_recovery_backup, import_identity_from_backup, import_message_store_from_backup,
    inspect_recovery_backup, BackupSecret, ConversationKind, IdentityImportPolicy, IdentityStore,
    MessageDirection, MessageStore, RecoveryBackupOptions, StoredMessage,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::temp_dir().join("hydra-msg-recovery-example");
    fs::create_dir_all(&base)?;
    let identity_path = base.join("identity.hydraid");
    let message_path = base.join("messages.hydramsgdb");
    let recovered_identity_path = base.join("identity-recovered.hydraid");
    let recovered_message_path = base.join("messages-recovered.hydramsgdb");

    let identity = IdentityStore::create(&identity_path, b"local identity password")?;
    let mut messages = MessageStore::create(&message_path, b"local message password")?;
    let conversation_id =
        messages.create_conversation(ConversationKind::Direct, 1_700_000_000_000)?;
    messages.append_message(StoredMessage {
        conversation_id,
        direction: MessageDirection::Outbound,
        sender_id: identity.public_identity().fingerprint().0,
        epoch: 0,
        state_version: 0,
        message_index: 0,
        received_at_ms: 1_700_000_000_001,
        content: b"encrypted database payload example".to_vec(),
    })?;
    messages.save(b"local message password")?;

    let backup = export_recovery_backup(
        &identity,
        Some(&messages),
        BackupSecret::Passphrase(b"correct horse recovery staple"),
        RecoveryBackupOptions::default(),
        1_700_000_000_002,
    )?;
    let manifest = inspect_recovery_backup(
        &backup,
        BackupSecret::Passphrase(b"correct horse recovery staple"),
    )?;
    println!(
        "backup conversations={} messages={} allow_clone={}",
        manifest.conversation_count, manifest.message_count, manifest.allow_active_device_clone
    );

    let recovered_identity = import_identity_from_backup(
        &backup,
        BackupSecret::Passphrase(b"correct horse recovery staple"),
        &recovered_identity_path,
        b"new identity password",
        IdentityImportPolicy::NewDevice,
    )?;
    let recovered_messages = import_message_store_from_backup(
        &backup,
        BackupSecret::Passphrase(b"correct horse recovery staple"),
        &recovered_message_path,
        b"new message password",
    )?;
    assert_eq!(
        recovered_identity.public_identity(),
        identity.public_identity()
    );
    assert_ne!(recovered_identity.device_id(), identity.device_id());
    assert_eq!(recovered_messages.messages().len(), 1);
    println!("recovered identity as a new device without cloning the old device ID");
    Ok(())
}
