use hydra_app_core::{ConversationKind, MessageDirection, MessageStore, StoredMessage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::PathBuf::from("hydra-message-store.example.hydramsgdb");
    let password = b"replace with a user supplied high-entropy password";

    let mut store = MessageStore::create(&path, password)?;
    let conversation_id = store.create_conversation(ConversationKind::GroupLite, 0)?;
    store.append_message(StoredMessage {
        conversation_id,
        direction: MessageDirection::Outbound,
        sender_id: [0x11; 32],
        epoch: 0,
        state_version: 0,
        message_index: 0,
        received_at_ms: 0,
        content: b"encrypted at rest by the local database".to_vec(),
    })?;
    store.save(password)?;

    let loaded = MessageStore::load(&path, password)?;
    println!(
        "loaded {} encrypted local message(s)",
        loaded.messages().len()
    );
    std::fs::remove_file(path).ok();
    Ok(())
}
