use hydra_app_core::{
    CommitDeliveryAttempt, CommitDeliveryGuard, CommitDeliveryStatus, ConversationId,
    ConversationKind, StoredConversation,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conversation = StoredConversation {
        id: ConversationId([0x44; 32]),
        kind: ConversationKind::GroupInteractive,
        created_at_ms: 1_000,
        current_epoch: 3,
        current_state_version: 12,
        members: Vec::new(),
    };
    let mut guard = CommitDeliveryGuard::from_conversation(&conversation, [0x12; 64]);
    let attempt = CommitDeliveryAttempt {
        conversation_id: conversation.id,
        epoch: 4,
        state_version: 13,
        parent_commit_hash: [0x12; 64],
        commit_hash: [0x13; 64],
    };
    assert_eq!(
        guard.observe_commit(attempt)?,
        CommitDeliveryStatus::Accepted
    );
    assert_eq!(
        guard.observe_commit(attempt)?,
        CommitDeliveryStatus::Duplicate
    );
    println!(
        "accepted commit for epoch {} / state version {} and rejected duplicate replay",
        guard.current_epoch(),
        guard.current_state_version()
    );
    Ok(())
}
