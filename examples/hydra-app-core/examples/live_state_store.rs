use hydra_app_core::{
    AppIdentity, AppSession, AppSessionRole, ConversationId, LiveStateStore, SessionHandshakeExport,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::path::PathBuf::from("target/examples/hydra-app-core/live_state_store");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("hydra-live-state.example.hydralive");
    let password = b"replace with a user supplied high-entropy password";

    let alice = AppIdentity::generate()?;
    let bob = AppIdentity::generate()?;
    let transcript = [0x42; 64];
    let secret = [0x24; 32];
    let mut alice_session = AppSession::start(
        AppSessionRole::Initiator,
        &alice,
        bob.public_identity(),
        SessionHandshakeExport::from_test_bytes(secret, transcript),
    )?;
    let conversation_id = ConversationId([0x91; 32]);

    alice_session.send(b"consume index before persistence")?;
    let mut store = LiveStateStore::create(&path, password)?;
    store.upsert_session(conversation_id, &alice_session);
    store.save(password)?;

    let loaded = LiveStateStore::load(&path, password)?;
    let mut restored = loaded.restore_session(conversation_id)?;
    let next = restored.send(b"continues after restart")?;
    println!(
        "restored live session next outgoing index: {}",
        next.index()
    );

    std::fs::remove_file(&path).ok();
    std::fs::remove_file(path.with_extension("hydralive.checkpoint")).ok();
    std::fs::remove_file(path.with_extension("hydralive.rollback.log")).ok();
    std::fs::remove_file(path.with_extension("hydralive.rollback.mirror.log")).ok();
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
