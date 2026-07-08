use std::fs;

use hydra_app_core::{
    AppIdentity, LiveStateStore, SignedBackupCheckpoint, POSSIBLE_ROLLBACK_WARNING,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::temp_dir().join("hydra-signed-backup-history-example");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base)?;
    let live_state_path = base.join("live-state.db");
    let history_path = base.join("signed-backup-history.txt");
    let export_dir = base.join("user-chosen-checkpoints");
    let password = b"example storage password";
    let identity = AppIdentity::generate()?;

    let mut store = LiveStateStore::create(&live_state_path, password)?;
    let checkpoint = store.save_with_signed_backup_history(
        password,
        &identity,
        &history_path,
        Some(&export_dir),
    )?;

    let exported = export_dir.join(format!(
        "hydra-checkpoint-{:020}.hcpt",
        checkpoint.backup_sequence,
    ));
    let decoded = SignedBackupCheckpoint::from_text(&fs::read_to_string(&exported)?)?;
    assert!(decoded.verify());

    LiveStateStore::load_with_signed_backup_history(
        &live_state_path,
        password,
        &history_path,
        std::slice::from_ref(&export_dir),
    )?;

    println!("signed backup checkpoint written: {}", exported.display());
    println!("warning shown on rollback:\n{POSSIBLE_ROLLBACK_WARNING}");
    Ok(())
}
