use std::path::PathBuf;

use crate::services;

pub(super) fn run_backup(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None | Some("status") => {
            print_recovery_status(&services::recovery_status(&[])?);
            Ok(())
        }
        Some("check") => {
            let exported_paths = args[1..].iter().map(PathBuf::from).collect::<Vec<_>>();
            let status = services::check_signed_history(&exported_paths)?;
            if status.possible_rollback {
                return Err("refusing automatic use of possibly rolled-back state".to_owned());
            }
            println!("signed backup history check: ok");
            print_recovery_status(&status);
            Ok(())
        }
        Some(other) => Err(format!("unknown backup command '{other}'")),
    }
}

pub(super) fn run_recovery(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("export-backup") => {
            let identity_password = args.get(1).ok_or_else(|| {
                "usage: hydra-app recovery export-backup <identity-password> <backup-password> <output-path> [--allow-active-device-clone]".to_owned()
            })?;
            let backup_password = args.get(2).ok_or_else(|| {
                "usage: hydra-app recovery export-backup <identity-password> <backup-password> <output-path> [--allow-active-device-clone]".to_owned()
            })?;
            let output_path = args.get(3).ok_or_else(|| {
                "usage: hydra-app recovery export-backup <identity-password> <backup-password> <output-path> [--allow-active-device-clone]".to_owned()
            })?;
            let allow_active_device_clone = args.iter().any(|arg| arg == "--allow-active-device-clone");
            let summary = services::export_recovery_backup_for_active_identity(
                identity_password.as_bytes(),
                backup_password.as_bytes(),
                PathBuf::from(output_path.as_str()),
                allow_active_device_clone,
            )?;
            println!("encrypted recovery backup exported: {}", summary.output_path.display());
            println!("bytes written: {}", summary.bytes_written);
            println!("includes conversations: {}", summary.includes_conversations);
            println!("allow active device clone: {}", summary.allow_active_device_clone);
            Ok(())
        }
        Some("inspect-backup") => {
            let backup_path = args.get(1).ok_or_else(|| {
                "usage: hydra-app recovery inspect-backup <backup-path> <backup-password>".to_owned()
            })?;
            let backup_password = args.get(2).ok_or_else(|| {
                "usage: hydra-app recovery inspect-backup <backup-path> <backup-password>".to_owned()
            })?;
            let inspection = services::inspect_recovery_backup(PathBuf::from(backup_path.as_str()), backup_password.as_bytes())?;
            println!("encrypted recovery backup inspection");
            println!("includes identity: {}", inspection.includes_identity);
            println!("includes conversations: {}", inspection.includes_conversations);
            println!("conversation count: {}", inspection.conversation_count);
            println!("message count: {}", inspection.message_count);
            println!("allow active device clone: {}", inspection.allow_active_device_clone);
            Ok(())
        }
        Some("export-checkpoint") => {
            let identity_password = args.get(1).ok_or_else(|| {
                "usage: hydra-app recovery export-checkpoint <identity-password> <directory>".to_owned()
            })?;
            let export_dir = args.get(2).ok_or_else(|| {
                "usage: hydra-app recovery export-checkpoint <identity-password> <directory>".to_owned()
            })?;
            let summary = services::export_signed_checkpoint_for_active_identity(
                identity_password.as_bytes(),
                export_dir,
            )?;
            println!("signed checkpoint exported: {}", summary.exported_checkpoint_path.display());
            println!("backup sequence: {}", summary.backup_sequence);
            println!("local rollback counter: {}", summary.local_rollback_counter);
            Ok(())
        }
        Some("check-history") => {
            let exported_paths = args[1..]
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            let status = services::check_signed_history(&exported_paths)?;
            print_recovery_status(&status);
            Ok(())
        }
        _ => Err("usage: hydra-app recovery <export-backup|inspect-backup|export-checkpoint|check-history> ...".to_owned()),
    }
}

fn print_recovery_status(status: &hydra_app_core::StorageRecoveryStatus) {
    println!("[Storage and recovery]");
    println!("data dir: {}", status.data_dir.display());
    println!(
        "active identity: {}",
        status.active_identity_label.as_deref().unwrap_or("none")
    );
    println!("identity count: {}", status.identity_count);
    println!("message store present: {}", status.message_store_present);
    println!(
        "message counts: conversations={} messages={}",
        status
            .message_store_conversation_count
            .map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        status
            .message_store_message_count
            .map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
    );
    println!("live-state present: {}", status.live_state_present);
    println!(
        "live-state sequence: {}",
        status
            .live_state_sequence
            .map_or_else(|| "none".to_owned(), |value| value.to_string())
    );
    println!("signed history present: {}", status.signed_history_present);
    println!(
        "signed checkpoint count: {}",
        status.signed_history_checkpoint_count
    );
    println!(
        "newest signed checkpoint sequence: {}",
        status
            .newest_signed_checkpoint_sequence
            .map_or_else(|| "none".to_owned(), |value| value.to_string())
    );
    println!("status: {}", status.status_message);
    if let Some(warning) = status.rollback_warning {
        println!("{warning}");
    }
}
