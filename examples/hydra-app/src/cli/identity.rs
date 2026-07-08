use std::path::PathBuf;

use hydra_app_core::IdentityImportPolicy;

use crate::services;

pub(super) fn run_identity(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None | Some("list") => {
            let identities = services::list_identities()?;
            println!("[Encrypted identities]");
            if identities.is_empty() {
                println!("no identities yet");
                println!("create one with: hydra-app identity generate <label> <password>");
                return Ok(());
            }
            for identity in identities {
                println!(
                    "{}{}  id={}  fingerprint={}  device={}  generation={}  revoked={}",
                    if identity.active { "* " } else { "  " },
                    identity.label,
                    identity.id,
                    identity.identity_fingerprint_hex,
                    identity.device_fingerprint_hex,
                    identity.generation,
                    identity.revoked,
                );
            }
            Ok(())
        }
        Some("generate") => {
            let label = args.get(1).ok_or_else(|| {
                "usage: hydra-app identity generate <label> <password>".to_owned()
            })?;
            let password = args.get(2).ok_or_else(|| {
                "usage: hydra-app identity generate <label> <password>".to_owned()
            })?;
            let identity = services::generate_identity(label, password.as_bytes())?;
            println!("generated encrypted identity: {}", identity.label);
            println!("identity id: {}", identity.id);
            println!(
                "identity fingerprint: {}",
                identity.identity_fingerprint_hex
            );
            println!("device fingerprint: {}", identity.device_fingerprint_hex);
            Ok(())
        }
        Some("import-store") => {
            let label = args.get(1).ok_or_else(|| {
                "usage: hydra-app identity import-store <label> <source-path> <source-password> <new-password> [--preserve-device-id]".to_owned()
            })?;
            let source_path = args.get(2).ok_or_else(|| {
                "usage: hydra-app identity import-store <label> <source-path> <source-password> <new-password> [--preserve-device-id]".to_owned()
            })?;
            let source_password = args.get(3).ok_or_else(|| {
                "usage: hydra-app identity import-store <label> <source-path> <source-password> <new-password> [--preserve-device-id]".to_owned()
            })?;
            let new_password = args.get(4).ok_or_else(|| {
                "usage: hydra-app identity import-store <label> <source-path> <source-password> <new-password> [--preserve-device-id]".to_owned()
            })?;
            let preserve_device_id = args.iter().any(|arg| arg == "--preserve-device-id");
            let identity = services::import_identity_store_file(
                label,
                PathBuf::from(source_path.as_str()),
                source_password.as_bytes(),
                new_password.as_bytes(),
                preserve_device_id,
            )?;
            println!("imported encrypted identity: {}", identity.label);
            println!("identity id: {}", identity.id);
            Ok(())
        }
        Some("import-backup") => {
            let label = args.get(1).ok_or_else(|| {
                "usage: hydra-app identity import-backup <label> <backup-path> <backup-password> <identity-password> [--preserve-device-id]".to_owned()
            })?;
            let backup_path = args.get(2).ok_or_else(|| {
                "usage: hydra-app identity import-backup <label> <backup-path> <backup-password> <identity-password> [--preserve-device-id]".to_owned()
            })?;
            let backup_password = args.get(3).ok_or_else(|| {
                "usage: hydra-app identity import-backup <label> <backup-path> <backup-password> <identity-password> [--preserve-device-id]".to_owned()
            })?;
            let identity_password = args.get(4).ok_or_else(|| {
                "usage: hydra-app identity import-backup <label> <backup-path> <backup-password> <identity-password> [--preserve-device-id]".to_owned()
            })?;
            let policy = if args.iter().any(|arg| arg == "--preserve-device-id") {
                IdentityImportPolicy::PreserveDeviceIfAllowed
            } else {
                IdentityImportPolicy::NewDevice
            };
            let identity = services::import_identity_backup_file(
                label,
                PathBuf::from(backup_path.as_str()),
                backup_password.as_bytes(),
                identity_password.as_bytes(),
                policy,
            )?;
            println!("imported encrypted recovery identity: {}", identity.label);
            println!("identity id: {}", identity.id);
            Ok(())
        }
        Some("switch") => {
            let id = args
                .get(1)
                .ok_or_else(|| "usage: hydra-app identity switch <identity-id>".to_owned())?;
            let identity = services::switch_identity(id)?;
            println!("active identity: {} ({})", identity.label, identity.id);
            Ok(())
        }
        Some(other) => Err(format!("unknown identity command '{other}'")),
    }
}
