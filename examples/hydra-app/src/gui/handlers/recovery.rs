use std::path::PathBuf;

use hydra_app_core::{
    check_signed_backup_history, current_recovery_time_ms, export_active_identity_recovery_backup,
    export_signed_backup_checkpoint_for_active_identity, inspect_recovery_backup_file,
    ActiveIdentityRecoveryBackupExport, RecoveryBackupOptions,
};

use crate::{config::AppConfig, secrets::load_storage_secret};

use super::{
    json::{
        recovery_backup_export_json, recovery_backup_inspection_json,
        signed_checkpoint_export_json, storage_recovery_status_json,
    },
    support::{optional_bool, parse_checkpoint_paths},
};
use crate::gui::forms::{parse_form, required_form_value};

pub(crate) fn api_recovery_export_backup(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let output_path = required_form_value(&form, "backup_path")?;
    let identity_password = required_form_value(&form, "identity_password")?;
    let backup_password = required_form_value(&form, "backup_password")?;
    let include_conversations =
        optional_bool(form.get("include_conversations").map(String::as_str))?;
    let allow_active_device_clone =
        optional_bool(form.get("allow_active_device_clone").map(String::as_str))?;
    let config = AppConfig::load_or_default()?;
    let secret = load_storage_secret(&config.data_dir)?;
    let output_path = PathBuf::from(output_path);
    let summary = export_active_identity_recovery_backup(ActiveIdentityRecoveryBackupExport {
        data_dir: &config.data_dir,
        identity_id: None,
        identity_password: identity_password.as_bytes(),
        storage_password: secret.expose_secret(),
        backup_password: backup_password.as_bytes(),
        output_path: &output_path,
        options: RecoveryBackupOptions {
            allow_active_device_clone,
            include_conversations,
        },
        created_at_ms: current_recovery_time_ms(),
    })
    .map_err(|error| error.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"message\":\"encrypted recovery backup exported\",\"backup\":{}}}",
        recovery_backup_export_json(&summary),
    ))
}

pub(crate) fn api_recovery_inspect_backup(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let backup_path = required_form_value(&form, "backup_path")?;
    let backup_password = required_form_value(&form, "backup_password")?;
    let inspection =
        inspect_recovery_backup_file(PathBuf::from(backup_path), backup_password.as_bytes())
            .map_err(|error| error.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"message\":\"encrypted recovery backup inspected\",\"backup\":{}}}",
        recovery_backup_inspection_json(&inspection),
    ))
}

pub(crate) fn api_recovery_export_checkpoint(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let export_dir = required_form_value(&form, "export_dir")?;
    let identity_password = required_form_value(&form, "identity_password")?;
    let config = AppConfig::load_or_default()?;
    let secret = load_storage_secret(&config.data_dir)?;
    let summary = export_signed_backup_checkpoint_for_active_identity(
        &config.data_dir,
        None,
        identity_password.as_bytes(),
        secret.expose_secret(),
        PathBuf::from(export_dir),
    )
    .map_err(|error| error.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"message\":\"signed backup checkpoint exported\",\"checkpoint\":{}}}",
        signed_checkpoint_export_json(&summary),
    ))
}

pub(crate) fn api_recovery_check_history(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let checkpoint_paths = form
        .get("checkpoint_paths")
        .map(String::as_str)
        .unwrap_or("");
    let paths = parse_checkpoint_paths(checkpoint_paths);
    let config = AppConfig::load_or_default()?;
    let secret = load_storage_secret(&config.data_dir)?;
    let status = check_signed_backup_history(&config.data_dir, secret.expose_secret(), &paths)
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"message\":\"signed backup history checked\",\"recovery_status\":{}}}",
        storage_recovery_status_json(&status),
    ))
}
