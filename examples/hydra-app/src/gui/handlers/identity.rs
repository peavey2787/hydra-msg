use std::path::PathBuf;

use hydra_app_core::{IdentityImportPolicy, IdentityVault};

use crate::{config::AppConfig, services};

use super::{
    json::{identity_created_with_session_json, identity_json, session_status_json},
    support::{ensure_passwords_match, optional_bool, remember_seconds_from_form},
};
use crate::gui::{
    forms::{parse_form, required_form_value},
    state::GuiAppState,
};

pub(crate) fn api_identity_generate(
    body: &[u8],
    app_state: &GuiAppState,
) -> Result<String, String> {
    let form = parse_form(body)?;
    let label = required_form_value(&form, "label")?;
    let password = required_form_value(&form, "password")?;
    let confirm = required_form_value(&form, "password_confirm")?;
    ensure_passwords_match(password, confirm)?;
    let remember_seconds = remember_seconds_from_form(
        form.get("remember_me").map(String::as_str),
        form.get("remember_duration").map(String::as_str),
        form.get("remember_custom_seconds").map(String::as_str),
    )?;
    let identity = services::generate_identity(label, password.as_bytes())?;
    let status = unlock_generated_identity(app_state, password.as_bytes(), remember_seconds)?;
    Ok(identity_created_with_session_json(
        &identity,
        &status,
        "identity generated and unlocked",
    ))
}

pub(crate) fn api_identity_import_store(
    body: &[u8],
    app_state: &GuiAppState,
) -> Result<String, String> {
    let form = parse_form(body)?;
    let label = required_form_value(&form, "label")?;
    let source_path = required_form_value(&form, "source_path")?;
    let source_password = required_form_value(&form, "source_password")?;
    let new_password = required_form_value(&form, "new_password")?;
    let confirm = required_form_value(&form, "new_password_confirm")?;
    ensure_passwords_match(new_password, confirm)?;
    let preserve_device_id = optional_bool(form.get("preserve_device_id").map(String::as_str))?;
    let remember_seconds = remember_seconds_from_form(
        form.get("remember_me").map(String::as_str),
        form.get("remember_duration").map(String::as_str),
        form.get("remember_custom_seconds").map(String::as_str),
    )?;
    let identity = services::import_identity_store_file(
        label,
        PathBuf::from(source_path),
        source_password.as_bytes(),
        new_password.as_bytes(),
        preserve_device_id,
    )?;
    let status = unlock_generated_identity(app_state, new_password.as_bytes(), remember_seconds)?;
    Ok(identity_created_with_session_json(
        &identity,
        &status,
        "encrypted identity imported and unlocked",
    ))
}

pub(crate) fn api_identity_import_backup(
    body: &[u8],
    app_state: &GuiAppState,
) -> Result<String, String> {
    let form = parse_form(body)?;
    let label = required_form_value(&form, "label")?;
    let backup_path = required_form_value(&form, "backup_path")?;
    let backup_password = required_form_value(&form, "backup_password")?;
    let identity_password = required_form_value(&form, "identity_password")?;
    let confirm = required_form_value(&form, "identity_password_confirm")?;
    ensure_passwords_match(identity_password, confirm)?;
    let preserve_device_id = optional_bool(form.get("preserve_device_id").map(String::as_str))?;
    let remember_seconds = remember_seconds_from_form(
        form.get("remember_me").map(String::as_str),
        form.get("remember_duration").map(String::as_str),
        form.get("remember_custom_seconds").map(String::as_str),
    )?;
    let policy = if preserve_device_id {
        IdentityImportPolicy::PreserveDeviceIfAllowed
    } else {
        IdentityImportPolicy::NewDevice
    };
    let identity = services::import_identity_backup_file(
        label,
        PathBuf::from(backup_path),
        backup_password.as_bytes(),
        identity_password.as_bytes(),
        policy,
    )?;
    let status =
        unlock_generated_identity(app_state, identity_password.as_bytes(), remember_seconds)?;
    Ok(identity_created_with_session_json(
        &identity,
        &status,
        "encrypted recovery backup imported and unlocked",
    ))
}

fn unlock_generated_identity(
    app_state: &GuiAppState,
    password: &[u8],
    remember_seconds: Option<u64>,
) -> Result<hydra_app_core::VaultSessionStatus, String> {
    let config = AppConfig::load_or_default()?;
    let vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let mut session = app_state.lock_identity_session()?;
    session
        .unlock_with_password_for(&vault, password, remember_seconds)
        .map_err(|error| error.to_string())
}

pub(crate) fn api_identity_switch(body: &[u8], app_state: &GuiAppState) -> Result<String, String> {
    let form = parse_form(body)?;
    let id = required_form_value(&form, "id")?;
    let config = AppConfig::load_or_default()?;
    let mut vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let identity = vault
        .switch_active_identity(id)
        .map_err(|error| error.to_string())?;
    let mut session = app_state.lock_identity_session()?;
    let _ = session.touch_active(&vault);
    let status = session.status(&vault);
    Ok(format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"message\":\"active identity switched\",",
            "\"identity\":{},",
            "\"session\":{}",
            "}}"
        ),
        identity_json(&identity),
        session_status_json(&status),
    ))
}

pub(crate) fn api_identity_unlock_session(
    body: &[u8],
    app_state: &GuiAppState,
) -> Result<String, String> {
    let form = parse_form(body)?;
    let password = required_form_value(&form, "password")?;
    let remember_seconds = remember_seconds_from_form(
        form.get("remember_me").map(String::as_str),
        form.get("remember_duration").map(String::as_str),
        form.get("remember_custom_seconds").map(String::as_str),
    )?;
    let config = AppConfig::load_or_default()?;
    let vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let mut session = app_state.lock_identity_session()?;
    let status = session
        .unlock_with_password_for(&vault, password.as_bytes(), remember_seconds)
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"message\":\"identity session unlocked in memory\",\"session\":{}}}",
        session_status_json(&status),
    ))
}

pub(crate) fn api_identity_lock_all(app_state: &GuiAppState) -> Result<String, String> {
    let status = app_state.lock_identity_session()?.lock_all();
    Ok(format!(
        "{{\"ok\":true,\"message\":\"all identities locked\",\"session\":{}}}",
        session_status_json(&status),
    ))
}

pub(crate) fn api_identity_idle_timeout(
    body: &[u8],
    app_state: &GuiAppState,
) -> Result<String, String> {
    let form = parse_form(body)?;
    let seconds = required_form_value(&form, "seconds")?.trim();
    let timeout = if seconds.is_empty() || seconds == "0" {
        None
    } else {
        Some(
            seconds
                .parse::<u64>()
                .map_err(|error| format!("identity idle timeout must be seconds: {error}"))?,
        )
    };
    let mut session = app_state.lock_identity_session()?;
    session
        .set_idle_timeout_seconds(timeout)
        .map_err(|error| error.to_string())?;
    let config = AppConfig::load_or_default()?;
    let vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let status = session.status(&vault);
    Ok(format!(
        "{{\"ok\":true,\"message\":\"identity idle timeout updated\",\"session\":{}}}",
        session_status_json(&status),
    ))
}
