use std::path::PathBuf;

use hydra_app_core::{
    IdentityVault, VaultIdentitySummary, DEFAULT_INVITE_TTL_SECONDS, MAX_INVITE_TTL_SECONDS,
    MIN_INVITE_TTL_SECONDS,
};

use crate::config::AppConfig;

use super::super::state::GuiAppState;

pub(crate) fn require_active_identity_unlocked(
    app_state: &GuiAppState,
) -> Result<VaultIdentitySummary, String> {
    let config = AppConfig::load_or_default()?;
    let vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let status = app_state.lock_identity_session()?.status(&vault);
    if !status.active_identity_unlocked {
        return Err("unlock the active identity in Security before using chat actions".to_owned());
    }
    vault
        .identities()
        .into_iter()
        .find(|identity| identity.active)
        .ok_or_else(|| "active identity is missing".to_owned())
}

pub(crate) fn optional_ttl_seconds(value: Option<&str>) -> Result<u64, String> {
    let text = value.map(str::trim).unwrap_or("");
    if text.is_empty() || text == "0" {
        return Ok(DEFAULT_INVITE_TTL_SECONDS);
    }
    let seconds = text
        .parse::<u64>()
        .map_err(|error| format!("join-code ttl must be seconds: {error}"))?;
    if !(MIN_INVITE_TTL_SECONDS..=MAX_INVITE_TTL_SECONDS).contains(&seconds) {
        return Err(format!(
            "join-code ttl must be between {MIN_INVITE_TTL_SECONDS} and {MAX_INVITE_TTL_SECONDS} seconds"
        ));
    }
    Ok(seconds)
}

pub(crate) fn parse_checkpoint_paths(value: &str) -> Vec<PathBuf> {
    value
        .split(['\n', '\r', ';', ','])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(PathBuf::from)
        .collect()
}

pub(crate) fn ensure_passwords_match(password: &str, confirm: &str) -> Result<(), String> {
    if password == confirm {
        Ok(())
    } else {
        Err("password confirmation does not match".to_owned())
    }
}

pub(crate) fn optional_bool(value: Option<&str>) -> Result<bool, String> {
    match value.map(str::trim).unwrap_or("") {
        "" | "false" | "0" | "no" | "off" => Ok(false),
        "true" | "1" | "yes" | "on" => Ok(true),
        _ => Err("boolean field must be true or false".to_owned()),
    }
}
pub(crate) fn remember_seconds_from_form(
    remember_me: Option<&str>,
    duration: Option<&str>,
    custom_seconds: Option<&str>,
) -> Result<Option<u64>, String> {
    if !optional_bool(remember_me)? {
        return Ok(None);
    }
    match duration.map(str::trim).unwrap_or("session") {
        "" | "session" | "forever" => Ok(None),
        "24h" => Ok(Some(24 * 60 * 60)),
        "1w" => Ok(Some(7 * 24 * 60 * 60)),
        "1m" => Ok(Some(30 * 24 * 60 * 60)),
        "1y" => Ok(Some(365 * 24 * 60 * 60)),
        "custom" => {
            let text = custom_seconds.map(str::trim).unwrap_or("");
            if text.is_empty() {
                return Err("custom remember-me duration requires seconds".to_owned());
            }
            let seconds = text
                .parse::<u64>()
                .map_err(|error| format!("custom remember-me duration must be seconds: {error}"))?;
            if seconds == 0 || seconds > 365 * 24 * 60 * 60 {
                return Err("custom remember-me duration must be between 1 second and 1 year".to_owned());
            }
            Ok(Some(seconds))
        }
        _ => Err("remember-me duration must be session, 24h, 1w, 1m, 1y, forever, or custom".to_owned()),
    }
}
