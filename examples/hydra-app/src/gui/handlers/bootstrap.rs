use hydra_app_core::{current_chat_bootstrap_time_ms, ChatBootstrapInvite, IdentityVault};

use crate::config::AppConfig;

use super::{json::bootstrap_invite_json, support::optional_ttl_seconds};
use crate::gui::{
    forms::{parse_form, required_form_value},
    state::GuiAppState,
};

pub(crate) fn api_bootstrap_create(body: &[u8], app_state: &GuiAppState) -> Result<String, String> {
    let form = parse_form(body)?;
    let ttl_seconds = optional_ttl_seconds(form.get("ttl_seconds").map(String::as_str))?;
    let recipient = form
        .get("recipient_fingerprint")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let config = AppConfig::load_or_default()?;
    let vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let mut session = app_state.lock_identity_session()?;
    let material = session
        .active_public_material(&vault)
        .map_err(|error| error.to_string())?;
    let invite =
        ChatBootstrapInvite::create_from_unlocked_identity(&material, recipient, ttl_seconds)
            .map_err(|error| error.to_string())?;
    Ok(format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"message\":\"chat bootstrap invite created\",",
            "\"invite\":{}",
            "}}"
        ),
        bootstrap_invite_json(&invite),
    ))
}

pub(crate) fn api_bootstrap_accept(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let join_code = required_form_value(&form, "join_code")?;
    let config = AppConfig::load_or_default()?;
    let vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let active_fingerprint = vault
        .identities()
        .into_iter()
        .find(|identity| identity.active)
        .map(|identity| identity.identity_fingerprint_hex);
    let invite = ChatBootstrapInvite::parse_join_code(
        join_code,
        current_chat_bootstrap_time_ms(),
        active_fingerprint.as_deref(),
    )
    .map_err(|error| error.to_string())?;
    Ok(format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"message\":\"chat bootstrap payload accepted for review\",",
            "\"invite\":{}",
            "}}"
        ),
        bootstrap_invite_json(&invite),
    ))
}
