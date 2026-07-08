use hydra_app_core::{
    current_chat_bootstrap_time_ms, ChatBootstrapInvite, UnlockedIdentityPublicMaterial,
};

use super::{context::AppContext, identity::active_identity_public_material};

pub fn create_bootstrap_invite_from_material(
    material: &UnlockedIdentityPublicMaterial,
    ttl_seconds: u64,
    recipient: Option<&str>,
) -> Result<ChatBootstrapInvite, String> {
    ChatBootstrapInvite::create_from_unlocked_identity(material, recipient, ttl_seconds)
        .map_err(|error| error.to_string())
}

pub fn create_bootstrap_invite(
    identity_password: &[u8],
    ttl_seconds: u64,
    recipient: Option<&str>,
) -> Result<ChatBootstrapInvite, String> {
    let material = active_identity_public_material(identity_password)?;
    create_bootstrap_invite_from_material(&material, ttl_seconds, recipient)
}

pub fn review_bootstrap_join_code(join_code: &str) -> Result<ChatBootstrapInvite, String> {
    let context = AppContext::load()?;
    let vault = context.vault()?;
    let active_fingerprint = vault
        .identities()
        .into_iter()
        .find(|identity| identity.active)
        .map(|identity| identity.identity_fingerprint_hex);
    ChatBootstrapInvite::parse_join_code(
        join_code,
        current_chat_bootstrap_time_ms(),
        active_fingerprint.as_deref(),
    )
    .map_err(|error| error.to_string())
}
