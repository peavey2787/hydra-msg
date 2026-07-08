use hydra_app_core::ChatBootstrapInvite;

use super::scalar::optional_string_json;
use crate::gui::encoding::json_escape;

pub(crate) fn bootstrap_invite_json(invite: &ChatBootstrapInvite) -> String {
    format!(
        concat!(
            "{{",
            "\"inviter_label\":\"{}\",",
            "\"public_key_hex\":\"{}\",",
            "\"identity_fingerprint_hex\":\"{}\",",
            "\"device_id_hex\":\"{}\",",
            "\"device_fingerprint_hex\":\"{}\",",
            "\"mailbox_hint\":\"{}\",",
            "\"recipient_fingerprint_hex\":{},",
            "\"created_at_ms\":{},",
            "\"expires_at_ms\":{},",
            "\"context_binding_hex\":\"{}\",",
            "\"safety_number\":\"{}\",",
            "\"join_code\":\"{}\"",
            "}}"
        ),
        json_escape(&invite.inviter_label),
        json_escape(&invite.public_key_hex),
        json_escape(&invite.identity_fingerprint_hex),
        json_escape(&invite.device_id_hex),
        json_escape(&invite.device_fingerprint_hex),
        json_escape(&invite.mailbox_hint),
        optional_string_json(invite.recipient_fingerprint_hex.as_deref()),
        invite.created_at_ms,
        invite.expires_at_ms,
        json_escape(&invite.context_binding_hex),
        json_escape(&invite.safety_number),
        json_escape(&invite.to_join_code()),
    )
}
