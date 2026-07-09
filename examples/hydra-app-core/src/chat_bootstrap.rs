use hydra_core::{types::IdentityPublicKey, ML_DSA_65_VK_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

use crate::{
    identity_vault::UnlockedIdentityPublicMaterial, AppError, AppResult, DeviceFingerprint,
    DeviceId, PublicIdentity,
};

pub const CHAT_BOOTSTRAP_PREFIX: &str = "hydra-msg-chat";
pub const DEFAULT_INVITE_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const MIN_INVITE_TTL_SECONDS: u64 = 60;
pub const MAX_INVITE_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const MAX_JOIN_CODE_LEN: usize = 8_192;

const CONTEXT_LABEL: &[u8] = b"HYDRA-MSG/app/chat-bootstrap/context";
const SAFETY_LABEL: &[u8] = b"HYDRA-MSG/app/chat-bootstrap/safety";
const MAILBOX_LABEL: &[u8] = b"HYDRA-MSG/app/chat-bootstrap/mailbox";
const MAX_LABEL_LEN: usize = 96;

#[derive(Clone, Copy)]
struct BootstrapFields<'a> {
    inviter_label: &'a str,
    public_key_hex: &'a str,
    identity_fingerprint_hex: &'a str,
    device_id_hex: &'a str,
    device_fingerprint_hex: &'a str,
    mailbox_hint: &'a str,
    recipient_fingerprint_hex: Option<&'a str>,
    created_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatBootstrapInvite {
    pub inviter_label: String,
    pub public_key_hex: String,
    pub identity_fingerprint_hex: String,
    pub device_id_hex: String,
    pub device_fingerprint_hex: String,
    pub mailbox_hint: String,
    pub recipient_fingerprint_hex: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub context_binding_hex: String,
    pub safety_number: String,
}

impl ChatBootstrapInvite {
    pub fn create_for_public_identity(
        inviter_label: &str,
        public_identity: &PublicIdentity,
        device_id: DeviceId,
        device_fingerprint: DeviceFingerprint,
        recipient_fingerprint_hex: Option<&str>,
        ttl_seconds: u64,
    ) -> AppResult<Self> {
        let public_key_hex = encode_hex(&public_identity.public_key().0);
        let identity_fingerprint_hex = encode_hex(&public_identity.fingerprint().0);
        let device_id_hex = encode_hex(&device_id.0);
        let device_fingerprint_hex = encode_hex(&device_fingerprint.0);
        Self::create_from_public_fields(
            inviter_label,
            &public_key_hex,
            &identity_fingerprint_hex,
            &device_id_hex,
            &device_fingerprint_hex,
            recipient_fingerprint_hex,
            ttl_seconds,
        )
    }

    pub fn create_from_unlocked_identity(
        material: &UnlockedIdentityPublicMaterial,
        recipient_fingerprint_hex: Option<&str>,
        ttl_seconds: u64,
    ) -> AppResult<Self> {
        Self::create_from_public_fields(
            &material.label,
            &material.public_key_hex,
            &material.identity_fingerprint_hex,
            &material.device_id_hex,
            &material.device_fingerprint_hex,
            recipient_fingerprint_hex,
            ttl_seconds,
        )
    }

    pub fn create_from_public_fields(
        inviter_label: &str,
        public_key_hex: &str,
        identity_fingerprint_hex: &str,
        device_id_hex: &str,
        device_fingerprint_hex: &str,
        recipient_fingerprint_hex: Option<&str>,
        ttl_seconds: u64,
    ) -> AppResult<Self> {
        validate_label(inviter_label)?;
        validate_ttl_seconds(ttl_seconds)?;
        validate_public_key_hex(public_key_hex)?;
        validate_hex_32(identity_fingerprint_hex, "identity fingerprint")?;
        validate_hex_32(device_id_hex, "device id")?;
        validate_hex_32(device_fingerprint_hex, "device fingerprint")?;
        let public_identity = public_identity_from_hex(public_key_hex)?;
        let derived_fingerprint = encode_hex(&public_identity.fingerprint().0);
        if derived_fingerprint != identity_fingerprint_hex {
            return Err(AppError::InvalidInput(
                "chat bootstrap public key does not match identity fingerprint",
            ));
        }
        let recipient = normalize_recipient(recipient_fingerprint_hex)?;
        let created_at_ms = current_time_ms();
        let ttl_ms = ttl_seconds
            .checked_mul(1_000)
            .ok_or(AppError::InvalidInput("chat bootstrap ttl is too large"))?;
        let expires_at_ms = created_at_ms
            .checked_add(ttl_ms)
            .ok_or(AppError::InvalidInput("chat bootstrap expiry overflows"))?;
        let mailbox_hint = derive_mailbox_hint(identity_fingerprint_hex, device_id_hex);
        Self::assemble(BootstrapFields {
            inviter_label,
            public_key_hex,
            identity_fingerprint_hex,
            device_id_hex,
            device_fingerprint_hex,
            mailbox_hint: &mailbox_hint,
            recipient_fingerprint_hex: recipient.as_deref(),
            created_at_ms,
            expires_at_ms,
        })
    }

    #[must_use]
    pub fn to_join_code(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            CHAT_BOOTSTRAP_PREFIX,
            encode_field(&self.inviter_label),
            self.public_key_hex,
            self.identity_fingerprint_hex,
            self.device_id_hex,
            self.device_fingerprint_hex,
            self.mailbox_hint,
            self.recipient_fingerprint_hex.as_deref().unwrap_or(""),
            self.created_at_ms,
            self.expires_at_ms,
            self.context_binding_hex,
            self.safety_number,
        )
    }

    pub fn parse_join_code(
        join_code: &str,
        now_ms: u64,
        local_recipient_fingerprint_hex: Option<&str>,
    ) -> AppResult<Self> {
        let code = join_code.trim();
        if code.is_empty() {
            return Err(AppError::InvalidInput("chat bootstrap join code is empty"));
        }
        if code.len() > MAX_JOIN_CODE_LEN {
            return Err(AppError::InvalidInput(
                "chat bootstrap join code is too long",
            ));
        }
        let parts = code.split('|').collect::<Vec<_>>();
        if parts.len() != 12 || parts[0] != CHAT_BOOTSTRAP_PREFIX {
            return Err(AppError::InvalidInput(
                "chat bootstrap join code is malformed",
            ));
        }
        let inviter_label = decode_field(parts[1])?;
        let recipient = normalize_recipient(if parts[7].is_empty() {
            None
        } else {
            Some(parts[7])
        })?;
        let created_at_ms = parse_u64(parts[8], "chat bootstrap created time is invalid")?;
        let expires_at_ms = parse_u64(parts[9], "chat bootstrap expiry is invalid")?;
        if expires_at_ms <= created_at_ms {
            return Err(AppError::InvalidInput("chat bootstrap expiry is invalid"));
        }
        if now_ms >= expires_at_ms {
            return Err(AppError::InvalidInput("chat bootstrap invite is expired"));
        }
        if let Some(recipient_fingerprint) = recipient.as_deref() {
            let local = local_recipient_fingerprint_hex.ok_or(AppError::InvalidInput(
                "chat bootstrap invite is for another recipient",
            ))?;
            validate_hex_32(local, "local recipient fingerprint")?;
            if !recipient_fingerprint.eq_ignore_ascii_case(local) {
                return Err(AppError::InvalidInput(
                    "chat bootstrap invite is for another recipient",
                ));
            }
        }
        let invite = Self::assemble(BootstrapFields {
            inviter_label: &inviter_label,
            public_key_hex: parts[2],
            identity_fingerprint_hex: parts[3],
            device_id_hex: parts[4],
            device_fingerprint_hex: parts[5],
            mailbox_hint: parts[6],
            recipient_fingerprint_hex: recipient.as_deref(),
            created_at_ms,
            expires_at_ms,
        })?;
        if invite.context_binding_hex != parts[10] {
            return Err(AppError::InvalidInput(
                "chat bootstrap context binding is invalid",
            ));
        }
        if invite.safety_number != parts[11] {
            return Err(AppError::InvalidInput(
                "chat bootstrap safety number is invalid",
            ));
        }
        Ok(invite)
    }

    fn assemble(fields: BootstrapFields<'_>) -> AppResult<Self> {
        validate_label(fields.inviter_label)?;
        validate_public_key_hex(fields.public_key_hex)?;
        validate_hex_32(fields.identity_fingerprint_hex, "identity fingerprint")?;
        validate_hex_32(fields.device_id_hex, "device id")?;
        validate_hex_32(fields.device_fingerprint_hex, "device fingerprint")?;
        validate_mailbox_hint(fields.mailbox_hint)?;
        let recipient = normalize_recipient(fields.recipient_fingerprint_hex)?;
        let expected_mailbox =
            derive_mailbox_hint(fields.identity_fingerprint_hex, fields.device_id_hex);
        if expected_mailbox != fields.mailbox_hint {
            return Err(AppError::InvalidInput(
                "chat bootstrap mailbox binding is invalid",
            ));
        }
        let public_identity = public_identity_from_hex(fields.public_key_hex)?;
        let derived_fingerprint = encode_hex(&public_identity.fingerprint().0);
        if derived_fingerprint != fields.identity_fingerprint_hex {
            return Err(AppError::InvalidInput(
                "chat bootstrap public key does not match identity fingerprint",
            ));
        }
        let binding_fields = BootstrapFields {
            recipient_fingerprint_hex: recipient.as_deref(),
            ..fields
        };
        let context_binding_hex = context_binding_hex(&binding_fields);
        let safety_number = safety_number(&binding_fields, &context_binding_hex);
        Ok(Self {
            inviter_label: fields.inviter_label.to_owned(),
            public_key_hex: fields.public_key_hex.to_ascii_lowercase(),
            identity_fingerprint_hex: fields.identity_fingerprint_hex.to_ascii_lowercase(),
            device_id_hex: fields.device_id_hex.to_ascii_lowercase(),
            device_fingerprint_hex: fields.device_fingerprint_hex.to_ascii_lowercase(),
            mailbox_hint: fields.mailbox_hint.to_owned(),
            recipient_fingerprint_hex: recipient,
            created_at_ms: fields.created_at_ms,
            expires_at_ms: fields.expires_at_ms,
            context_binding_hex,
            safety_number,
        })
    }
}

#[must_use]
pub fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn context_binding_hex(fields: &BootstrapFields<'_>) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(CONTEXT_LABEL);
    append_field(&mut input, fields.inviter_label.as_bytes());
    append_field(
        &mut input,
        fields.public_key_hex.to_ascii_lowercase().as_bytes(),
    );
    append_field(
        &mut input,
        fields
            .identity_fingerprint_hex
            .to_ascii_lowercase()
            .as_bytes(),
    );
    append_field(
        &mut input,
        fields.device_id_hex.to_ascii_lowercase().as_bytes(),
    );
    append_field(
        &mut input,
        fields
            .device_fingerprint_hex
            .to_ascii_lowercase()
            .as_bytes(),
    );
    append_field(&mut input, fields.mailbox_hint.as_bytes());
    append_field(
        &mut input,
        fields
            .recipient_fingerprint_hex
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_bytes(),
    );
    append_field(&mut input, fields.created_at_ms.to_string().as_bytes());
    append_field(&mut input, fields.expires_at_ms.to_string().as_bytes());
    encode_hex(&RustCryptoBackend::sha3_256(&input))
}

fn safety_number(fields: &BootstrapFields<'_>, context_binding_hex: &str) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(SAFETY_LABEL);
    append_field(
        &mut input,
        fields.public_key_hex.to_ascii_lowercase().as_bytes(),
    );
    append_field(
        &mut input,
        fields
            .identity_fingerprint_hex
            .to_ascii_lowercase()
            .as_bytes(),
    );
    append_field(
        &mut input,
        fields.device_id_hex.to_ascii_lowercase().as_bytes(),
    );
    append_field(
        &mut input,
        fields
            .device_fingerprint_hex
            .to_ascii_lowercase()
            .as_bytes(),
    );
    append_field(
        &mut input,
        fields
            .recipient_fingerprint_hex
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_bytes(),
    );
    append_field(&mut input, context_binding_hex.as_bytes());
    let digest = RustCryptoBackend::sha3_256(&input);
    let mut groups = Vec::with_capacity(8);
    for chunk in digest[..20].chunks_exact(5) {
        let value = u64::from_be_bytes([0, 0, 0, chunk[0], chunk[1], chunk[2], chunk[3], chunk[4]])
            % 100_000;
        groups.push(format!("{value:05}"));
    }
    groups.join("-")
}

fn append_field(input: &mut Vec<u8>, field: &[u8]) {
    input.extend_from_slice(&(field.len() as u64).to_be_bytes());
    input.extend_from_slice(field);
}

fn derive_mailbox_hint(identity_fingerprint_hex: &str, device_id_hex: &str) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(MAILBOX_LABEL);
    append_field(
        &mut input,
        identity_fingerprint_hex.to_ascii_lowercase().as_bytes(),
    );
    append_field(&mut input, device_id_hex.to_ascii_lowercase().as_bytes());
    encode_hex(&RustCryptoBackend::sha3_256(&input))[..16].to_owned()
}

fn normalize_recipient(value: Option<&str>) -> AppResult<Option<String>> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => {
            validate_hex_32(value, "recipient fingerprint")?;
            Ok(Some(value.to_ascii_lowercase()))
        }
        None => Ok(None),
    }
}

fn validate_ttl_seconds(ttl_seconds: u64) -> AppResult<()> {
    if !(MIN_INVITE_TTL_SECONDS..=MAX_INVITE_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(AppError::InvalidInput(
            "chat bootstrap ttl is outside allowed range",
        ));
    }
    Ok(())
}

fn validate_label(label: &str) -> AppResult<()> {
    let label = label.trim();
    if label.is_empty() {
        return Err(AppError::InvalidInput(
            "chat bootstrap label must not be empty",
        ));
    }
    if label.len() > MAX_LABEL_LEN
        || label.contains('|')
        || label.contains('\n')
        || label.contains('\r')
        || label.contains('\t')
    {
        return Err(AppError::InvalidInput("chat bootstrap label is invalid"));
    }
    Ok(())
}

fn validate_public_key_hex(value: &str) -> AppResult<()> {
    if value.len() == ML_DSA_65_VK_SIZE * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AppError::InvalidInput(
            "chat bootstrap public key is invalid",
        ))
    }
}

fn validate_hex_32(value: &str, _name: &'static str) -> AppResult<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AppError::InvalidInput(
            "chat bootstrap hex field is invalid",
        ))
    }
}

fn validate_mailbox_hint(value: &str) -> AppResult<()> {
    if value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AppError::InvalidInput(
            "chat bootstrap mailbox hint is invalid",
        ))
    }
}

fn public_identity_from_hex(hex: &str) -> AppResult<PublicIdentity> {
    let bytes = decode_hex(hex)?;
    let array: [u8; ML_DSA_65_VK_SIZE] = bytes
        .try_into()
        .map_err(|_| AppError::InvalidInput("chat bootstrap public key length is invalid"))?;
    PublicIdentity::from_public_key(IdentityPublicKey(array))
}

fn parse_u64(value: &str, message: &'static str) -> AppResult<u64> {
    value
        .parse::<u64>()
        .map_err(|_| AppError::InvalidInput(message))
}

fn encode_field(value: &str) -> String {
    encode_hex(value.as_bytes())
}

fn decode_field(value: &str) -> AppResult<String> {
    String::from_utf8(decode_hex(value)?)
        .map_err(|_| AppError::InvalidInput("chat bootstrap label is not UTF-8"))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(hex: &str) -> AppResult<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(AppError::InvalidInput("chat bootstrap hex has odd length"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        out.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> AppResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AppError::InvalidInput(
            "chat bootstrap hex has invalid character",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppIdentity;

    fn invite(ttl_seconds: u64) -> ChatBootstrapInvite {
        let identity = AppIdentity::generate().unwrap();
        ChatBootstrapInvite::create_for_public_identity(
            "Alice",
            &identity.public_identity(),
            DeviceId([7; 32]),
            DeviceFingerprint([9; 32]),
            None,
            ttl_seconds,
        )
        .unwrap()
    }

    #[test]
    fn join_code_round_trips_public_bootstrap_payload() {
        let invite = invite(DEFAULT_INVITE_TTL_SECONDS);
        let code = invite.to_join_code();
        let parsed =
            ChatBootstrapInvite::parse_join_code(&code, invite.created_at_ms, None).unwrap();
        assert_eq!(parsed, invite);
        assert!(!code.contains("password"));
        assert!(!code.contains("secret"));
        assert!(!code.contains("private"));
    }

    #[test]
    fn malformed_and_tampered_join_codes_are_rejected() {
        let invite = invite(DEFAULT_INVITE_TTL_SECONDS);
        assert!(ChatBootstrapInvite::parse_join_code(
            "not-a-hydra-code",
            invite.created_at_ms,
            None
        )
        .is_err());
        let mut parts = invite
            .to_join_code()
            .split('|')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        parts[10] = "00".repeat(32);
        assert!(
            ChatBootstrapInvite::parse_join_code(&parts.join("|"), invite.created_at_ms, None)
                .is_err()
        );
    }

    #[test]
    fn expired_invites_are_rejected() {
        let invite = invite(MIN_INVITE_TTL_SECONDS);
        assert!(ChatBootstrapInvite::parse_join_code(
            &invite.to_join_code(),
            invite.expires_at_ms,
            None
        )
        .is_err());
        assert!(ChatBootstrapInvite::parse_join_code(
            &invite.to_join_code(),
            invite.expires_at_ms - 1,
            None
        )
        .is_ok());
    }

    #[test]
    fn recipient_bound_invites_reject_wrong_recipient() {
        let identity = AppIdentity::generate().unwrap();
        let recipient = "11".repeat(32);
        let invite = ChatBootstrapInvite::create_for_public_identity(
            "Alice",
            &identity.public_identity(),
            DeviceId([1; 32]),
            DeviceFingerprint([2; 32]),
            Some(&recipient),
            DEFAULT_INVITE_TTL_SECONDS,
        )
        .unwrap();
        assert!(ChatBootstrapInvite::parse_join_code(
            &invite.to_join_code(),
            invite.created_at_ms,
            Some(&recipient)
        )
        .is_ok());
        assert!(ChatBootstrapInvite::parse_join_code(
            &invite.to_join_code(),
            invite.created_at_ms,
            Some(&"22".repeat(32))
        )
        .is_err());
    }

    #[test]
    fn ttl_boundaries_are_explicit() {
        let identity = AppIdentity::generate().unwrap();
        let public = identity.public_identity();
        assert!(ChatBootstrapInvite::create_for_public_identity(
            "Alice",
            &public,
            DeviceId([1; 32]),
            DeviceFingerprint([2; 32]),
            None,
            MIN_INVITE_TTL_SECONDS - 1,
        )
        .is_err());
        assert!(ChatBootstrapInvite::create_for_public_identity(
            "Alice",
            &public,
            DeviceId([1; 32]),
            DeviceFingerprint([2; 32]),
            None,
            MIN_INVITE_TTL_SECONDS,
        )
        .is_ok());
        assert!(ChatBootstrapInvite::create_for_public_identity(
            "Alice",
            &public,
            DeviceId([1; 32]),
            DeviceFingerprint([2; 32]),
            None,
            MAX_INVITE_TTL_SECONDS,
        )
        .is_ok());
        assert!(ChatBootstrapInvite::create_for_public_identity(
            "Alice",
            &public,
            DeviceId([1; 32]),
            DeviceFingerprint([2; 32]),
            None,
            MAX_INVITE_TTL_SECONDS + 1,
        )
        .is_err());
    }
}
