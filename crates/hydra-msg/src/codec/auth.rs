use super::{exact_array_from_vec, hex_decode, hex_encode, required_field};
use crate::{
    HydraAnonymousAuthNullifier, HydraAnonymousAuthPolicy, HydraMsgError, HydraResult,
    AUTH_TOKEN_MAGIC,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

pub(crate) struct ParsedAnonymousAuthToken {
    pub(crate) policy: HydraAnonymousAuthPolicy,
    pub(crate) nonce: [u8; 32],
    pub(crate) tag: [u8; 32],
}

pub(crate) fn encode_anonymous_auth_token(
    policy: &HydraAnonymousAuthPolicy,
    nonce: [u8; 32],
    tag: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(AUTH_TOKEN_MAGIC.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"scope\t");
    out.extend_from_slice(hex_encode(policy.scope.as_bytes()).as_bytes());
    out.extend_from_slice(b"\naction\t");
    out.extend_from_slice(hex_encode(policy.action.as_bytes()).as_bytes());
    out.extend_from_slice(b"\nexpires_at\t");
    match policy.expires_at_unix_seconds {
        Some(expires_at) => out.extend_from_slice(expires_at.to_string().as_bytes()),
        None => out.extend_from_slice(b"none"),
    }
    out.extend_from_slice(b"\nnonce\t");
    out.extend_from_slice(hex_encode(&nonce).as_bytes());
    out.extend_from_slice(b"\ntag\t");
    out.extend_from_slice(hex_encode(&tag).as_bytes());
    out.push(b'\n');
    out
}

pub(crate) fn decode_anonymous_auth_token(bytes: &[u8]) -> HydraResult<ParsedAnonymousAuthToken> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("anonymous auth token utf-8"))?;
    let mut lines = text.lines();
    let magic = lines
        .next()
        .ok_or(HydraMsgError::InvalidEncoding("anonymous auth token magic"))?;
    if magic != AUTH_TOKEN_MAGIC {
        return Err(HydraMsgError::InvalidEncoding("anonymous auth token magic"));
    }
    let scope = decode_string_field(required_field(
        &mut lines,
        "scope",
        "anonymous auth token scope",
    )?)?;
    let action = decode_string_field(required_field(
        &mut lines,
        "action",
        "anonymous auth token action",
    )?)?;
    let expires_at = decode_expiry(required_field(
        &mut lines,
        "expires_at",
        "anonymous auth token expiry",
    )?)?;
    let nonce = exact_array_from_vec(hex_decode(required_field(
        &mut lines,
        "nonce",
        "anonymous auth token nonce",
    )?)?)?;
    let tag = exact_array_from_vec(hex_decode(required_field(
        &mut lines,
        "tag",
        "anonymous auth token tag",
    )?)?)?;
    if lines.any(|line| !line.trim().is_empty()) {
        return Err(HydraMsgError::InvalidEncoding(
            "anonymous auth token trailing data",
        ));
    }
    Ok(ParsedAnonymousAuthToken {
        policy: HydraAnonymousAuthPolicy {
            scope,
            action,
            expires_at_unix_seconds: expires_at,
        },
        nonce,
        tag,
    })
}

pub(crate) fn anonymous_auth_token_tag(
    issuer_secret: &SecretBytes<32>,
    policy: &HydraAnonymousAuthPolicy,
    nonce: &[u8; 32],
) -> [u8; 32] {
    RustCryptoBackend::hmac_sha3_256(issuer_secret, &anonymous_auth_mac_input(policy, nonce))
}

pub(crate) fn verify_anonymous_auth_token_tag(
    issuer_secret: &SecretBytes<32>,
    token: &ParsedAnonymousAuthToken,
) -> HydraResult<()> {
    RustCryptoBackend::verify_hmac_sha3_256(
        issuer_secret,
        &anonymous_auth_mac_input(&token.policy, &token.nonce),
        &token.tag,
    )?;
    Ok(())
}

pub(crate) fn anonymous_auth_token_nullifier(
    issuer_secret: &SecretBytes<32>,
    token: &ParsedAnonymousAuthToken,
) -> HydraAnonymousAuthNullifier {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/facade/anonymous-auth/nullifier\0");
    input.extend_from_slice(&token.nonce);
    input.extend_from_slice(&token.tag);
    HydraAnonymousAuthNullifier(RustCryptoBackend::hmac_sha3_256(issuer_secret, &input))
}

fn anonymous_auth_mac_input(policy: &HydraAnonymousAuthPolicy, nonce: &[u8; 32]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/facade/anonymous-auth/token\0");
    write_field(&mut input, policy.scope.as_bytes());
    write_field(&mut input, policy.action.as_bytes());
    match policy.expires_at_unix_seconds {
        Some(expires_at) => input.extend_from_slice(&expires_at.to_be_bytes()),
        None => input.extend_from_slice(&0_u64.to_be_bytes()),
    }
    input.extend_from_slice(nonce);
    input
}

fn write_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn decode_string_field(value: &str) -> HydraResult<String> {
    String::from_utf8(hex_decode(value)?)
        .map_err(|_| HydraMsgError::InvalidEncoding("anonymous auth token text"))
}

fn decode_expiry(value: &str) -> HydraResult<Option<u64>> {
    if value == "none" {
        return Ok(None);
    }
    Ok(Some(
        value
            .parse()
            .map_err(|_| HydraMsgError::InvalidEncoding("anonymous auth token expiry"))?,
    ))
}

pub(crate) fn encode_anonymous_auth_secret(secret: &SecretBytes<32>) -> String {
    hex_encode(secret.expose_secret())
}

pub(crate) fn decode_anonymous_auth_secret(value: &str) -> HydraResult<SecretBytes<32>> {
    Ok(SecretBytes::from_array(exact_array_from_vec(hex_decode(value)?)?))
}

pub(crate) fn encode_anonymous_auth_spent(nullifier: HydraAnonymousAuthNullifier) -> String {
    nullifier.hex()
}

pub(crate) fn decode_anonymous_auth_spent(value: &str) -> HydraResult<HydraAnonymousAuthNullifier> {
    Ok(HydraAnonymousAuthNullifier(exact_array_from_vec(hex_decode(value)?)?))
}
