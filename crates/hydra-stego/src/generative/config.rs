use crate::{frame, StegoError};

const MAX_COVER_BYTES: usize = 128 * 1024 * 1024;

/// Deterministic settings shared by the three model-backed profiles.
///
/// The expected model fingerprint is mandatory so production integrations
/// cannot silently bind to whichever model happens to be available at runtime.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelConfig {
    pub prompt: String,
    pub candidate_count: usize,
    pub temperature: f64,
    pub maximum_payload_bytes: usize,
    pub maximum_finish_tokens: usize,
    pub maximum_cover_tokens: usize,
    pub maximum_cover_bytes: usize,
    pub expected_fingerprint: String,
}

impl ModelConfig {
    /// Creates a configuration pinned to one exact model/runtime fingerprint.
    pub fn new(expected_fingerprint: impl Into<String>) -> Self {
        Self {
            prompt: "A private, casual conversation between two longtime friends. Alex says:"
                .to_owned(),
            candidate_count: 32,
            temperature: 1.0,
            maximum_payload_bytes: frame::MAX_PAYLOAD_BYTES,
            maximum_finish_tokens: 8,
            maximum_cover_tokens: 128 * 1024,
            maximum_cover_bytes: 16 * 1024 * 1024,
            expected_fingerprint: expected_fingerprint.into(),
        }
    }
}

pub(crate) fn validate(config: &ModelConfig) -> Result<(), StegoError> {
    if config.prompt.trim().is_empty() || config.prompt.len() > 64 * 1024 {
        return Err(StegoError::InvalidConfig(
            "model prompt must be non-empty and at most 64 KiB",
        ));
    }
    if config.expected_fingerprint.trim().is_empty() || config.expected_fingerprint.len() > 1024 {
        return Err(StegoError::InvalidConfig(
            "expected model fingerprint must be non-empty and at most 1024 bytes",
        ));
    }
    if !(2..=4096).contains(&config.candidate_count) {
        return Err(StegoError::InvalidConfig(
            "candidate count must be from 2 through 4096",
        ));
    }
    if !config.temperature.is_finite() || !(0.1..=2.0).contains(&config.temperature) {
        return Err(StegoError::InvalidConfig(
            "temperature must be finite and from 0.1 through 2.0",
        ));
    }
    if !(1..=frame::MAX_PAYLOAD_BYTES).contains(&config.maximum_payload_bytes) {
        return Err(StegoError::InvalidConfig(
            "maximum payload must be from 1 byte through 64 KiB",
        ));
    }
    if config.maximum_finish_tokens > 128 {
        return Err(StegoError::InvalidConfig(
            "maximum finish tokens must not exceed 128",
        ));
    }
    if !(1..=4 * 1024 * 1024).contains(&config.maximum_cover_tokens) {
        return Err(StegoError::InvalidConfig(
            "maximum cover tokens must be from 1 through 4,194,304",
        ));
    }
    if !(1..=MAX_COVER_BYTES).contains(&config.maximum_cover_bytes) {
        return Err(StegoError::InvalidConfig(
            "maximum cover bytes must be from 1 through 134,217,728",
        ));
    }
    Ok(())
}
