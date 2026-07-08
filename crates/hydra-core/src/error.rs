use core::fmt;

/// Shared error type for foundational protocol components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydraError {
    InvalidSize { expected: usize, actual: usize },
    InvalidHeader,
    InvalidPayload,
    InvalidAuthTag,
    AuthFailure,
    ReplayDetected,
    MessageTooOld,
    MessageTooFarAhead,
    EpochMismatch { expected: u64, actual: u64 },
    IllegalStateTransition,
    UnsupportedSuite,
    CryptoBackendUnavailable,
    SerializationFailure,
    DeserializationFailure,
    NotImplemented(&'static str),
}

pub type HydraResult<T> = Result<T, HydraError>;

impl fmt::Display for HydraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for HydraError {}
