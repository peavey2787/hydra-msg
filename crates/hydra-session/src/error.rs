use core::fmt;

/// Local control-flow diagnostics.
///
/// These variants are never peer-visible protocol responses. Callers must map
/// all remote-controlled receive failures to one generic externally observable
/// failure and keep detailed diagnostics rate-limited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    InvalidState,
    InvalidEnvelope,
    InvalidPayload,
    AuthenticationFailed,
    ReplayDetected,
    MessageTooOld,
    MessageTooFarAhead,
    CounterExhausted,
    SkippedKeyLimit,
    RefreshConflict,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SessionError {}

pub type SessionResult<T> = Result<T, SessionError>;
