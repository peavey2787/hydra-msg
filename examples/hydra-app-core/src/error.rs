use core::fmt;

use hydra_crypto::CryptoError;
use hydra_group::GroupError;
use hydra_session::SessionError;

pub type AppResult<T> = Result<T, AppError>;

/// Stable app-facing error buckets.
///
/// Apps should use this class at remote trust boundaries and avoid revealing
/// detailed local diagnostics to peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppErrorClass {
    InvalidInput,
    InvalidState,
    Authentication,
    Replay,
    TooOld,
    TooFarAhead,
    Entropy,
    Crypto,
    Session,
    Group,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppError {
    InvalidInput(&'static str),
    InvalidState(&'static str),
    EntropyUnavailable,
    Crypto(CryptoError),
    Session(SessionError),
    Group(GroupError),
}

impl AppError {
    #[must_use]
    pub const fn class(self) -> AppErrorClass {
        match self {
            Self::InvalidInput(_) => AppErrorClass::InvalidInput,
            Self::InvalidState(_) => AppErrorClass::InvalidState,
            Self::EntropyUnavailable => AppErrorClass::Entropy,
            Self::Crypto(CryptoError::AuthenticationFailed) => AppErrorClass::Authentication,
            Self::Crypto(CryptoError::EntropyUnavailable) => AppErrorClass::Entropy,
            Self::Crypto(_) => AppErrorClass::Crypto,
            Self::Session(SessionError::AuthenticationFailed) => AppErrorClass::Authentication,
            Self::Session(SessionError::ReplayDetected) => AppErrorClass::Replay,
            Self::Session(SessionError::MessageTooOld) => AppErrorClass::TooOld,
            Self::Session(SessionError::MessageTooFarAhead) => AppErrorClass::TooFarAhead,
            Self::Session(SessionError::InvalidState | SessionError::RefreshConflict) => {
                AppErrorClass::InvalidState
            }
            Self::Session(_) => AppErrorClass::Session,
            Self::Group(GroupError::AuthenticationFailed | GroupError::InvalidGroupSignature) => {
                AppErrorClass::Authentication
            }
            Self::Group(GroupError::ReplayDetected) => AppErrorClass::Replay,
            Self::Group(GroupError::MessageTooOld) => AppErrorClass::TooOld,
            Self::Group(GroupError::MessageTooFarAhead) => AppErrorClass::TooFarAhead,
            Self::Group(GroupError::InvalidState) => AppErrorClass::InvalidState,
            Self::Group(_) => AppErrorClass::Group,
        }
    }
}

impl From<CryptoError> for AppError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<SessionError> for AppError {
    fn from(value: SessionError) -> Self {
        Self::Session(value)
    }
}

impl From<GroupError> for AppError {
    fn from(value: GroupError) -> Self {
        Self::Group(value)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(formatter, "invalid app input: {field}"),
            Self::InvalidState(state) => write!(formatter, "invalid app state: {state}"),
            Self::EntropyUnavailable => formatter.write_str("operating-system entropy unavailable"),
            Self::Crypto(error) => write!(formatter, "crypto error: {error}"),
            Self::Session(error) => write!(formatter, "session error: {error}"),
            Self::Group(error) => write!(formatter, "group error: {error:?}"),
        }
    }
}

impl std::error::Error for AppError {}
