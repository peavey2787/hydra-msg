//! Atomic 1:1 session ratchets, replay handling, refresh cutover, and close.

#![forbid(unsafe_code)]

mod error;
mod key_derivation;
mod ratchet;
mod refresh;
mod session;
mod skipped_keys;

pub use error::{SessionError, SessionResult};
pub use key_derivation::{derive_initial_secrets, InitialSessionSecrets};
pub use ratchet::DirectionChainSnapshot;
pub use refresh::{
    derive_refresh_candidate, ConfirmedRefresh, RefreshCandidate, RefreshRole, VerifiedRefresh,
};
pub use session::{
    Direction, OutboundMessage, ReceivedMessage, RefreshIdDecision, SessionPhase, SessionRole,
    SessionState, SessionStateSnapshot,
};
pub use skipped_keys::SkippedMessageKeySnapshot;

#[cfg(test)]
mod tests;
