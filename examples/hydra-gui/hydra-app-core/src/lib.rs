//! Production reference-app orchestration over the public `hydra-msg` SDK.
//!
//! This crate deliberately owns no protocol, cryptographic, identity-secret,
//! contact-trust, session, lobby, replay, attachment, persistence, or backup
//! primitives. Those responsibilities remain inside `hydra-msg`. The app layer
//! owns only transient presentation state and carrier configuration.

#![forbid(unsafe_code)]
#![deny(dead_code, deprecated, unused)]

mod app;
mod carrier;
mod ui;

pub use app::{HydraApp, RoutedLobbyPacket};
pub use carrier::{CarrierConfig, CarrierKind};
pub use hydra_msg::{
    ContactId, HydraContact, HydraIdentitySummary, HydraLobby, HydraLobbyPolicy,
    HydraLobbyRoutingHint, HydraMessage, HydraMsgError, HydraOneTimeContactCard, HydraResult,
    HydraSessionStatus, HydraStorageDebugStatus, HydraStorageStatus, IdentityId, LobbyId,
    MessageId, ReceivedHydraMessage,
};
pub use ui::{
    AppUiState, ConversationRef, DisplayDirection, DisplayMessage, NotificationPreferences,
    RememberMePolicy,
};
