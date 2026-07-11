use crate::{CarrierConfig, ContactId, IdentityId, LobbyId, MessageId};
use std::collections::HashMap;

/// Conversation selected in the app shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConversationRef {
    Direct(ContactId),
    Lobby(LobbyId),
}

/// How long the app may keep an SDK identity unlocked in this process.
///
/// This is UX metadata only. Secret material remains inside `hydra-msg` and is
/// discarded immediately when the corresponding SDK lock method is called or
/// when the process exits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RememberMePolicy {
    #[default]
    Never,
    Session,
}

/// Notification preferences owned by the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationPreferences {
    pub direct_messages: bool,
    pub lobby_messages: bool,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            direct_messages: true,
            lobby_messages: true,
        }
    }
}

/// Display direction retained only for the current app process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayDirection {
    Sent,
    Received,
}

/// Presentation history entry. It contains no packet or protocol state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayMessage {
    pub conversation: ConversationRef,
    pub direction: DisplayDirection,
    pub message_id: Option<MessageId>,
    pub plaintext: Vec<u8>,
    pub attachment_count: usize,
}

/// Non-protocol state owned by the reference UI.
#[derive(Clone, Debug, Default)]
pub struct AppUiState {
    pub selected_profile: Option<IdentityId>,
    pub selected_conversation: Option<ConversationRef>,
    pub drafts: HashMap<ConversationRef, String>,
    pub remember_me: HashMap<IdentityId, RememberMePolicy>,
    pub contact_aliases: HashMap<ContactId, String>,
    pub notifications: NotificationPreferences,
    pub carrier: CarrierConfig,
    pub display_history: Vec<DisplayMessage>,
}
