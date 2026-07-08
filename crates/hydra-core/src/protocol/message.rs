use crate::types::{ContentKind, MessageIndex, SessionId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageContext {
    pub session_id: SessionId,
    pub index: MessageIndex,
    pub kind: ContentKind,
}
