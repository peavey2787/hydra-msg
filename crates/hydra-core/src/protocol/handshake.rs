use crate::types::{HandshakeMessageType, SessionStateType};
use crate::{HydraError, HydraResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeStep {
    pub message_type: HandshakeMessageType,
    pub from_state: SessionStateType,
    pub to_state: SessionStateType,
}

pub fn validate_transition(from: SessionStateType, to: SessionStateType) -> HydraResult<()> {
    let ok = matches!(
        (from, to),
        (SessionStateType::Init, SessionStateType::Responded)
            | (SessionStateType::Init, SessionStateType::Established)
            | (SessionStateType::Responded, SessionStateType::Established)
            | (SessionStateType::Established, SessionStateType::Rotating)
            | (SessionStateType::Rotating, SessionStateType::Established)
            | (_, SessionStateType::Closed)
    );

    ok.then_some(()).ok_or(HydraError::IllegalStateTransition)
}
