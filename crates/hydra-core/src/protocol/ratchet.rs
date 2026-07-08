use crate::constants::{LABEL_CHAIN_STEP, LABEL_MESSAGE_KEY};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetLabels {
    pub message_key: &'static [u8],
    pub chain_step: &'static [u8],
}

#[must_use]
pub const fn labels() -> RatchetLabels {
    RatchetLabels {
        message_key: LABEL_MESSAGE_KEY,
        chain_step: LABEL_CHAIN_STEP,
    }
}
