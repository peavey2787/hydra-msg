use crate::types::{Epoch, GroupId};
use crate::{HydraError, HydraResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupMessageContext {
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub message_index: u64,
}

pub fn require_epoch(expected: Epoch, actual: Epoch) -> HydraResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(HydraError::EpochMismatch {
            expected: expected.0,
            actual: actual.0,
        })
    }
}
