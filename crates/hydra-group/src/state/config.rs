use crate::{
    GovernancePolicy, GroupMode, MembershipMechanism, ModePolicy, RosterEntry, StateVersion,
};
use hydra_core::types::{Epoch, GroupId};

pub struct GroupStateConfig {
    pub group_id: GroupId,
    pub mode: GroupMode,
    pub mechanism: MembershipMechanism,
    pub epoch: Epoch,
    pub state_version: StateVersion,
    pub governance_policy: GovernancePolicy,
    pub mode_policy: ModePolicy,
    pub roster: Vec<RosterEntry>,
}
