mod config;
mod membership_private;
mod replay;
mod roster_view;
mod sender_chain;
mod snapshot;

pub use config::GroupStateConfig;
pub use membership_private::MembershipPrivateState;
pub use replay::{AcceptedGroupMessage, GroupReplayState, SenderReplayState};
pub use sender_chain::{
    SenderChainCursor, SenderChainResolution, SenderChainState, SkippedGroupMessageKey,
};
pub use snapshot::{
    GroupReplayStateSnapshot, GroupStateSnapshot, MembershipPrivateStateSnapshot,
    PrivatePathNodeSecretSnapshot, SenderChainCursorSnapshot, SenderChainStateSnapshot,
    SenderReplayStateSnapshot, SkippedGroupMessageKeySnapshot,
};

use crate::{
    validate_governance_for_roster, validate_mode_mechanism, validate_roster_for_mode,
    EpochKeyContext, GovernancePolicy, GroupError, GroupMode, GroupPhase, GroupResult, MemberId,
    MemberStatus, MembershipMechanism, ModePolicy, RosterEntry, SenderMessageStep, StateVersion,
};
use hydra_core::types::{Epoch, GroupId, Secret32};
use roster_view::{active_sender_entries, compute_roster_hash};

/// Group state stores the authenticated public state plus only the local
/// private membership state and sender/replay cursors needed by this member.
pub struct GroupState {
    pub group_id: GroupId,
    pub mode: GroupMode,
    pub mechanism: MembershipMechanism,
    pub epoch: Epoch,
    pub state_version: StateVersion,
    pub last_commit_hash: [u8; 64],
    pub previous_commit_hash: [u8; 64],
    pub roster_hash: [u8; 64],
    pub tree_hash: [u8; 64],
    pub governance_policy: GovernancePolicy,
    pub mode_policy: ModePolicy,
    pub roster: Vec<RosterEntry>,
    pub membership: MembershipPrivateState,
    pub sender_chains: SenderChainState,
    pub replay_state: GroupReplayState,
    pub phase: GroupPhase,
}

impl GroupState {
    pub fn export_snapshot(&self) -> GroupResult<GroupStateSnapshot> {
        let membership = self
            .membership
            .export_snapshot()
            .ok_or(GroupError::InvalidState)?;
        Ok(GroupStateSnapshot {
            group_id: self.group_id,
            mode: self.mode,
            mechanism: self.mechanism,
            epoch: self.epoch,
            state_version: self.state_version,
            last_commit_hash: self.last_commit_hash,
            previous_commit_hash: self.previous_commit_hash,
            roster_hash: self.roster_hash,
            tree_hash: self.tree_hash,
            governance_policy: self.governance_policy.clone(),
            mode_policy: self.mode_policy,
            roster: self.roster.clone(),
            membership,
            sender_chains: self.sender_chains.export_snapshot(),
            replay_state: self.replay_state.export_snapshot(),
            phase: self.phase,
        })
    }

    pub fn from_snapshot(snapshot: GroupStateSnapshot) -> GroupResult<Self> {
        validate_mode_mechanism(snapshot.mode, snapshot.mechanism)?;
        if !snapshot.roster.is_empty() {
            validate_roster_for_mode(snapshot.mode, snapshot.epoch, &snapshot.roster)?;
            validate_governance_for_roster(&snapshot.governance_policy, &snapshot.roster)?;
        }
        Ok(Self {
            group_id: snapshot.group_id,
            mode: snapshot.mode,
            mechanism: snapshot.mechanism,
            epoch: snapshot.epoch,
            state_version: snapshot.state_version,
            last_commit_hash: snapshot.last_commit_hash,
            previous_commit_hash: snapshot.previous_commit_hash,
            roster_hash: snapshot.roster_hash,
            tree_hash: snapshot.tree_hash,
            governance_policy: snapshot.governance_policy,
            mode_policy: snapshot.mode_policy,
            roster: snapshot.roster,
            membership: MembershipPrivateState::from_snapshot(snapshot.membership),
            sender_chains: SenderChainState::from_snapshot(snapshot.sender_chains),
            replay_state: GroupReplayState::from_snapshot(snapshot.replay_state),
            phase: snapshot.phase,
        })
    }

    pub fn new_empty(
        group_id: GroupId,
        mode: GroupMode,
        mechanism: MembershipMechanism,
        governance_policy: GovernancePolicy,
        mode_policy: ModePolicy,
    ) -> GroupResult<Self> {
        validate_mode_mechanism(mode, mechanism)?;
        Ok(Self {
            group_id,
            mode,
            mechanism,
            epoch: Epoch(0),
            state_version: StateVersion(0),
            last_commit_hash: [0; 64],
            previous_commit_hash: [0; 64],
            roster_hash: [0; 64],
            tree_hash: [0; 64],
            governance_policy,
            mode_policy,
            roster: Vec::new(),
            membership: MembershipPrivateState::Empty,
            sender_chains: SenderChainState::default(),
            replay_state: GroupReplayState::default(),
            phase: GroupPhase::Active,
        })
    }

    pub fn new_validated(config: GroupStateConfig) -> GroupResult<Self> {
        validate_mode_mechanism(config.mode, config.mechanism)?;
        validate_roster_for_mode(config.mode, config.epoch, &config.roster)?;
        validate_governance_for_roster(&config.governance_policy, &config.roster)?;
        let roster_hash = compute_roster_hash(config.mode, &config.roster)?;
        Ok(Self {
            group_id: config.group_id,
            mode: config.mode,
            mechanism: config.mechanism,
            epoch: config.epoch,
            state_version: config.state_version,
            last_commit_hash: [0; 64],
            previous_commit_hash: [0; 64],
            roster_hash,
            tree_hash: [0; 64],
            governance_policy: config.governance_policy,
            mode_policy: config.mode_policy,
            roster: config.roster,
            membership: MembershipPrivateState::Empty,
            sender_chains: SenderChainState::default(),
            replay_state: GroupReplayState::default(),
            phase: GroupPhase::Active,
        })
    }

    pub fn set_mode_and_mechanism(
        &mut self,
        mode: GroupMode,
        mechanism: MembershipMechanism,
    ) -> GroupResult<()> {
        self.require_active()?;
        validate_mode_mechanism(mode, mechanism)?;
        if !self.roster.is_empty() {
            validate_roster_for_mode(mode, self.epoch, &self.roster)?;
            validate_governance_for_roster(&self.governance_policy, &self.roster)?;
        }
        self.mode = mode;
        self.mechanism = mechanism;
        Ok(())
    }

    pub fn replace_roster(&mut self, roster: Vec<RosterEntry>) -> GroupResult<()> {
        self.require_active()?;
        validate_roster_for_mode(self.mode, self.epoch, &roster)?;
        validate_governance_for_roster(&self.governance_policy, &roster)?;
        let new_roster_hash = compute_roster_hash(self.mode, &roster)?;
        self.roster = roster;
        self.roster_hash = new_roster_hash;
        Ok(())
    }

    pub fn add_member(&mut self, entry: RosterEntry) -> GroupResult<()> {
        self.require_active()?;
        let mut candidate = self.roster.clone();
        if candidate
            .iter()
            .any(|existing| existing.member_id == entry.member_id)
        {
            return Err(GroupError::MemberAlreadyExists {
                member_id: entry.member_id,
            });
        }
        candidate.push(entry);
        self.replace_roster(candidate)
    }

    pub fn remove_member(&mut self, member_id: MemberId, removed_epoch: Epoch) -> GroupResult<()> {
        self.require_active()?;
        let mut candidate = self.roster.clone();
        let Some(entry) = candidate
            .iter_mut()
            .find(|entry| entry.member_id == member_id)
        else {
            return Err(GroupError::MemberNotFound { member_id });
        };
        if entry.status != MemberStatus::Active {
            return Err(GroupError::MemberInactive { member_id });
        }
        entry.status = MemberStatus::Removed;
        entry.removed_epoch = removed_epoch;
        self.replace_roster(candidate)
    }

    pub fn change_member_role(
        &mut self,
        member_id: MemberId,
        new_role: crate::GroupRole,
    ) -> GroupResult<()> {
        self.require_active()?;
        if !new_role.is_active_in_mode(self.mode) {
            return Err(GroupError::InvalidRoleForMode {
                mode: self.mode,
                role: new_role,
            });
        }
        let mut candidate = self.roster.clone();
        let Some(entry) = candidate
            .iter_mut()
            .find(|entry| entry.member_id == member_id)
        else {
            return Err(GroupError::MemberNotFound { member_id });
        };
        if entry.status != MemberStatus::Active {
            return Err(GroupError::MemberInactive { member_id });
        }
        entry.role = new_role;
        self.replace_roster(candidate)
    }

    pub fn require_active(&self) -> GroupResult<()> {
        if self.phase == GroupPhase::Active {
            Ok(())
        } else {
            Err(GroupError::InvalidState)
        }
    }

    pub fn require_sender(&self, member_id: MemberId) -> GroupResult<&RosterEntry> {
        self.require_active()?;
        crate::ensure_sender_allowed(self.mode, &self.roster, member_id)
    }

    pub fn epoch_key_context(&self) -> EpochKeyContext {
        EpochKeyContext {
            group_id: self.group_id,
            mode: self.mode,
            epoch: self.epoch,
            state_version: self.state_version,
            roster_hash: self.roster_hash,
            tree_hash: self.tree_hash,
            commit_hash: self.last_commit_hash,
        }
    }

    pub fn install_epoch_sender_chains(&mut self, epoch_key: &Secret32) -> GroupResult<()> {
        self.require_active()?;
        validate_roster_for_mode(self.mode, self.epoch, &self.roster)?;
        let context = self.epoch_key_context();
        let mut sender_chains = SenderChainState::default();
        let mut replay_state = GroupReplayState::default();
        sender_chains.install_epoch(&context, epoch_key, &self.roster)?;
        replay_state.install_epoch(self.mode, &self.roster)?;
        self.sender_chains.clear();
        self.sender_chains = sender_chains;
        self.replay_state = replay_state;
        Ok(())
    }

    pub fn next_sender_message_step(&mut self, sender: MemberId) -> GroupResult<SenderMessageStep> {
        self.require_sender(sender)?;
        let context = self.epoch_key_context();
        self.sender_chains.next_send_step(&context, sender)
    }

    pub fn next_sender_index(&self, sender: MemberId) -> GroupResult<u64> {
        self.require_sender(sender)?;
        self.sender_chains
            .next_index(sender)
            .ok_or(GroupError::SenderNotAllowed { member_id: sender })
    }

    pub fn mark_forked(&mut self) {
        self.membership.clear();
        self.sender_chains.clear();
        self.replay_state.clear();
        self.phase = GroupPhase::Forked;
    }

    pub fn close(&mut self) {
        self.membership.clear();
        self.sender_chains.clear();
        self.replay_state.clear();
        self.phase = GroupPhase::Closed;
    }
}

impl Drop for GroupState {
    fn drop(&mut self) {
        self.membership.clear();
        self.sender_chains.clear();
        self.replay_state.clear();
    }
}

pub(super) fn route_tag_eq(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
