use crate::private_path::PrivatePath;
use crate::public_tree::PublicTree;
use crate::{
    derive_sender_chain_key, derive_sender_message_step, roster_hash, sender_chain_commitment,
    validate_governance_for_roster, validate_mode_mechanism, validate_roster_for_mode,
    EpochKeyContext, GovernancePolicy, GroupError, GroupMode, GroupPhase, GroupResult, MemberId,
    MemberStatus, MembershipMechanism, ModePolicy, RosterEntry, SenderMessageStep, StateVersion,
};
use hydra_core::protocol::replay::{ReplayError, ReplayWindow, ReplayWindowSnapshot};
use hydra_core::types::{Epoch, GroupId, LeafIndex, Secret32};

/// Private membership material for the active group epoch.
///
/// M7.1 only models the state shape. Later M7 slices populate the TreeKEM and
/// direct-wrap secret material and install it atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivatePathNodeSecretSnapshot {
    pub node_index: u32,
    pub path_secret: [u8; 32],
    pub node_seed_d: [u8; 32],
    pub node_seed_z: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipPrivateStateSnapshot {
    TreeKem {
        public_tree: PublicTree,
        leaf_index: Option<LeafIndex>,
        path: Vec<PrivatePathNodeSecretSnapshot>,
    },
    DirectWrap {
        epoch_secret: [u8; 32],
    },
    Empty,
}

pub enum MembershipPrivateState {
    TreeKem {
        public_tree: PublicTree,
        private_path: PrivatePath,
    },
    DirectWrap {
        epoch_secret: Secret32,
    },
    Empty,
}

impl MembershipPrivateState {
    pub fn clear(&mut self) {
        let mut old = std::mem::replace(self, Self::Empty);
        old.wipe_in_place();
    }

    fn wipe_in_place(&mut self) {
        match self {
            Self::TreeKem { private_path, .. } => private_path.clear(),
            Self::DirectWrap { epoch_secret } => epoch_secret.wipe(),
            Self::Empty => {}
        }
    }

    #[must_use]
    pub const fn mechanism(&self) -> Option<MembershipMechanism> {
        match self {
            Self::TreeKem { .. } => Some(MembershipMechanism::TreeKem),
            Self::DirectWrap { .. } => Some(MembershipMechanism::DirectWrap),
            Self::Empty => None,
        }
    }

    #[must_use]
    pub fn export_snapshot(&self) -> Option<MembershipPrivateStateSnapshot> {
        match self {
            Self::TreeKem {
                public_tree,
                private_path,
            } => Some(MembershipPrivateStateSnapshot::TreeKem {
                public_tree: public_tree.clone(),
                leaf_index: private_path.leaf_index,
                path: private_path
                    .path
                    .iter()
                    .map(|node| PrivatePathNodeSecretSnapshot {
                        node_index: node.node_index,
                        path_secret: *node.path_secret.expose_for_backend(),
                        node_seed_d: *node.node_seed_d.expose_for_backend(),
                        node_seed_z: *node.node_seed_z.expose_for_backend(),
                    })
                    .collect(),
            }),
            Self::DirectWrap { epoch_secret } => Some(MembershipPrivateStateSnapshot::DirectWrap {
                epoch_secret: *epoch_secret.expose_for_backend(),
            }),
            Self::Empty => Some(MembershipPrivateStateSnapshot::Empty),
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: MembershipPrivateStateSnapshot) -> Self {
        match snapshot {
            MembershipPrivateStateSnapshot::TreeKem {
                public_tree,
                leaf_index,
                path,
            } => Self::TreeKem {
                public_tree,
                private_path: PrivatePath {
                    leaf_index,
                    path: path
                        .into_iter()
                        .map(|node| crate::PrivatePathNodeSecret {
                            node_index: node.node_index,
                            path_secret: Secret32::new(node.path_secret),
                            node_seed_d: Secret32::new(node.node_seed_d),
                            node_seed_z: Secret32::new(node.node_seed_z),
                        })
                        .collect(),
                },
            },
            MembershipPrivateStateSnapshot::DirectWrap { epoch_secret } => Self::DirectWrap {
                epoch_secret: Secret32::new(epoch_secret),
            },
            MembershipPrivateStateSnapshot::Empty => Self::Empty,
        }
    }
}

impl Drop for MembershipPrivateState {
    fn drop(&mut self) {
        self.wipe_in_place();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderChainCursorSnapshot {
    pub sender: MemberId,
    pub next_index: u64,
    pub chain_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedGroupMessageKeySnapshot {
    pub sender: MemberId,
    pub index: u64,
    pub route_tag: [u8; 16],
    pub message_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderChainStateSnapshot {
    pub senders: Vec<SenderChainCursorSnapshot>,
    pub skipped: Vec<SkippedGroupMessageKeySnapshot>,
}

pub struct SenderChainCursor {
    pub sender: MemberId,
    pub next_index: u64,
    chain_key: Secret32,
}

impl SenderChainCursor {
    pub fn new(sender: MemberId, chain_key: Secret32) -> Self {
        Self {
            sender,
            next_index: 0,
            chain_key,
        }
    }

    #[must_use]
    pub fn chain_key_commitment(&self) -> [u8; 32] {
        sender_chain_commitment(self.sender, self.next_index, &self.chain_key)
    }

    pub fn clear(&mut self) {
        self.chain_key.wipe();
        self.next_index = 0;
    }
}

impl Drop for SenderChainCursor {
    fn drop(&mut self) {
        self.clear();
    }
}

pub struct SkippedGroupMessageKey {
    pub sender: MemberId,
    pub index: u64,
    pub route_tag: [u8; 16],
    message_key: Secret32,
}

impl SkippedGroupMessageKey {
    fn from_step(step: &SenderMessageStep) -> Self {
        Self {
            sender: step.sender,
            index: step.index,
            route_tag: step.route_tag,
            message_key: Secret32::new(*step.message_key.expose_for_backend()),
        }
    }

    #[must_use]
    pub fn key_commitment(&self) -> [u8; 32] {
        sender_chain_commitment(self.sender, self.index, &self.message_key)
    }

    fn to_step(&self) -> SenderMessageStep {
        SenderMessageStep {
            sender: self.sender,
            index: self.index,
            message_key: Secret32::new(*self.message_key.expose_for_backend()),
            next_chain_key: Secret32::zero(),
            route_tag: self.route_tag,
        }
    }

    fn clear(&mut self) {
        self.message_key.wipe();
        self.route_tag.fill(0);
        self.index = 0;
    }
}

impl Drop for SkippedGroupMessageKey {
    fn drop(&mut self) {
        self.clear();
    }
}

pub enum SenderChainResolution {
    Skipped {
        step: SenderMessageStep,
    },
    CurrentOrFuture {
        step: SenderMessageStep,
        skipped: Vec<SkippedGroupMessageKey>,
    },
}

impl SenderChainResolution {
    #[must_use]
    pub const fn step(&self) -> &SenderMessageStep {
        match self {
            Self::Skipped { step } | Self::CurrentOrFuture { step, .. } => step,
        }
    }
}

#[derive(Default)]
pub struct SenderChainState {
    pub senders: Vec<SenderChainCursor>,
    skipped: Vec<SkippedGroupMessageKey>,
}

impl SenderChainState {
    #[must_use]
    pub fn len(&self) -> usize {
        self.senders.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }

    pub fn clear(&mut self) {
        for sender in &mut self.senders {
            sender.clear();
        }
        for skipped in &mut self.skipped {
            skipped.clear();
        }
        self.senders.clear();
        self.skipped.clear();
    }

    pub fn install_epoch(
        &mut self,
        context: &EpochKeyContext,
        epoch_key: &Secret32,
        roster: &[RosterEntry],
    ) -> GroupResult<()> {
        let mut candidate = Vec::new();
        for entry in active_sender_entries(context.mode, roster) {
            candidate.push(SenderChainCursor::new(
                entry.member_id,
                derive_sender_chain_key(epoch_key, context, entry.member_id)?,
            ));
        }
        candidate.sort_by_key(|entry| entry.sender.0);
        if candidate.is_empty() {
            return Err(GroupError::InvalidSenderChain);
        }
        self.clear();
        self.senders = candidate;
        Ok(())
    }

    #[must_use]
    pub fn next_index(&self, sender: MemberId) -> Option<u64> {
        self.senders
            .iter()
            .find(|entry| entry.sender == sender)
            .map(|entry| entry.next_index)
    }

    #[must_use]
    pub fn chain_key_commitment(&self, sender: MemberId) -> Option<[u8; 32]> {
        self.senders
            .iter()
            .find(|entry| entry.sender == sender)
            .map(SenderChainCursor::chain_key_commitment)
    }

    pub fn next_send_step(
        &mut self,
        context: &EpochKeyContext,
        sender: MemberId,
    ) -> GroupResult<SenderMessageStep> {
        let cursor = self
            .senders
            .iter_mut()
            .find(|entry| entry.sender == sender)
            .ok_or(GroupError::SenderNotAllowed { member_id: sender })?;
        if cursor.next_index == u64::MAX {
            return Err(GroupError::CounterExhausted);
        }
        let step =
            derive_sender_message_step(&cursor.chain_key, context, sender, cursor.next_index)?;
        cursor.chain_key.wipe();
        cursor.chain_key = Secret32::new(*step.next_chain_key.expose_for_backend());
        cursor.next_index = cursor
            .next_index
            .checked_add(1)
            .ok_or(GroupError::CounterExhausted)?;
        Ok(step)
    }

    pub fn resolution_for_route(
        &self,
        context: &EpochKeyContext,
        route_tag: [u8; 16],
        index: u64,
        skip_bound: u64,
    ) -> GroupResult<SenderChainResolution> {
        let mut matched = None;
        let mut too_far_ahead = false;
        let mut older_than_cursor = false;

        for skipped in &self.skipped {
            if skipped.index == index && route_tag_eq(&skipped.route_tag, &route_tag) {
                if matched.is_some() {
                    return Err(GroupError::InvalidSenderChain);
                }
                matched = Some(SenderChainResolution::Skipped {
                    step: skipped.to_step(),
                });
            }
        }

        for cursor in &self.senders {
            if index < cursor.next_index {
                older_than_cursor = true;
                continue;
            }
            let gap = index - cursor.next_index;
            if gap > skip_bound {
                too_far_ahead = true;
                continue;
            }
            let resolution = derive_resolution_for_cursor(context, cursor, index)?;
            if route_tag_eq(&resolution.step().route_tag, &route_tag) {
                if matched.is_some() {
                    return Err(GroupError::InvalidSenderChain);
                }
                matched = Some(resolution);
            }
        }

        if let Some(resolution) = matched {
            return Ok(resolution);
        }
        if too_far_ahead {
            return Err(GroupError::MessageTooFarAhead);
        }
        if older_than_cursor {
            return Err(GroupError::MessageTooOld);
        }
        Err(GroupError::AuthenticationFailed)
    }

    pub fn commit_resolution(
        &mut self,
        resolution: SenderChainResolution,
        skip_bound: usize,
    ) -> GroupResult<()> {
        match resolution {
            SenderChainResolution::Skipped { step } => {
                let position = self
                    .skipped
                    .iter()
                    .position(|entry| {
                        entry.sender == step.sender
                            && entry.index == step.index
                            && route_tag_eq(&entry.route_tag, &step.route_tag)
                    })
                    .ok_or(GroupError::InvalidSenderChain)?;
                self.skipped.remove(position);
                Ok(())
            }
            SenderChainResolution::CurrentOrFuture { step, skipped } => {
                let cursor = self
                    .senders
                    .iter_mut()
                    .find(|entry| entry.sender == step.sender)
                    .ok_or(GroupError::SenderNotAllowed {
                        member_id: step.sender,
                    })?;
                if cursor.next_index > step.index {
                    return Err(GroupError::InvalidSenderChain);
                }
                let skipped_for_sender = self
                    .skipped
                    .iter()
                    .filter(|entry| entry.sender == step.sender)
                    .count();
                if skipped_for_sender
                    .checked_add(skipped.len())
                    .is_none_or(|total| total > skip_bound)
                {
                    return Err(GroupError::InvalidSenderChain);
                }
                cursor.chain_key.wipe();
                cursor.chain_key = Secret32::new(*step.next_chain_key.expose_for_backend());
                cursor.next_index = step
                    .index
                    .checked_add(1)
                    .ok_or(GroupError::CounterExhausted)?;
                self.skipped.extend(skipped);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    #[must_use]
    pub fn export_snapshot(&self) -> SenderChainStateSnapshot {
        SenderChainStateSnapshot {
            senders: self
                .senders
                .iter()
                .map(|sender| SenderChainCursorSnapshot {
                    sender: sender.sender,
                    next_index: sender.next_index,
                    chain_key: *sender.chain_key.expose_for_backend(),
                })
                .collect(),
            skipped: self
                .skipped
                .iter()
                .map(|skipped| SkippedGroupMessageKeySnapshot {
                    sender: skipped.sender,
                    index: skipped.index,
                    route_tag: skipped.route_tag,
                    message_key: *skipped.message_key.expose_for_backend(),
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: SenderChainStateSnapshot) -> Self {
        Self {
            senders: snapshot
                .senders
                .into_iter()
                .map(|sender| SenderChainCursor {
                    sender: sender.sender,
                    next_index: sender.next_index,
                    chain_key: Secret32::new(sender.chain_key),
                })
                .collect(),
            skipped: snapshot
                .skipped
                .into_iter()
                .map(|skipped| SkippedGroupMessageKey {
                    sender: skipped.sender,
                    index: skipped.index,
                    route_tag: skipped.route_tag,
                    message_key: Secret32::new(skipped.message_key),
                })
                .collect(),
        }
    }

    pub fn append_test_commitment(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&(self.senders.len() as u64).to_be_bytes());
        for sender in &self.senders {
            output.extend_from_slice(&sender.sender.0);
            output.extend_from_slice(&sender.next_index.to_be_bytes());
            output.extend_from_slice(&sender.chain_key_commitment());
        }
        output.extend_from_slice(&(self.skipped.len() as u64).to_be_bytes());
        for skipped in &self.skipped {
            output.extend_from_slice(&skipped.sender.0);
            output.extend_from_slice(&skipped.index.to_be_bytes());
            output.extend_from_slice(&skipped.route_tag);
            output.extend_from_slice(&skipped.key_commitment());
        }
    }
}

fn derive_resolution_for_cursor(
    context: &EpochKeyContext,
    cursor: &SenderChainCursor,
    target_index: u64,
) -> GroupResult<SenderChainResolution> {
    let mut chain_key = Secret32::new(*cursor.chain_key.expose_for_backend());
    let mut skipped = Vec::new();
    let mut index = cursor.next_index;
    loop {
        let step = derive_sender_message_step(&chain_key, context, cursor.sender, index)?;
        chain_key.wipe();
        if index == target_index {
            return Ok(SenderChainResolution::CurrentOrFuture { step, skipped });
        }
        let next_chain_key = Secret32::new(*step.next_chain_key.expose_for_backend());
        skipped.push(SkippedGroupMessageKey::from_step(&step));
        chain_key = next_chain_key;
        index = index.checked_add(1).ok_or(GroupError::CounterExhausted)?;
    }
}

impl Drop for SenderChainState {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedGroupMessage {
    pub sender: MemberId,
    pub index: u64,
    pub route_tag: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderReplayStateSnapshot {
    pub sender: MemberId,
    pub replay: ReplayWindowSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupReplayStateSnapshot {
    pub senders: Vec<SenderReplayStateSnapshot>,
    pub accepted_messages: Vec<AcceptedGroupMessage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderReplayState {
    pub sender: MemberId,
    pub replay: ReplayWindow,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupReplayState {
    pub senders: Vec<SenderReplayState>,
    pub accepted_messages: Vec<AcceptedGroupMessage>,
}

impl GroupReplayState {
    pub fn install_epoch(&mut self, mode: GroupMode, roster: &[RosterEntry]) -> GroupResult<()> {
        let mut candidate = active_sender_entries(mode, roster)
            .into_iter()
            .map(|entry| SenderReplayState {
                sender: entry.member_id,
                replay: ReplayWindow::default(),
            })
            .collect::<Vec<_>>();
        candidate.sort_by_key(|entry| entry.sender.0);
        if candidate.is_empty() {
            return Err(GroupError::InvalidSenderChain);
        }
        self.senders = candidate;
        self.accepted_messages.clear();
        Ok(())
    }

    #[must_use]
    pub fn contains_route_tag(&self, route_tag: [u8; 16], index: u64) -> bool {
        self.accepted_messages
            .iter()
            .any(|entry| entry.index == index && route_tag_eq(&entry.route_tag, &route_tag))
    }

    pub fn mark_accepted(
        &mut self,
        sender: MemberId,
        index: u64,
        route_tag: [u8; 16],
    ) -> GroupResult<()> {
        if self.contains_route_tag(route_tag, index) {
            return Err(GroupError::ReplayDetected);
        }
        let replay = self
            .senders
            .iter_mut()
            .find(|entry| entry.sender == sender)
            .ok_or(GroupError::InvalidSenderChain)?;
        replay.replay.mark(index).map_err(map_replay_error)?;
        self.accepted_messages.push(AcceptedGroupMessage {
            sender,
            index,
            route_tag,
        });
        Ok(())
    }

    pub fn clear(&mut self) {
        for sender in &mut self.senders {
            sender.replay.clear();
        }
        self.senders.clear();
        self.accepted_messages.clear();
    }

    #[must_use]
    pub fn export_snapshot(&self) -> GroupReplayStateSnapshot {
        GroupReplayStateSnapshot {
            senders: self
                .senders
                .iter()
                .map(|sender| SenderReplayStateSnapshot {
                    sender: sender.sender,
                    replay: sender.replay.export_snapshot(),
                })
                .collect(),
            accepted_messages: self.accepted_messages.clone(),
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: GroupReplayStateSnapshot) -> Self {
        Self {
            senders: snapshot
                .senders
                .into_iter()
                .map(|sender| SenderReplayState {
                    sender: sender.sender,
                    replay: ReplayWindow::from_snapshot(sender.replay),
                })
                .collect(),
            accepted_messages: snapshot.accepted_messages,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupStateSnapshot {
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
    pub membership: MembershipPrivateStateSnapshot,
    pub sender_chains: SenderChainStateSnapshot,
    pub replay_state: GroupReplayStateSnapshot,
    pub phase: GroupPhase,
}

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

fn route_tag_eq(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn map_replay_error(error: ReplayError) -> GroupError {
    match error {
        ReplayError::Replay => GroupError::ReplayDetected,
        ReplayError::TooOld => GroupError::MessageTooOld,
    }
}

fn active_sender_entries(mode: GroupMode, roster: &[RosterEntry]) -> Vec<&RosterEntry> {
    roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active && entry.role.can_send_in_mode(mode))
        .collect()
}

fn compute_roster_hash(mode: GroupMode, roster: &[RosterEntry]) -> GroupResult<[u8; 64]> {
    roster_hash(&crate::encode_roster(mode, roster)?)
}
