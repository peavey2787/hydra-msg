use super::{
    active_sender_entries, route_tag_eq, GroupReplayStateSnapshot, SenderReplayStateSnapshot,
};
use crate::{GroupError, GroupMode, GroupResult, MemberId, RosterEntry};
use hydra_core::{
    protocol::replay::{ReplayError, ReplayWindow},
    REPLAY_WINDOW_WIDTH,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedGroupMessage {
    pub sender: MemberId,
    pub index: u64,
    pub route_tag: [u8; 16],
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
        let minimum_index = index.saturating_sub((REPLAY_WINDOW_WIDTH - 1) as u64);
        self.accepted_messages
            .retain(|entry| entry.sender != sender || entry.index >= minimum_index);
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

    pub fn from_snapshot(
        snapshot: GroupReplayStateSnapshot,
        mode: GroupMode,
        roster: &[RosterEntry],
    ) -> GroupResult<Self> {
        let allowed = active_sender_entries(mode, roster)
            .into_iter()
            .map(|entry| entry.member_id)
            .collect::<std::collections::HashSet<_>>();
        if snapshot.senders.len() > allowed.len() {
            return Err(GroupError::InvalidSenderChain);
        }
        let mut sender_ids = std::collections::HashSet::new();
        if snapshot
            .senders
            .iter()
            .any(|sender| !allowed.contains(&sender.sender) || !sender_ids.insert(sender.sender))
        {
            return Err(GroupError::InvalidSenderChain);
        }
        let max_accepted = allowed
            .len()
            .checked_mul(REPLAY_WINDOW_WIDTH)
            .ok_or(GroupError::InvalidSenderChain)?;
        if snapshot.accepted_messages.len() > max_accepted {
            return Err(GroupError::InvalidSenderChain);
        }
        let mut accepted_ids = std::collections::HashSet::new();
        let mut accepted_routes = std::collections::HashSet::new();
        let mut accepted_per_sender = std::collections::HashMap::new();
        for message in &snapshot.accepted_messages {
            if !allowed.contains(&message.sender)
                || !accepted_ids.insert((message.sender, message.index))
                || !accepted_routes.insert((message.index, message.route_tag))
            {
                return Err(GroupError::InvalidSenderChain);
            }
            let count = accepted_per_sender.entry(message.sender).or_insert(0usize);
            *count += 1;
            if *count > REPLAY_WINDOW_WIDTH {
                return Err(GroupError::InvalidSenderChain);
            }
        }
        Ok(Self {
            senders: snapshot
                .senders
                .into_iter()
                .map(|sender| SenderReplayState {
                    sender: sender.sender,
                    replay: ReplayWindow::from_snapshot(sender.replay),
                })
                .collect(),
            accepted_messages: snapshot.accepted_messages,
        })
    }
}

fn map_replay_error(error: ReplayError) -> GroupError {
    match error {
        ReplayError::Replay => GroupError::ReplayDetected,
        ReplayError::TooOld => GroupError::MessageTooOld,
    }
}
