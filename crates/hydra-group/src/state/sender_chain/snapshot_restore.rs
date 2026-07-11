use super::{SenderChainCursor, SenderChainState, SkippedGroupMessageKey};
use crate::state::roster_view::active_sender_entries;
use crate::{
    GroupError, GroupMode, GroupResult, RosterEntry, SenderChainCursorSnapshot,
    SenderChainStateSnapshot, SkippedGroupMessageKeySnapshot,
};
use hydra_core::types::Secret32;

impl SenderChainState {
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

    pub fn from_snapshot(
        snapshot: SenderChainStateSnapshot,
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
        let skip_bound = mode.sender_skip_bound();
        let max_skipped = allowed
            .len()
            .checked_mul(skip_bound)
            .ok_or(GroupError::InvalidSenderChain)?;
        if snapshot.skipped.len() > max_skipped {
            return Err(GroupError::InvalidSenderChain);
        }
        let mut skipped_ids = std::collections::HashSet::new();
        let mut skipped_per_sender = std::collections::HashMap::new();
        for skipped in &snapshot.skipped {
            if !allowed.contains(&skipped.sender)
                || !skipped_ids.insert((skipped.sender, skipped.index))
            {
                return Err(GroupError::InvalidSenderChain);
            }
            let count = skipped_per_sender.entry(skipped.sender).or_insert(0usize);
            *count += 1;
            if *count > skip_bound {
                return Err(GroupError::InvalidSenderChain);
            }
        }
        Ok(Self {
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
        })
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
