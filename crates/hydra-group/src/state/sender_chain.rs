mod snapshot_restore;

use super::{active_sender_entries, route_tag_eq};
use crate::{
    derive_sender_chain_key, derive_sender_message_step, sender_chain_commitment, EpochKeyContext,
    GroupError, GroupResult, MemberId, RosterEntry, SenderMessageStep,
};
use hydra_core::types::Secret32;

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
