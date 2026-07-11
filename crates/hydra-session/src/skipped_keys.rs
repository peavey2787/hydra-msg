use hydra_core::MAX_SKIP;
use hydra_crypto::SecretBytes;

use crate::{ratchet::derive_route_tag, Direction, SessionError, SessionResult};

pub struct SkippedMessageKey {
    session_id: [u8; 32],
    direction: Direction,
    index: u64,
    key: SecretBytes<32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedMessageKeySnapshot {
    pub session_id: [u8; 32],
    pub direction: Direction,
    pub index: u64,
    pub key: [u8; 32],
}

#[derive(Default)]
pub struct SkippedKeyStore {
    entries: Vec<SkippedMessageKey>,
}

impl SkippedKeyStore {
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn ensure_capacity_for(&self, additional: usize) -> SessionResult<()> {
        if self
            .entries
            .len()
            .checked_add(additional)
            .is_none_or(|total| total > MAX_SKIP)
        {
            return Err(SessionError::SkippedKeyLimit);
        }
        Ok(())
    }

    pub(crate) fn commit_batch(
        &mut self,
        session_id: [u8; 32],
        direction: Direction,
        entries: Vec<(u64, SecretBytes<32>)>,
    ) {
        debug_assert!(self.entries.len() + entries.len() <= MAX_SKIP);
        self.entries
            .extend(entries.into_iter().map(|(index, key)| SkippedMessageKey {
                session_id,
                direction,
                index,
                key,
            }));
    }

    #[must_use]
    pub fn get(
        &self,
        session_id: &[u8; 32],
        direction: Direction,
        index: u64,
    ) -> Option<&SecretBytes<32>> {
        self.entries
            .iter()
            .find(|entry| {
                &entry.session_id == session_id
                    && entry.direction == direction
                    && entry.index == index
            })
            .map(|entry| &entry.key)
    }

    pub fn remove(
        &mut self,
        session_id: &[u8; 32],
        direction: Direction,
        index: u64,
    ) -> SessionResult<()> {
        let position = self
            .entries
            .iter()
            .position(|entry| {
                &entry.session_id == session_id
                    && entry.direction == direction
                    && entry.index == index
            })
            .ok_or(SessionError::InvalidState)?;
        self.entries.remove(position);
        Ok(())
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub(crate) fn append_receive_route_tags(
        &self,
        session_id: &[u8; 32],
        direction: Direction,
        output: &mut Vec<[u8; 16]>,
    ) {
        output.extend(
            self.entries
                .iter()
                .filter(|entry| &entry.session_id == session_id && entry.direction == direction)
                .map(|entry| derive_route_tag(&entry.key, session_id, entry.index)),
        );
    }

    #[must_use]
    pub fn export_snapshot(&self) -> Vec<SkippedMessageKeySnapshot> {
        self.entries
            .iter()
            .map(|entry| SkippedMessageKeySnapshot {
                session_id: entry.session_id,
                direction: entry.direction,
                index: entry.index,
                key: *entry.key.expose_secret(),
            })
            .collect()
    }

    pub fn from_snapshot(entries: Vec<SkippedMessageKeySnapshot>) -> SessionResult<Self> {
        if entries.len() > MAX_SKIP {
            return Err(SessionError::SkippedKeyLimit);
        }
        let mut seen = std::collections::HashSet::new();
        let mut restored = Vec::with_capacity(entries.len());
        for entry in entries {
            if !seen.insert((entry.session_id, entry.direction, entry.index)) {
                return Err(SessionError::InvalidState);
            }
            restored.push(SkippedMessageKey {
                session_id: entry.session_id,
                direction: entry.direction,
                index: entry.index,
                key: SecretBytes::from_array(entry.key),
            });
        }
        Ok(Self { entries: restored })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn append_test_commitment(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&(self.entries.len() as u64).to_be_bytes());
        for entry in &self.entries {
            output.extend_from_slice(&entry.session_id);
            output.push(entry.direction as u8);
            output.extend_from_slice(&entry.index.to_be_bytes());
            output.extend_from_slice(entry.key.expose_secret());
        }
    }
}
