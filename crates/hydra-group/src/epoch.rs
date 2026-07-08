use hydra_core::{
    types::{Epoch, GroupId, Secret32},
    SUITE_ID,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

use crate::{lp, u64_be, GroupError, GroupMode, GroupResult, MemberId, StateVersion};

const LABEL_EPOCH_KEY: &[u8] = b"HYDRA-MSG/v1/group/epoch-key";
const LABEL_EPOCH_KEY_CONTEXT: &[u8] = b"HYDRA-MSG/v1/group/epoch-key/context";
const LABEL_SENDER_CHAIN: &[u8] = b"HYDRA-MSG/v1/group/sender-chain";
const LABEL_SENDER_MESSAGE_KEY: &[u8] = b"HYDRA-MSG/v1/group/sender-message-key";
const LABEL_SENDER_CHAIN_ADVANCE: &[u8] = b"HYDRA-MSG/v1/group/sender-chain-advance";
const LABEL_SENDER_ROUTE_TAG: &[u8] = b"HYDRA-MSG/v1/group/sender-route-tag";
const LABEL_SENDER_CHAIN_COMMITMENT: &[u8] = b"HYDRA-MSG/v1/group/sender-chain-commitment";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochKeyContext {
    pub group_id: GroupId,
    pub mode: GroupMode,
    pub epoch: Epoch,
    pub state_version: StateVersion,
    pub roster_hash: [u8; 64],
    pub tree_hash: [u8; 64],
    pub commit_hash: [u8; 64],
}

pub struct SenderMessageStep {
    pub sender: MemberId,
    pub index: u64,
    pub message_key: Secret32,
    pub next_chain_key: Secret32,
    pub route_tag: [u8; 16],
}

impl SenderMessageStep {
    pub fn clear(&mut self) {
        self.message_key.wipe();
        self.next_chain_key.wipe();
        self.route_tag.fill(0);
    }
}

impl Drop for SenderMessageStep {
    fn drop(&mut self) {
        self.clear();
    }
}

pub fn next_epoch(current: Epoch) -> GroupResult<Epoch> {
    current
        .0
        .checked_add(1)
        .map(Epoch)
        .ok_or(GroupError::CounterExhausted)
}

pub fn derive_epoch_key(root_path_secret: &Secret32, epoch: Epoch) -> GroupResult<Secret32> {
    let mut context = Vec::new();
    context.extend_from_slice(&SUITE_ID);
    context.extend_from_slice(&u64_be(epoch.0));
    derive_secret32(root_path_secret, LABEL_EPOCH_KEY, &context)
}

pub fn derive_epoch_key_for_context(
    root_epoch_secret: &Secret32,
    context: &EpochKeyContext,
) -> GroupResult<Secret32> {
    derive_secret32(
        root_epoch_secret,
        LABEL_EPOCH_KEY_CONTEXT,
        &encode_epoch_context(context)?,
    )
}

pub fn derive_sender_chain_key(
    epoch_key: &Secret32,
    context: &EpochKeyContext,
    sender: MemberId,
) -> GroupResult<Secret32> {
    let mut encoded = encode_epoch_context(context)?;
    encoded.extend_from_slice(&sender.0);
    derive_secret32(epoch_key, LABEL_SENDER_CHAIN, &encoded)
}

pub fn derive_sender_message_step(
    chain_key: &Secret32,
    context: &EpochKeyContext,
    sender: MemberId,
    index: u64,
) -> GroupResult<SenderMessageStep> {
    let encoded = encode_sender_step_context(context, sender, index)?;
    let message_key = derive_secret32(chain_key, LABEL_SENDER_MESSAGE_KEY, &encoded)?;
    let next_chain_key = derive_secret32(chain_key, LABEL_SENDER_CHAIN_ADVANCE, &encoded)?;
    let route_full = RustCryptoBackend::hmac_sha3_256(
        &SecretBytes::from_array(*message_key.expose_for_backend()),
        &route_tag_input(&encoded)?,
    );
    let mut route_tag = [0_u8; 16];
    route_tag.copy_from_slice(&route_full[..16]);
    Ok(SenderMessageStep {
        sender,
        index,
        message_key,
        next_chain_key,
        route_tag,
    })
}

pub fn sender_chain_commitment(
    sender: MemberId,
    next_index: u64,
    chain_key: &Secret32,
) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(LABEL_SENDER_CHAIN_COMMITMENT);
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&sender.0);
    input.extend_from_slice(&u64_be(next_index));
    input.extend_from_slice(chain_key.expose_for_backend());
    RustCryptoBackend::sha3_256(&input)
}

fn encode_epoch_context(context: &EpochKeyContext) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SUITE_ID);
    encoded.extend_from_slice(&context.group_id.0);
    encoded.push(context.mode as u8);
    encoded.extend_from_slice(&u64_be(context.epoch.0));
    encoded.extend_from_slice(&u64_be(context.state_version.0));
    encoded.extend_from_slice(&context.roster_hash);
    encoded.extend_from_slice(&context.tree_hash);
    encoded.extend_from_slice(&context.commit_hash);
    lp(&encoded)
}

fn encode_sender_step_context(
    context: &EpochKeyContext,
    sender: MemberId,
    index: u64,
) -> GroupResult<Vec<u8>> {
    let mut encoded = encode_epoch_context(context)?;
    encoded.extend_from_slice(&sender.0);
    encoded.extend_from_slice(&u64_be(index));
    lp(&encoded)
}

fn route_tag_input(encoded_sender_context: &[u8]) -> GroupResult<Vec<u8>> {
    let mut input = Vec::new();
    input.extend_from_slice(LABEL_SENDER_ROUTE_TAG);
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&lp(encoded_sender_context)?);
    Ok(input)
}

fn derive_secret32(secret: &Secret32, label: &[u8], context: &[u8]) -> GroupResult<Secret32> {
    let mut info = Vec::new();
    info.extend_from_slice(&lp(label)?);
    info.extend_from_slice(&lp(context)?);
    let output = RustCryptoBackend::hkdf_expand(secret.expose_for_backend(), &info, 32)
        .map_err(|_| GroupError::InvalidSenderChain)?;
    let bytes: [u8; 32] = output
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::InvalidSenderChain)?;
    Ok(Secret32::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(
        epoch: u64,
        state_version: u64,
        roster: u8,
        tree: u8,
        commit: u8,
    ) -> EpochKeyContext {
        EpochKeyContext {
            group_id: GroupId([0x42; 32]),
            mode: GroupMode::Interactive,
            epoch: Epoch(epoch),
            state_version: StateVersion(state_version),
            roster_hash: [roster; 64],
            tree_hash: [tree; 64],
            commit_hash: [commit; 64],
        }
    }

    #[test]
    fn epoch_key_derivation_is_deterministic_and_epoch_bound() {
        let root = Secret32::new([0x11; 32]);
        let left = derive_epoch_key(&root, Epoch(7)).unwrap();
        let right = derive_epoch_key(&root, Epoch(7)).unwrap();
        let changed = derive_epoch_key(&root, Epoch(8)).unwrap();
        assert_eq!(left.expose_for_backend(), right.expose_for_backend());
        assert_ne!(left.expose_for_backend(), changed.expose_for_backend());
    }

    #[test]
    fn sender_chain_keys_are_context_and_sender_bound() {
        let epoch_key = Secret32::new([0x22; 32]);
        let base = context(2, 3, 4, 5, 6);
        let same = derive_sender_chain_key(&epoch_key, &base, MemberId([1; 32])).unwrap();
        let same_again = derive_sender_chain_key(&epoch_key, &base, MemberId([1; 32])).unwrap();
        let other_sender = derive_sender_chain_key(&epoch_key, &base, MemberId([2; 32])).unwrap();
        let other_epoch =
            derive_sender_chain_key(&epoch_key, &context(3, 3, 4, 5, 6), MemberId([1; 32]))
                .unwrap();
        assert_eq!(same.expose_for_backend(), same_again.expose_for_backend());
        assert_ne!(same.expose_for_backend(), other_sender.expose_for_backend());
        assert_ne!(same.expose_for_backend(), other_epoch.expose_for_backend());
    }

    #[test]
    fn sender_message_step_advances_and_binds_route_tags() {
        let epoch_key = Secret32::new([0x33; 32]);
        let context = context(4, 5, 6, 7, 8);
        let chain = derive_sender_chain_key(&epoch_key, &context, MemberId([9; 32])).unwrap();
        let first = derive_sender_message_step(&chain, &context, MemberId([9; 32]), 0).unwrap();
        let first_again =
            derive_sender_message_step(&chain, &context, MemberId([9; 32]), 0).unwrap();
        let second = derive_sender_message_step(&chain, &context, MemberId([9; 32]), 1).unwrap();
        assert_eq!(
            first.message_key.expose_for_backend(),
            first_again.message_key.expose_for_backend()
        );
        assert_eq!(first.route_tag, first_again.route_tag);
        assert_ne!(
            first.message_key.expose_for_backend(),
            second.message_key.expose_for_backend()
        );
        assert_ne!(first.route_tag, second.route_tag);
    }
}
