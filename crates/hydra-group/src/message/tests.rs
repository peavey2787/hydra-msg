use super::*;
use crate::{
    GovernancePolicy, GroupError, GroupMode, GroupRole, GroupState, MemberId, MemberStatus,
    MembershipMechanism, ModePolicy, RosterEntry, StateVersion,
};
use hydra_core::types::{EnvelopeClass, Epoch, GroupId, IdentityFingerprint, Secret32};
use hydra_crypto::{CryptoBackend, MlDsaVerificationKey, RustCryptoBackend};
use hydra_envelope::decode_outer_header;

fn member(value: u8) -> MemberId {
    MemberId([value; 32])
}

fn fingerprint(value: u8) -> IdentityFingerprint {
    IdentityFingerprint([value; 32])
}

fn active_entry(member_value: u8, role: GroupRole) -> RosterEntry {
    RosterEntry {
        member_id: member(member_value),
        device_identity_fingerprint: fingerprint(member_value),
        role,
        status: MemberStatus::Active,
        tree_leaf_slot: u32::from(member_value),
        joined_epoch: Epoch(1),
        removed_epoch: Epoch(0),
    }
}

fn signed_entry(member_value: u8, role: GroupRole, key: &MlDsaVerificationKey) -> RosterEntry {
    RosterEntry {
        device_identity_fingerprint: identity_fingerprint(key),
        ..active_entry(member_value, role)
    }
}

fn lite_state() -> GroupState {
    let roster = vec![
        active_entry(1, GroupRole::Member),
        active_entry(2, GroupRole::Member),
    ];
    build_lite_state(roster)
}

fn signed_lite_state(key: &MlDsaVerificationKey) -> GroupState {
    build_lite_state(vec![
        signed_entry(1, GroupRole::Member, key),
        active_entry(2, GroupRole::Member),
    ])
}

fn build_lite_state(roster: Vec<RosterEntry>) -> GroupState {
    let mut state = GroupState::new_validated(crate::GroupStateConfig {
        group_id: GroupId([0x42; 32]),
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        epoch: Epoch(7),
        state_version: StateVersion(9),
        governance_policy: GovernancePolicy::single_signer(member(1)),
        mode_policy: ModePolicy::default(),
        roster,
    })
    .unwrap();
    state.tree_hash = [0x77; 64];
    state.last_commit_hash = [0x88; 64];
    state
        .install_epoch_sender_chains(&Secret32::new([0x33; 32]))
        .unwrap();
    state
}

#[test]
fn group_data_seals_opens_and_advances_one_sender_chain() {
    let mut sender = lite_state();
    let mut receiver = lite_state();
    let before_sender_two = receiver.sender_chains.next_index(member(2));
    let outbound = sender.seal_group_data(member(1), b"group hello").unwrap();
    assert_eq!(outbound.index, 0);
    assert_eq!(sender.sender_chains.next_index(member(1)), Some(1));

    let received = receiver.open_group_data(&outbound.envelope).unwrap();
    assert_eq!(received.sender, member(1));
    assert_eq!(received.index, 0);
    assert_eq!(received.content, b"group hello");
    assert_eq!(receiver.sender_chains.next_index(member(1)), Some(1));
    assert_eq!(
        receiver.sender_chains.next_index(member(2)),
        before_sender_two
    );
}

#[test]
fn signed_group_data_verifies_signature_and_strips_it_from_content() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut sender = signed_lite_state(&keypair.verification_key);
    let mut receiver = signed_lite_state(&keypair.verification_key);
    let outbound = sender
        .seal_signed_group_data(member(1), &keypair.signing_key, b"signed group hello")
        .unwrap();
    let received = receiver
        .open_signed_group_data(&outbound.envelope, |sender| {
            if sender == member(1) {
                Some(keypair.verification_key.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(received.sender, member(1));
    assert_eq!(received.content, b"signed group hello");
}

#[test]
fn invalid_group_sender_signature_preserves_receiver_state() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let wrong = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut sender = signed_lite_state(&keypair.verification_key);
    let mut receiver = signed_lite_state(&keypair.verification_key);
    let outbound = sender
        .seal_signed_group_data(member(1), &keypair.signing_key, b"signed group hello")
        .unwrap();
    let before_index = receiver.sender_chains.next_index(member(1));
    let before_commitment = receiver.sender_chains.chain_key_commitment(member(1));
    let before_replay = receiver.replay_state.accepted_messages.len();
    assert_eq!(
        receiver.open_signed_group_data(&outbound.envelope, |_| {
            Some(wrong.verification_key.clone())
        }),
        Err(GroupError::InvalidGroupSignature)
    );
    assert_eq!(receiver.sender_chains.next_index(member(1)), before_index);
    assert_eq!(
        receiver.sender_chains.chain_key_commitment(member(1)),
        before_commitment
    );
    assert_eq!(receiver.replay_state.accepted_messages.len(), before_replay);
}

#[test]
fn group_signature_digest_binds_mode_and_envelope_class() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut state = signed_lite_state(&keypair.verification_key);
    let step = state.next_sender_message_step(member(1)).unwrap();
    let lite = group_data_signature_digest(&state, EnvelopeClass::Lite, &step, b"x").unwrap();
    let standard =
        group_data_signature_digest(&state, EnvelopeClass::Standard, &step, b"x").unwrap();
    assert_ne!(lite, standard);
    let mut broadcast = state;
    broadcast.mode = GroupMode::Broadcast;
    let broadcast_digest =
        group_data_signature_digest(&broadcast, EnvelopeClass::Lite, &step, b"x").unwrap();
    assert_ne!(lite, broadcast_digest);
}

#[test]
fn duplicate_group_data_is_rejected_without_advancing_again() {
    let mut sender = lite_state();
    let mut receiver = lite_state();
    let outbound = sender.seal_group_data(member(1), b"duplicate").unwrap();
    receiver.open_group_data(&outbound.envelope).unwrap();
    let before = receiver.sender_chains.chain_key_commitment(member(1));
    assert_eq!(
        receiver.open_group_data(&outbound.envelope),
        Err(GroupError::ReplayDetected)
    );
    assert_eq!(
        receiver.sender_chains.chain_key_commitment(member(1)),
        before
    );
}

#[test]
fn authentication_failure_preserves_receiver_chain_and_replay_state() {
    let mut sender = lite_state();
    let mut receiver = lite_state();
    let mut outbound = sender.seal_group_data(member(1), b"tamper").unwrap();
    outbound.envelope[100] ^= 1;
    let before_index = receiver.sender_chains.next_index(member(1));
    let before_commitment = receiver.sender_chains.chain_key_commitment(member(1));
    let before_replay = receiver.replay_state.accepted_messages.len();
    assert_eq!(
        receiver.open_group_data(&outbound.envelope),
        Err(GroupError::AuthenticationFailed)
    );
    assert_eq!(receiver.sender_chains.next_index(member(1)), before_index);
    assert_eq!(
        receiver.sender_chains.chain_key_commitment(member(1)),
        before_commitment
    );
    assert_eq!(receiver.replay_state.accepted_messages.len(), before_replay);
}

#[test]
fn sender_must_be_send_capable_and_epoch_installed() {
    let mut state = lite_state();
    state.sender_chains.clear();
    assert_eq!(
        state.seal_group_data(member(1), b"not installed"),
        Err(GroupError::SenderNotAllowed {
            member_id: member(1)
        })
    );

    let roster = vec![
        active_entry(1, GroupRole::Moderator),
        active_entry(2, GroupRole::Audience),
    ];
    let mut broadcast = GroupState::new_validated(crate::GroupStateConfig {
        group_id: GroupId([0x99; 32]),
        mode: GroupMode::Broadcast,
        mechanism: MembershipMechanism::TreeKem,
        epoch: Epoch(1),
        state_version: StateVersion(0),
        governance_policy: GovernancePolicy::single_signer(member(1)),
        mode_policy: ModePolicy::default(),
        roster,
    })
    .unwrap();
    broadcast.tree_hash = [0x11; 64];
    broadcast.last_commit_hash = [0x22; 64];
    broadcast
        .install_epoch_sender_chains(&Secret32::new([0x44; 32]))
        .unwrap();
    assert_eq!(
        broadcast.seal_group_data(member(2), b"audience"),
        Err(GroupError::SenderNotAllowed {
            member_id: member(2)
        })
    );
}

#[test]
fn class_boundaries_select_smallest_group_data_class() {
    let mut sender = lite_state();
    for (length, expected) in [
        (hydra_core::LITE_MAX_CONTENT_SIZE, EnvelopeClass::Lite),
        (
            hydra_core::LITE_MAX_CONTENT_SIZE + 1,
            EnvelopeClass::Standard,
        ),
        (
            hydra_core::STANDARD_MAX_CONTENT_SIZE + 1,
            EnvelopeClass::Full,
        ),
    ] {
        let outbound = sender
            .seal_group_data(member(1), &vec![0xa5; length])
            .unwrap();
        let header = decode_outer_header(&outbound.envelope).unwrap();
        assert_eq!(header.envelope_class, expected);
    }
    assert_eq!(
        sender.seal_group_data(member(1), &vec![0; hydra_core::FULL_MAX_CONTENT_SIZE + 1]),
        Err(GroupError::InvalidEnvelope)
    );
}

#[test]
fn signed_group_message_rejects_different_mode_or_envelope_class_context() {
    let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
    let mut sender = signed_lite_state(&keypair.verification_key);
    let mut receiver = signed_lite_state(&keypair.verification_key);
    let outbound = sender
        .seal_signed_group_data(member(1), &keypair.signing_key, b"context-bound")
        .unwrap();

    let mut wrong_class = outbound.envelope.clone();
    wrong_class[6] = EnvelopeClass::Standard as u8;
    assert!(receiver
        .open_signed_group_data(&wrong_class, |_| Some(keypair.verification_key.clone()))
        .is_err());

    let mut wrong_mode = signed_lite_state(&keypair.verification_key);
    wrong_mode.mode = GroupMode::Broadcast;
    assert!(wrong_mode
        .open_signed_group_data(&outbound.envelope, |_| Some(
            keypair.verification_key.clone()
        ))
        .is_err());
}
