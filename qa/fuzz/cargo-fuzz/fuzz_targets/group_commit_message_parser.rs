#![no_main]

use hydra_core::{
    types::{EnvelopeClass, Epoch, GroupId, IdentityFingerprint, Secret32},
    ML_DSA_65_SIG_SIZE,
};
use hydra_envelope::decode_outer_header;
use hydra_group::{
    change_payload_hash, commit_hash, commit_sig_digest, encode_change_payload,
    encode_commit_core, encode_governance_policy, encode_mode_policy, encode_roster,
    encode_signature_set, validate_governance_policy, validate_signature_set, ChangePayload,
    CommitCore, CommitKind, CommitSignature, GovernancePolicy, GroupMode, GroupRole, GroupState,
    GroupStateConfig, MemberId, MemberStatus, MembershipMechanism, ModePolicy, RosterEntry,
    StateVersion,
};
use libfuzzer_sys::fuzz_target;

fn member(value: u8) -> MemberId {
    MemberId([value; 32])
}

fn active_entry(value: u8, role: GroupRole) -> RosterEntry {
    RosterEntry {
        member_id: member(value),
        device_identity_fingerprint: IdentityFingerprint([value; 32]),
        role,
        status: MemberStatus::Active,
        tree_leaf_slot: u32::from(value),
        joined_epoch: Epoch(1),
        removed_epoch: Epoch(0),
    }
}

fn lite_state() -> Option<GroupState> {
    let roster = vec![
        active_entry(1, GroupRole::Member),
        active_entry(2, GroupRole::Member),
    ];
    let mut state = GroupState::new_validated(GroupStateConfig {
        group_id: GroupId([0x42; 32]),
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        epoch: Epoch(7),
        state_version: StateVersion(9),
        governance_policy: GovernancePolicy::single_signer(member(1)),
        mode_policy: ModePolicy::default(),
        roster,
    })
    .ok()?;
    state.tree_hash = [0x77; 64];
    state.last_commit_hash = [0x88; 64];
    state
        .install_epoch_sender_chains(&Secret32::new([0x33; 32]))
        .ok()?;
    Some(state)
}

fuzz_target!(|data: &[u8]| {
    let _ = decode_outer_header(data);
    let governance = GovernancePolicy::single_signer(member(1));
    let _ = validate_governance_policy(&governance);
    let signatures = vec![CommitSignature {
        signer: member(1),
        signature: [0x11; ML_DSA_65_SIG_SIZE],
    }];
    let _ = validate_signature_set(&signatures);
    let _ = encode_signature_set(&signatures);
    let roster = vec![active_entry(1, GroupRole::Member)];
    let _ = encode_roster(&roster);
    let mode_policy = ModePolicy::default();
    let _ = encode_governance_policy(&governance);
    let _ = encode_mode_policy(mode_policy);
    let change = ChangePayload::GovernanceChange {
        new_governance_policy: &governance,
    };
    let encoded_change = encode_change_payload(&change).unwrap_or_default();
    let change_bytes = if data.is_empty() {
        encoded_change.as_slice()
    } else {
        &data[..data.len().min(512)]
    };
    let core = CommitCore {
        commit_kind: CommitKind::GovernanceChange,
        group_id: GroupId([0x42; 32]),
        old_group_mode: Some(GroupMode::Lite),
        new_group_mode: GroupMode::Lite,
        new_membership_mechanism: MembershipMechanism::DirectWrap,
        old_epoch: Epoch(1),
        new_epoch: Epoch(2),
        old_state_version: StateVersion(1),
        new_state_version: StateVersion(2),
        parent_commit_hash: [0x66; 64],
        old_roster_hash: [0x77; 64],
        new_roster_hash: [0x88; 64],
        old_tree_hash: [0xdd; 64],
        new_tree_hash: [0xee; 64],
        commit_nonce: [0x55; 32],
        change_payload_hash: change_payload_hash(change_bytes).unwrap_or([0; 64]),
        key_schedule_commitment: [0x44; 64],
        governance_policy_hash: [0x99; 64],
        mode_policy_hash: [0xaa; 64],
    };
    if let Ok(encoded_core) = encode_commit_core(&core) {
        let _ = commit_hash(&encoded_core);
        let _ = commit_sig_digest(&encoded_core);
    }

    if let Some(mut state) = lite_state() {
        let bounded = data[..data.len().min(EnvelopeClass::Lite.max_content_size())].to_vec();
        if let Ok(outbound) = state.seal_group_data(member(1), &bounded) {
            let _ = state.open_group_data(&outbound.envelope);
            let mut tampered = outbound.envelope;
            if !tampered.is_empty() && !data.is_empty() {
                let index = data.len() % tampered.len();
                tampered[index] ^= data[0];
            }
            let _ = state.open_group_data(&tampered);
        }
        let _ = state.open_group_data(data);
    }
});
