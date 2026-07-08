use crate::{
    change_payload_hash, commit_hash, commit_sig_digest, encode_change_payload, encode_commit_core,
    encode_governance_policy, governance_policy_hash, mode_policy_hash, CommitCore, CommitKind,
    GroupResult, GroupState,
};

use super::{
    key_schedule::key_schedule_commitment,
    payload::build_change_payload,
    transition::build_transition,
    types::{CommitPlan, PreparedCommit},
    validation::{
        validate_change_specific_signatures, validate_governance_signatures,
        validate_parent_for_change,
    },
};

pub fn prepare_commit(state: &GroupState, plan: CommitPlan) -> GroupResult<PreparedCommit> {
    state.require_active()?;
    validate_parent_for_change(state, plan.committer, &plan.change)?;

    let transition = build_transition(state, &plan)?;
    if plan.change.kind() == CommitKind::Create {
        validate_governance_signatures(
            &transition.governance_policy,
            &transition.roster,
            &plan.signatures,
        )?;
    } else {
        validate_governance_signatures(&state.governance_policy, &state.roster, &plan.signatures)?;
    }
    validate_change_specific_signatures(&plan.change, &plan.signatures)?;
    let payload = build_change_payload(state, &plan.change)?;
    let encoded_payload = encode_change_payload(&payload)?;
    let payload_hash = change_payload_hash(&encoded_payload)?;
    let key_commitment = key_schedule_commitment(state, &transition, &plan)?;

    let canonical_governance = encode_governance_policy(&transition.governance_policy)?;
    let core = CommitCore {
        commit_kind: plan.change.kind(),
        group_id: state.group_id,
        old_group_mode: if plan.change.kind() == CommitKind::Create {
            None
        } else {
            Some(state.mode)
        },
        new_group_mode: transition.mode,
        new_membership_mechanism: transition.mechanism,
        old_epoch: state.epoch,
        new_epoch: transition.epoch,
        old_state_version: state.state_version,
        new_state_version: transition.state_version,
        parent_commit_hash: state.last_commit_hash,
        old_roster_hash: state.roster_hash,
        new_roster_hash: transition.roster_hash,
        old_tree_hash: state.tree_hash,
        new_tree_hash: transition.tree_hash,
        commit_nonce: plan.commit_nonce,
        change_payload_hash: payload_hash,
        key_schedule_commitment: key_commitment,
        governance_policy_hash: governance_policy_hash(&canonical_governance)?,
        mode_policy_hash: mode_policy_hash(transition.mode_policy)?,
    };
    let encoded_core = encode_commit_core(&core)?;
    let signature_digest = commit_sig_digest(&encoded_core)?;
    let commit_hash = commit_hash(&encoded_core)?;
    Ok(PreparedCommit {
        core,
        encoded_core,
        signature_digest,
        commit_hash,
        signatures: plan.signatures,
        candidate: transition,
    })
}
