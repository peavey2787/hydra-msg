use crate::{
    derive_epoch_key_for_context, CommitKind, GroupError, GroupResult, GroupState,
    MembershipMechanism,
};

use super::{
    membership::install_membership_material,
    types::PreparedCommit,
    validation::{validate_governance_signatures, verify_prepared_commit_integrity},
};

pub fn apply_prepared_commit(state: &mut GroupState, prepared: PreparedCommit) -> GroupResult<()> {
    state.require_active()?;
    if prepared.core.group_id != state.group_id
        || prepared.core.parent_commit_hash != state.last_commit_hash
        || prepared.core.old_roster_hash != state.roster_hash
        || prepared.core.old_tree_hash != state.tree_hash
        || prepared.core.old_epoch != state.epoch
        || prepared.core.old_state_version != state.state_version
        || (prepared.core.commit_kind != CommitKind::Create
            && prepared.core.old_group_mode != Some(state.mode))
    {
        return Err(GroupError::InvalidCommitParent);
    }
    if prepared.core.commit_kind == CommitKind::Create {
        validate_governance_signatures(
            &prepared.candidate.governance_policy,
            &prepared.candidate.roster,
            &prepared.signatures,
        )?;
    } else {
        validate_governance_signatures(
            &state.governance_policy,
            &state.roster,
            &prepared.signatures,
        )?;
    }
    verify_prepared_commit_integrity(&prepared)?;

    state.previous_commit_hash = state.last_commit_hash;
    state.mode = prepared.candidate.mode;
    state.mechanism = prepared.candidate.mechanism;
    state.epoch = prepared.candidate.epoch;
    state.state_version = prepared.candidate.state_version;
    state.last_commit_hash = prepared.commit_hash;
    state.roster_hash = prepared.candidate.roster_hash;
    state.tree_hash = prepared.candidate.tree_hash;
    state.governance_policy = prepared.candidate.governance_policy;
    state.mode_policy = prepared.candidate.mode_policy;
    state.roster = prepared.candidate.roster;

    let sender_epoch_key = match (&prepared.candidate.direct_epoch_secret, state.mechanism) {
        (Some(secret), MembershipMechanism::DirectWrap) => Some(derive_epoch_key_for_context(
            secret,
            &state.epoch_key_context(),
        )?),
        _ => None,
    };
    install_membership_material(
        state,
        prepared.candidate.public_tree,
        prepared.candidate.direct_epoch_secret,
    );
    if let Some(epoch_key) = sender_epoch_key.as_ref() {
        state.install_epoch_sender_chains(epoch_key)?;
    } else {
        state.sender_chains.clear();
        state.replay_state.clear();
    }
    Ok(())
}
