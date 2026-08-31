use crate::{GroupError, GroupResult, GroupState};

use super::{
    apply::apply_prepared_commit,
    types::{CommitInstallResult, PreparedCommit},
    validation::verify_prepared_commit_integrity,
};

pub fn install_prepared_commit(
    state: &mut GroupState,
    prepared: PreparedCommit,
) -> GroupResult<CommitInstallResult> {
    state.require_active()?;
    verify_prepared_commit_integrity(&prepared)?;

    if is_duplicate_commit(state, &prepared) {
        return Ok(CommitInstallResult::Duplicate);
    }

    if extends_current_commit(state, &prepared) {
        apply_prepared_commit(state, prepared)?;
        return Ok(CommitInstallResult::Applied);
    }

    if forks_current_commit(state, &prepared) {
        state.mark_forked();
        return Ok(CommitInstallResult::Forked);
    }

    Err(GroupError::InvalidCommitParent)
}

fn is_duplicate_commit(state: &GroupState, prepared: &PreparedCommit) -> bool {
    prepared.commit_hash == state.last_commit_hash
        && prepared.core.new_epoch == state.epoch
        && prepared.core.new_state_version == state.state_version
        && prepared.core.new_roster_hash == state.roster_hash
        && prepared.core.new_tree_hash == state.tree_hash
}

fn extends_current_commit(state: &GroupState, prepared: &PreparedCommit) -> bool {
    prepared.core.parent_commit_hash == state.last_commit_hash
        && prepared.core.old_epoch == state.epoch
        && prepared.core.old_state_version == state.state_version
}

fn forks_current_commit(state: &GroupState, prepared: &PreparedCommit) -> bool {
    prepared.core.parent_commit_hash == state.previous_commit_hash
        && prepared.core.new_epoch == state.epoch
        && prepared.core.new_state_version == state.state_version
        && prepared.commit_hash != state.last_commit_hash
}
