use std::collections::BTreeMap;

use hydra_core::{
    types::{Epoch, GroupId, Secret32},
    ML_DSA_65_SIG_SIZE,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use hydra_group::{
    apply_prepared_commit, derive_epoch_key_for_context, member_id, prepare_commit, CommitChange,
    CommitPlan, CommitSignature, GovernancePolicy, GroupMode, GroupRole, GroupState,
    GroupStateConfig, GroupStateSnapshot, MemberId, MemberStatus, MembershipMechanism,
    MembershipPrivateState, ModePolicy, RosterEntry, StateVersion,
};

use crate::random::random_array;
use crate::{AppError, AppIdentity, AppResult, PublicIdentity};

#[derive(Debug, PartialEq, Eq)]
pub struct AppSignedGroupEnvelope {
    sender: MemberId,
    index: u64,
    envelope: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AppGroupMessage {
    sender: MemberId,
    index: u64,
    content: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AppGroupRekeyNotice {
    removed_member_id: MemberId,
    new_epoch: Epoch,
    new_state_version: StateVersion,
    commit_hash: [u8; 64],
    group_rekey_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupRekeyPolicy {
    pub lite_every_messages: u64,
    pub interactive_every_messages: u64,
    pub broadcast_every_messages: u64,
    pub on_membership_change: bool,
}

impl GroupRekeyPolicy {
    #[must_use]
    pub const fn threshold_for_mode(self, mode: GroupMode) -> u64 {
        match mode {
            GroupMode::Lite => self.lite_every_messages,
            GroupMode::Interactive => self.interactive_every_messages,
            GroupMode::Broadcast => self.broadcast_every_messages,
        }
    }

    #[must_use]
    pub const fn should_rekey(self, mode: GroupMode, next_send_index: u64) -> bool {
        let threshold = self.threshold_for_mode(mode);
        threshold != 0 && next_send_index >= threshold
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppGroupRekeyReason {
    MessageThreshold,
    MembershipChange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppGroupPolicyRekey {
    reason: AppGroupRekeyReason,
    new_epoch: Epoch,
    new_state_version: StateVersion,
    commit_hash: [u8; 64],
}

#[derive(Debug, PartialEq, Eq)]
pub struct AppGroupPolicySend {
    message: AppSignedGroupEnvelope,
    rekey: Option<AppGroupPolicyRekey>,
}

pub struct AppGroupMembershipChange {
    welcome: AppGroupWelcome,
    rekey: Option<AppGroupPolicyRekey>,
}

/// Opaque Lite welcome material for the newly joined member.
///
/// This A0 object is local app-library handoff material. A later transport and
/// welcome-encryption milestone must wrap this before it crosses a network.
pub struct AppGroupWelcome {
    group_id: GroupId,
    recipient: MemberId,
    epoch: Epoch,
    state_version: StateVersion,
    parent_commit_hash: [u8; 64],
    commit_hash: [u8; 64],
    roster: Vec<RosterEntry>,
    governance_policy: GovernancePolicy,
    mode_policy: ModePolicy,
    direct_epoch_secret: SecretBytes<32>,
    identities: Vec<(MemberId, PublicIdentity)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AppGroupSnapshot {
    pub state: GroupStateSnapshot,
    pub local_member_id: MemberId,
    pub identities: Vec<(MemberId, PublicIdentity)>,
}

pub struct AppGroup {
    state: GroupState,
    local_member_id: MemberId,
    identities: BTreeMap<MemberId, PublicIdentity>,
}

impl AppGroup {
    pub fn create_lite(local_identity: &AppIdentity, local_role: GroupRole) -> AppResult<Self> {
        let group_id = GroupId(random_array()?);
        Self::create_lite_with_group_id(group_id, local_identity, local_role)
    }

    pub fn create_lite_with_group_id(
        group_id: GroupId,
        local_identity: &AppIdentity,
        local_role: GroupRole,
    ) -> AppResult<Self> {
        if !local_role.is_active_in_mode(GroupMode::Lite)
            || !local_role.can_send_in_mode(GroupMode::Lite)
        {
            return Err(AppError::InvalidInput(
                "Lite creator must have a send-capable Lite role",
            ));
        }
        let joined_epoch = Epoch(0);
        let local_public = local_identity.public_identity();
        let local_member_id = member_id(group_id, local_public.fingerprint(), joined_epoch);
        let roster = vec![RosterEntry {
            member_id: local_member_id,
            device_identity_fingerprint: local_public.fingerprint(),
            role: local_role,
            status: MemberStatus::Active,
            tree_leaf_slot: u32::MAX,
            joined_epoch,
            removed_epoch: Epoch(0),
        }];
        let governance_policy = GovernancePolicy::single_signer(local_member_id);
        let mode_policy = ModePolicy::default();
        let mut state = GroupState::new_empty(
            group_id,
            GroupMode::Lite,
            MembershipMechanism::DirectWrap,
            governance_policy.clone(),
            mode_policy,
        )?;
        let direct_epoch_secret = SecretBytes::from_array(random_array::<32>()?);
        let plan = CommitPlan {
            committer: local_member_id,
            commit_nonce: random_array()?,
            change: CommitChange::Create {
                new_roster: roster,
                new_governance_policy: governance_policy,
                new_mode_policy: mode_policy,
                new_tree_hash: [0; 64],
            },
            signatures: Vec::new(),
            update_path: None,
            direct_epoch_secret: Some(*direct_epoch_secret.expose_secret()),
        };
        let prepared = prepare_signed_commit(&state, local_identity, local_member_id, plan)?;
        apply_prepared_commit(&mut state, prepared)?;
        let mut identities = BTreeMap::new();
        identities.insert(local_member_id, local_public);
        Ok(Self {
            state,
            local_member_id,
            identities,
        })
    }

    pub fn install_lite_welcome(
        local_identity: &AppIdentity,
        welcome: AppGroupWelcome,
    ) -> AppResult<Self> {
        let local_public = local_identity.public_identity();
        if local_public.fingerprint()
            != welcome
                .roster
                .iter()
                .find(|entry| entry.member_id == welcome.recipient)
                .ok_or(AppError::InvalidInput(
                    "welcome recipient is absent from roster",
                ))?
                .device_identity_fingerprint
        {
            return Err(AppError::InvalidInput(
                "welcome was not addressed to this identity",
            ));
        }
        let mut state = GroupState::new_validated(GroupStateConfig {
            group_id: welcome.group_id,
            mode: GroupMode::Lite,
            mechanism: MembershipMechanism::DirectWrap,
            epoch: welcome.epoch,
            state_version: welcome.state_version,
            governance_policy: welcome.governance_policy.clone(),
            mode_policy: welcome.mode_policy,
            roster: welcome.roster.clone(),
        })?;
        state.previous_commit_hash = welcome.parent_commit_hash;
        state.last_commit_hash = welcome.commit_hash;
        install_direct_epoch_secret(&mut state, welcome.direct_epoch_secret)?;
        let mut identities = welcome
            .identities
            .iter()
            .map(|(member, identity)| (*member, identity.clone()))
            .collect::<BTreeMap<_, _>>();
        identities.insert(welcome.recipient, local_public);
        Ok(Self {
            state,
            local_member_id: welcome.recipient,
            identities,
        })
    }

    pub fn add_lite_member(
        &mut self,
        sponsor_identity: &AppIdentity,
        new_identity: PublicIdentity,
        new_role: GroupRole,
    ) -> AppResult<AppGroupWelcome> {
        if self.state.mode != GroupMode::Lite
            || self.state.mechanism != MembershipMechanism::DirectWrap
        {
            return Err(AppError::InvalidState(
                "add_lite_member requires an active Lite group",
            ));
        }
        if !new_role.is_active_in_mode(GroupMode::Lite) {
            return Err(AppError::InvalidInput(
                "new member role is invalid for Lite mode",
            ));
        }
        self.require_local_identity(sponsor_identity)?;
        let joined_epoch = next_app_epoch(self.state.epoch)?;
        let new_member_id = member_id(
            self.state.group_id,
            new_identity.fingerprint(),
            joined_epoch,
        );
        let new_entry = RosterEntry {
            member_id: new_member_id,
            device_identity_fingerprint: new_identity.fingerprint(),
            role: new_role,
            status: MemberStatus::Active,
            tree_leaf_slot: u32::MAX,
            joined_epoch,
            removed_epoch: Epoch(0),
        };
        let parent_commit_hash = self.state.last_commit_hash;
        let direct_epoch_secret = SecretBytes::from_array(random_array::<32>()?);
        let plan = CommitPlan {
            committer: self.local_member_id,
            commit_nonce: random_array()?,
            change: CommitChange::Join {
                new_entry: new_entry.clone(),
            },
            signatures: Vec::new(),
            update_path: None,
            direct_epoch_secret: Some(*direct_epoch_secret.expose_secret()),
        };
        let prepared =
            prepare_signed_commit(&self.state, sponsor_identity, self.local_member_id, plan)?;
        let commit_hash = prepared.commit_hash;
        apply_prepared_commit(&mut self.state, prepared)?;
        self.identities.insert(new_member_id, new_identity.clone());
        Ok(AppGroupWelcome {
            group_id: self.state.group_id,
            recipient: new_member_id,
            epoch: self.state.epoch,
            state_version: self.state.state_version,
            parent_commit_hash,
            commit_hash,
            roster: self.state.roster.clone(),
            governance_policy: self.state.governance_policy.clone(),
            mode_policy: self.state.mode_policy,
            direct_epoch_secret,
            identities: self
                .identities
                .iter()
                .map(|(member, identity)| (*member, identity.clone()))
                .collect(),
        })
    }

    pub fn add_lite_member_with_rekey_policy(
        &mut self,
        sponsor_identity: &AppIdentity,
        new_identity: PublicIdentity,
        new_role: GroupRole,
        policy: GroupRekeyPolicy,
    ) -> AppResult<AppGroupMembershipChange> {
        let welcome = self.add_lite_member(sponsor_identity, new_identity, new_role)?;
        let rekey = if policy.on_membership_change {
            Some(AppGroupPolicyRekey {
                reason: AppGroupRekeyReason::MembershipChange,
                new_epoch: welcome.epoch,
                new_state_version: welcome.state_version,
                commit_hash: welcome.commit_hash,
            })
        } else {
            None
        };
        Ok(AppGroupMembershipChange { welcome, rekey })
    }

    pub fn send_signed(
        &mut self,
        local_identity: &AppIdentity,
        content: &[u8],
    ) -> AppResult<AppSignedGroupEnvelope> {
        self.require_local_identity(local_identity)?;
        let outbound = self.state.seal_signed_group_data(
            self.local_member_id,
            local_identity.signing_key(),
            content,
        )?;
        Ok(AppSignedGroupEnvelope {
            sender: outbound.sender,
            index: outbound.index,
            envelope: outbound.envelope,
        })
    }

    pub fn send_signed_with_rekey_policy(
        &mut self,
        local_identity: &AppIdentity,
        content: &[u8],
        policy: GroupRekeyPolicy,
    ) -> AppResult<AppGroupPolicySend> {
        self.require_local_identity(local_identity)?;
        let next_sender_index = self.state.next_sender_index(self.local_member_id)?;
        let rekey = if policy.should_rekey(self.state.mode, next_sender_index) {
            Some(self.rekey_lite_epoch(local_identity, AppGroupRekeyReason::MessageThreshold)?)
        } else {
            None
        };
        let message = self.send_signed(local_identity, content)?;
        Ok(AppGroupPolicySend { message, rekey })
    }

    pub fn receive_signed(&mut self, envelope: &[u8]) -> AppResult<AppGroupMessage> {
        let identities = &self.identities;
        let received = self.state.open_signed_group_data(envelope, |member| {
            identities
                .get(&member)
                .map(PublicIdentity::verification_key_for_group)
        })?;
        Ok(AppGroupMessage {
            sender: received.sender,
            index: received.index,
            content: received.content,
        })
    }

    pub fn remove_lite_member_and_rekey(
        &mut self,
        sponsor_identity: &AppIdentity,
        removed_member_id: MemberId,
        reason_code: u16,
    ) -> AppResult<AppGroupRekeyNotice> {
        if self.state.mode != GroupMode::Lite
            || self.state.mechanism != MembershipMechanism::DirectWrap
        {
            return Err(AppError::InvalidState(
                "remove_lite_member_and_rekey requires a Lite group",
            ));
        }
        if removed_member_id == self.local_member_id {
            return Err(AppError::InvalidInput(
                "local app facade cannot remove its own active device",
            ));
        }
        self.require_local_identity(sponsor_identity)?;
        if !self.state.roster.iter().any(|entry| {
            entry.member_id == removed_member_id && entry.status == MemberStatus::Active
        }) {
            return Err(AppError::InvalidInput(
                "removed member is not active in this group",
            ));
        }
        let direct_epoch_secret = SecretBytes::from_array(random_array::<32>()?);
        let plan = CommitPlan {
            committer: self.local_member_id,
            commit_nonce: random_array()?,
            change: CommitChange::RemoveOrRevoke {
                member_id: removed_member_id,
                reason_code,
            },
            signatures: Vec::new(),
            update_path: None,
            direct_epoch_secret: Some(*direct_epoch_secret.expose_secret()),
        };
        let prepared =
            prepare_signed_commit(&self.state, sponsor_identity, self.local_member_id, plan)?;
        let commit_hash = prepared.commit_hash;
        apply_prepared_commit(&mut self.state, prepared)?;
        self.identities.remove(&removed_member_id);
        Ok(AppGroupRekeyNotice {
            removed_member_id,
            new_epoch: self.state.epoch,
            new_state_version: self.state.state_version,
            commit_hash,
            group_rekey_required: true,
        })
    }

    pub fn rekey_lite_epoch(
        &mut self,
        sponsor_identity: &AppIdentity,
        reason: AppGroupRekeyReason,
    ) -> AppResult<AppGroupPolicyRekey> {
        if self.state.mode != GroupMode::Lite
            || self.state.mechanism != MembershipMechanism::DirectWrap
        {
            return Err(AppError::InvalidState(
                "automatic app group rekey currently requires Lite DirectWrap",
            ));
        }
        self.require_local_identity(sponsor_identity)?;
        let direct_epoch_secret = SecretBytes::from_array(random_array::<32>()?);
        let plan = CommitPlan {
            committer: self.local_member_id,
            commit_nonce: random_array()?,
            change: CommitChange::GovernanceChange {
                new_governance_policy: self.state.governance_policy.clone(),
            },
            signatures: Vec::new(),
            update_path: None,
            direct_epoch_secret: Some(*direct_epoch_secret.expose_secret()),
        };
        let prepared =
            prepare_signed_commit(&self.state, sponsor_identity, self.local_member_id, plan)?;
        let commit_hash = prepared.commit_hash;
        apply_prepared_commit(&mut self.state, prepared)?;
        Ok(AppGroupPolicyRekey {
            reason,
            new_epoch: self.state.epoch,
            new_state_version: self.state.state_version,
            commit_hash,
        })
    }

    pub fn export_snapshot(&self) -> AppResult<AppGroupSnapshot> {
        Ok(AppGroupSnapshot {
            state: self.state.export_snapshot()?,
            local_member_id: self.local_member_id,
            identities: self
                .identities
                .iter()
                .map(|(member, identity)| (*member, identity.clone()))
                .collect(),
        })
    }

    pub fn from_snapshot(snapshot: AppGroupSnapshot) -> AppResult<Self> {
        let state = GroupState::from_snapshot(snapshot.state)?;
        if !state.roster.iter().any(|entry| {
            entry.member_id == snapshot.local_member_id && entry.status == MemberStatus::Active
        }) {
            return Err(AppError::InvalidInput(
                "group snapshot local member is not active",
            ));
        }
        Ok(Self {
            state,
            local_member_id: snapshot.local_member_id,
            identities: snapshot.identities.into_iter().collect(),
        })
    }

    #[must_use]
    pub const fn group_id(&self) -> GroupId {
        self.state.group_id
    }

    #[must_use]
    pub const fn local_member_id(&self) -> MemberId {
        self.local_member_id
    }

    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.state.epoch
    }

    #[must_use]
    pub const fn state_version(&self) -> StateVersion {
        self.state.state_version
    }

    #[must_use]
    pub fn roster(&self) -> &[RosterEntry] {
        &self.state.roster
    }

    fn require_local_identity(&self, identity: &AppIdentity) -> AppResult<()> {
        let expected = self
            .identities
            .get(&self.local_member_id)
            .ok_or(AppError::InvalidState("missing local group identity"))?;
        if expected.fingerprint() == identity.fingerprint() {
            Ok(())
        } else {
            Err(AppError::InvalidInput(
                "identity does not match local group member",
            ))
        }
    }
}

impl AppSignedGroupEnvelope {
    #[must_use]
    pub const fn sender(&self) -> MemberId {
        self.sender
    }

    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    #[must_use]
    pub fn as_envelope(&self) -> &[u8] {
        &self.envelope
    }

    #[must_use]
    pub fn into_envelope(self) -> Vec<u8> {
        self.envelope
    }
}

impl AppGroupMessage {
    #[must_use]
    pub const fn sender(&self) -> MemberId {
        self.sender
    }

    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

impl AppGroupRekeyNotice {
    #[must_use]
    pub const fn removed_member_id(&self) -> MemberId {
        self.removed_member_id
    }

    #[must_use]
    pub const fn new_epoch(&self) -> Epoch {
        self.new_epoch
    }

    #[must_use]
    pub const fn new_state_version(&self) -> StateVersion {
        self.new_state_version
    }

    #[must_use]
    pub const fn commit_hash(&self) -> [u8; 64] {
        self.commit_hash
    }

    #[must_use]
    pub const fn group_rekey_required(&self) -> bool {
        self.group_rekey_required
    }
}

impl AppGroupWelcome {
    #[must_use]
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    #[must_use]
    pub const fn recipient(&self) -> MemberId {
        self.recipient
    }

    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    #[must_use]
    pub const fn state_version(&self) -> StateVersion {
        self.state_version
    }

    #[must_use]
    pub const fn commit_hash(&self) -> [u8; 64] {
        self.commit_hash
    }
}

impl AppGroupPolicyRekey {
    #[must_use]
    pub const fn reason(&self) -> AppGroupRekeyReason {
        self.reason
    }

    #[must_use]
    pub const fn new_epoch(&self) -> Epoch {
        self.new_epoch
    }

    #[must_use]
    pub const fn new_state_version(&self) -> StateVersion {
        self.new_state_version
    }

    #[must_use]
    pub const fn commit_hash(&self) -> [u8; 64] {
        self.commit_hash
    }
}

impl AppGroupPolicySend {
    #[must_use]
    pub fn message(&self) -> &AppSignedGroupEnvelope {
        &self.message
    }

    #[must_use]
    pub const fn rekey(&self) -> Option<AppGroupPolicyRekey> {
        self.rekey
    }
}

impl AppGroupMembershipChange {
    #[must_use]
    pub fn welcome(&self) -> &AppGroupWelcome {
        &self.welcome
    }

    #[must_use]
    pub fn into_welcome(self) -> AppGroupWelcome {
        self.welcome
    }

    #[must_use]
    pub const fn rekey(&self) -> Option<AppGroupPolicyRekey> {
        self.rekey
    }
}

fn prepare_signed_commit(
    state: &GroupState,
    signer_identity: &AppIdentity,
    signer: MemberId,
    plan: CommitPlan,
) -> AppResult<hydra_group::PreparedCommit> {
    let placeholder = CommitSignature {
        signer,
        signature: [0; ML_DSA_65_SIG_SIZE],
    };
    let unsigned = rebuild_plan(&plan, vec![placeholder]);
    let prepared = prepare_commit(state, unsigned)?;
    let signature =
        RustCryptoBackend::mldsa65_sign(signer_identity.signing_key(), &prepared.signature_digest)?;
    let signed = rebuild_plan(&plan, vec![CommitSignature { signer, signature }]);
    Ok(prepare_commit(state, signed)?)
}

fn rebuild_plan(plan: &CommitPlan, signatures: Vec<CommitSignature>) -> CommitPlan {
    CommitPlan {
        committer: plan.committer,
        commit_nonce: plan.commit_nonce,
        change: plan.change.clone(),
        signatures,
        update_path: plan.update_path.clone(),
        direct_epoch_secret: plan.direct_epoch_secret,
    }
}

fn install_direct_epoch_secret(state: &mut GroupState, secret: SecretBytes<32>) -> AppResult<()> {
    state.membership = MembershipPrivateState::DirectWrap {
        epoch_secret: Secret32::new(*secret.expose_secret()),
    };
    let epoch_secret = Secret32::new(*secret.expose_secret());
    let epoch_key = derive_epoch_key_for_context(&epoch_secret, &state.epoch_key_context())?;
    state.install_epoch_sender_chains(&epoch_key)?;
    Ok(())
}

fn next_app_epoch(epoch: Epoch) -> AppResult<Epoch> {
    epoch
        .0
        .checked_add(1)
        .map(Epoch)
        .ok_or(AppError::InvalidState("group epoch exhausted"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_group_create_join_and_signed_message_round_trip() {
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let mut alice_group = AppGroup::create_lite(&alice, GroupRole::Member).unwrap();
        let welcome = alice_group
            .add_lite_member(&alice, bob.public_identity(), GroupRole::Member)
            .unwrap();
        let mut bob_group = AppGroup::install_lite_welcome(&bob, welcome).unwrap();

        let outbound = alice_group.send_signed(&alice, b"hello group").unwrap();
        let received = bob_group.receive_signed(outbound.as_envelope()).unwrap();
        assert_eq!(received.content(), b"hello group");
        assert_eq!(received.sender(), alice_group.local_member_id());
    }

    #[test]
    fn wrong_local_identity_cannot_send() {
        let alice = AppIdentity::generate().unwrap();
        let mallory = AppIdentity::generate().unwrap();
        let mut group = AppGroup::create_lite(&alice, GroupRole::Member).unwrap();
        assert_eq!(
            group.send_signed(&mallory, b"nope").unwrap_err().class(),
            crate::AppErrorClass::InvalidInput
        );
    }

    #[test]
    fn lite_member_removal_rekeys_and_old_device_cannot_read_future_message() {
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let mut alice_group = AppGroup::create_lite(&alice, GroupRole::Member).unwrap();
        let welcome = alice_group
            .add_lite_member(&alice, bob.public_identity(), GroupRole::Member)
            .unwrap();
        let mut bob_group = AppGroup::install_lite_welcome(&bob, welcome).unwrap();
        let bob_member_id = bob_group.local_member_id();
        let old_epoch = alice_group.epoch();
        let notice = alice_group
            .remove_lite_member_and_rekey(&alice, bob_member_id, 1)
            .unwrap();
        assert_eq!(notice.removed_member_id(), bob_member_id);
        assert!(notice.group_rekey_required());
        assert!(notice.new_epoch().0 > old_epoch.0);
        let outbound = alice_group.send_signed(&alice, b"after removal").unwrap();
        assert!(bob_group.receive_signed(outbound.as_envelope()).is_err());
    }

    #[test]
    fn group_policy_threshold_rekeys_before_next_message() {
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let mut alice_group = AppGroup::create_lite(&alice, GroupRole::Member).unwrap();
        let welcome = alice_group
            .add_lite_member(&alice, bob.public_identity(), GroupRole::Member)
            .unwrap();
        let mut bob_group = AppGroup::install_lite_welcome(&bob, welcome).unwrap();
        let policy = GroupRekeyPolicy {
            lite_every_messages: 1,
            interactive_every_messages: 1,
            broadcast_every_messages: 1,
            on_membership_change: true,
        };
        let first = alice_group
            .send_signed_with_rekey_policy(&alice, b"first", policy)
            .unwrap();
        assert!(first.rekey().is_none());
        bob_group
            .receive_signed(first.message().as_envelope())
            .unwrap();
        let old_epoch = alice_group.epoch();
        let second = alice_group
            .send_signed_with_rekey_policy(&alice, b"second", policy)
            .unwrap();
        assert_eq!(
            second.rekey().unwrap().reason(),
            AppGroupRekeyReason::MessageThreshold
        );
        assert!(alice_group.epoch().0 > old_epoch.0);
        assert!(bob_group
            .receive_signed(second.message().as_envelope())
            .is_err());
    }
}
