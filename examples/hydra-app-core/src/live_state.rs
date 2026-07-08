use std::{
    fs,
    path::{Path, PathBuf},
};

use hydra_core::{
    protocol::replay::ReplayWindowSnapshot,
    types::{Epoch, GroupId, IdentityFingerprint, IdentityPublicKey, LeafIndex},
    ML_DSA_65_VK_SIZE,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use hydra_group::{
    AcceptedGroupMessage, GovernancePolicy, GroupMode, GroupPhase, GroupReplayStateSnapshot,
    GroupRole, GroupStateSnapshot, MemberId, MemberStatus, MembershipMechanism,
    MembershipPrivateStateSnapshot, ModePolicy, PrivatePathNodeSecretSnapshot, PublicLeaf,
    PublicNodeKey, PublicTree, PublicTreeNode, RosterEntry, SenderChainCursorSnapshot,
    SenderChainStateSnapshot, SenderReplayStateSnapshot, SkippedGroupMessageKeySnapshot,
    StateVersion,
};
use hydra_session::{
    Direction, DirectionChainSnapshot, SessionPhase, SessionRole, SessionStateSnapshot,
    SkippedMessageKeySnapshot,
};
use zeroize::Zeroize;

use crate::{
    group::AppGroupSnapshot,
    random::random_array,
    secret_handling::{
        crash_safe_atomic_write, derive_storage_key, read_crash_safe, StorageKdfPolicy,
    },
    session::AppSessionSnapshot,
    AppError, AppGroup, AppResult, AppSession, ConversationId, PublicIdentity,
};

const STORE_MAGIC: &[u8; 8] = b"HYDRALS1";
const STORE_VERSION: u8 = 1;
const STORE_SALT_SIZE: usize = 32;
const STORE_NONCE_SIZE: usize = 12;
const STORE_HEADER_SIZE: usize = 8 + 1 + 1 + 4 + STORE_SALT_SIZE + STORE_NONCE_SIZE;
const PLAINTEXT_MAGIC: &[u8; 15] = b"HYDRA-LIVE-DB-1";
const PLAINTEXT_SCHEMA_VERSION: u32 = 1;
const CHECKPOINT_MAGIC: &[u8; 15] = b"HYDRA-LIVE-CHK1";
const ROLLBACK_LOG_MAGIC: &[u8; 15] = b"HYDRA-LIVE-RBL1";
const ROLLBACK_LOG_ENTRY_SIZE: usize = 15 + 8 + 32 + 32 + 32;
const ROLLBACK_ZERO_PREV: [u8; 32] = [0_u8; 32];

#[derive(Clone, Debug, PartialEq)]
pub struct StoredLiveSessionState {
    pub conversation_id: ConversationId,
    pub snapshot: AppSessionSnapshot,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredLiveGroupState {
    pub conversation_id: ConversationId,
    pub snapshot: AppGroupSnapshot,
}

/// Encrypted live protocol state database.
///
/// `MessageStore` persists history and app metadata. `LiveStateStore` persists
/// the sensitive active protocol state needed to continue after restart:
/// session ratchets, group epoch secrets, sender chains, skipped keys, replay
/// windows, commit hashes, rosters, and identity bindings. The file is paired
/// with a small checkpoint sidecar so a stale but otherwise valid encrypted DB
/// is detected when the checkpoint was not rolled back with it.
pub struct LiveStateStore {
    path: PathBuf,
    rollback_counter: u64,
    sessions: Vec<StoredLiveSessionState>,
    groups: Vec<StoredLiveGroupState>,
}

impl LiveStateStore {
    pub fn create(path: impl AsRef<Path>, password: &[u8]) -> AppResult<Self> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
            rollback_counter: 0,
            sessions: Vec::new(),
            groups: Vec::new(),
        };
        store.write_current(password)?;
        Ok(store)
    }

    pub fn load(path: impl AsRef<Path>, password: &[u8]) -> AppResult<Self> {
        let path = path.as_ref();
        let file = read_crash_safe(path, "live state database cannot be read")?;
        if file.len() <= STORE_HEADER_SIZE {
            return Err(AppError::InvalidInput("live state database is truncated"));
        }
        let (header, ciphertext) = file.split_at(STORE_HEADER_SIZE);
        let (kdf_policy, salt, nonce) = decode_header(header)?;
        let key = derive_live_key(password, &salt, kdf_policy)?;
        let plaintext = RustCryptoBackend::aead_open(&key, &nonce, header, ciphertext)?;
        let decoded = decode_plaintext(&plaintext)?;
        let rollback_key = derive_rollback_key(password)?;
        verify_checkpoint(path, decoded.rollback_counter, &file, &rollback_key)?;
        Ok(Self {
            path: path.to_path_buf(),
            rollback_counter: decoded.rollback_counter,
            sessions: decoded.sessions,
            groups: decoded.groups,
        })
    }

    pub fn save(&mut self, password: &[u8]) -> AppResult<()> {
        self.rollback_counter =
            self.rollback_counter
                .checked_add(1)
                .ok_or(AppError::InvalidState(
                    "live state rollback counter exhausted",
                ))?;
        self.write_current(password)
    }

    pub fn upsert_session(&mut self, conversation_id: ConversationId, session: &AppSession) {
        let record = StoredLiveSessionState {
            conversation_id,
            snapshot: session.export_snapshot(),
        };
        match self
            .sessions
            .iter_mut()
            .find(|existing| existing.conversation_id == conversation_id)
        {
            Some(existing) => *existing = record,
            None => self.sessions.push(record),
        }
    }

    pub fn restore_session(&self, conversation_id: ConversationId) -> AppResult<AppSession> {
        let record = self
            .sessions
            .iter()
            .find(|session| session.conversation_id == conversation_id)
            .ok_or(AppError::InvalidInput("live session state not found"))?;
        AppSession::from_snapshot(record.snapshot.clone())
    }

    pub fn upsert_group(
        &mut self,
        conversation_id: ConversationId,
        group: &AppGroup,
    ) -> AppResult<()> {
        let record = StoredLiveGroupState {
            conversation_id,
            snapshot: group.export_snapshot()?,
        };
        match self
            .groups
            .iter_mut()
            .find(|existing| existing.conversation_id == conversation_id)
        {
            Some(existing) => *existing = record,
            None => self.groups.push(record),
        }
        Ok(())
    }

    pub fn restore_group(&self, conversation_id: ConversationId) -> AppResult<AppGroup> {
        let record = self
            .groups
            .iter()
            .find(|group| group.conversation_id == conversation_id)
            .ok_or(AppError::InvalidInput("live group state not found"))?;
        AppGroup::from_snapshot(record.snapshot.clone())
    }

    #[must_use]
    pub const fn rollback_counter(&self) -> u64 {
        self.rollback_counter
    }

    #[must_use]
    pub fn sessions(&self) -> &[StoredLiveSessionState] {
        &self.sessions
    }

    #[must_use]
    pub fn groups(&self) -> &[StoredLiveGroupState] {
        &self.groups
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_current(&self, password: &[u8]) -> AppResult<()> {
        let mut salt = random_array::<STORE_SALT_SIZE>()?;
        let nonce = random_array::<STORE_NONCE_SIZE>()?;
        let kdf_policy = StorageKdfPolicy::scrypt_interactive();
        let key = derive_live_key(password, &salt, kdf_policy)?;
        let plaintext = encode_plaintext(self)?;
        let header = encode_header(kdf_policy, &salt, &nonce);
        let ciphertext = RustCryptoBackend::aead_seal(&key, &nonce, &header, &plaintext)?;
        salt.zeroize();
        let mut file = Vec::with_capacity(header.len() + ciphertext.len());
        file.extend_from_slice(&header);
        file.extend_from_slice(&ciphertext);
        crash_safe_atomic_write(&self.path, &file, "live state database cannot be written")?;
        let rollback_key = derive_rollback_key(password)?;
        write_checkpoint(&self.path, self.rollback_counter, &file, &rollback_key)
    }
}

struct DecodedLiveStateStore {
    rollback_counter: u64,
    sessions: Vec<StoredLiveSessionState>,
    groups: Vec<StoredLiveGroupState>,
}

fn derive_live_key(
    password: &[u8],
    salt: &[u8; STORE_SALT_SIZE],
    policy: StorageKdfPolicy,
) -> AppResult<hydra_crypto::SecretBytes<32>> {
    derive_storage_key(
        b"HYDRA-MSG/v1/app/live-state-store",
        password,
        salt,
        policy.kdf_id,
        policy.parameter_code,
    )
}

fn derive_rollback_key(password: &[u8]) -> AppResult<hydra_crypto::SecretBytes<32>> {
    const ROLLBACK_KEY_SALT: [u8; STORE_SALT_SIZE] = [0x52_u8; STORE_SALT_SIZE];
    let policy = StorageKdfPolicy::scrypt_interactive();
    derive_storage_key(
        b"HYDRA-MSG/v1/app/live-state-rollback-log",
        password,
        &ROLLBACK_KEY_SALT,
        policy.kdf_id,
        policy.parameter_code,
    )
}

fn encode_header(
    policy: StorageKdfPolicy,
    salt: &[u8; STORE_SALT_SIZE],
    nonce: &[u8; STORE_NONCE_SIZE],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(STORE_HEADER_SIZE);
    out.extend_from_slice(STORE_MAGIC);
    out.push(STORE_VERSION);
    out.push(policy.kdf_id);
    out.extend_from_slice(&policy.parameter_code.to_be_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out
}

fn decode_header(
    header: &[u8],
) -> AppResult<(
    StorageKdfPolicy,
    [u8; STORE_SALT_SIZE],
    [u8; STORE_NONCE_SIZE],
)> {
    if header.len() != STORE_HEADER_SIZE
        || &header[..8] != STORE_MAGIC
        || header[8] != STORE_VERSION
    {
        return Err(AppError::InvalidInput(
            "live state database header is invalid",
        ));
    }
    let kdf_id = header[9];
    let parameter_code = u32::from_be_bytes(header[10..14].try_into().expect("fixed header range"));
    let salt = header[14..46].try_into().expect("fixed salt range");
    let nonce = header[46..58].try_into().expect("fixed nonce range");
    Ok((
        StorageKdfPolicy {
            kdf_id,
            parameter_code,
        },
        salt,
        nonce,
    ))
}

fn encode_plaintext(store: &LiveStateStore) -> AppResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(PLAINTEXT_MAGIC);
    put_u32(&mut out, PLAINTEXT_SCHEMA_VERSION);
    put_u64(&mut out, store.rollback_counter);
    put_vec_len(&mut out, store.sessions.len(), "live session count")?;
    for session in &store.sessions {
        encode_live_session(&mut out, session)?;
    }
    put_vec_len(&mut out, store.groups.len(), "live group count")?;
    for group in &store.groups {
        encode_live_group(&mut out, group)?;
    }
    Ok(out)
}

fn decode_plaintext(input: &[u8]) -> AppResult<DecodedLiveStateStore> {
    let mut offset = 0;
    if take_exact(input, &mut offset, PLAINTEXT_MAGIC.len())? != PLAINTEXT_MAGIC.as_slice() {
        return Err(AppError::InvalidInput(
            "live state plaintext marker is invalid",
        ));
    }
    if take_u32(input, &mut offset)? != PLAINTEXT_SCHEMA_VERSION {
        return Err(AppError::InvalidInput("live state schema is unsupported"));
    }
    let rollback_counter = take_u64(input, &mut offset)?;
    let session_count = take_u32(input, &mut offset)? as usize;
    let mut sessions = Vec::with_capacity(session_count);
    for _ in 0..session_count {
        sessions.push(decode_live_session(input, &mut offset)?);
    }
    let group_count = take_u32(input, &mut offset)? as usize;
    let mut groups = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        groups.push(decode_live_group(input, &mut offset)?);
    }
    if offset != input.len() {
        return Err(AppError::InvalidInput("live state has trailing bytes"));
    }
    Ok(DecodedLiveStateStore {
        rollback_counter,
        sessions,
        groups,
    })
}

fn encode_live_session(out: &mut Vec<u8>, record: &StoredLiveSessionState) -> AppResult<()> {
    out.extend_from_slice(&record.conversation_id.0);
    encode_public_identity(out, &record.snapshot.local_identity);
    encode_public_identity(out, &record.snapshot.peer_identity);
    encode_session_state(out, &record.snapshot.state)
}

fn decode_live_session(input: &[u8], offset: &mut usize) -> AppResult<StoredLiveSessionState> {
    let conversation_id = ConversationId(take_array(input, offset)?);
    let local_identity = decode_public_identity(input, offset)?;
    let peer_identity = decode_public_identity(input, offset)?;
    let state = decode_session_state(input, offset)?;
    Ok(StoredLiveSessionState {
        conversation_id,
        snapshot: AppSessionSnapshot {
            state,
            local_identity,
            peer_identity,
        },
    })
}

fn encode_live_group(out: &mut Vec<u8>, record: &StoredLiveGroupState) -> AppResult<()> {
    out.extend_from_slice(&record.conversation_id.0);
    encode_group_state(out, &record.snapshot.state)?;
    out.extend_from_slice(&record.snapshot.local_member_id.0);
    put_vec_len(
        out,
        record.snapshot.identities.len(),
        "group identity count",
    )?;
    for (member, identity) in &record.snapshot.identities {
        out.extend_from_slice(&member.0);
        encode_public_identity(out, identity);
    }
    Ok(())
}

fn decode_live_group(input: &[u8], offset: &mut usize) -> AppResult<StoredLiveGroupState> {
    let conversation_id = ConversationId(take_array(input, offset)?);
    let state = decode_group_state(input, offset)?;
    let local_member_id = MemberId(take_array(input, offset)?);
    let identity_count = take_u32(input, offset)? as usize;
    let mut identities = Vec::with_capacity(identity_count);
    for _ in 0..identity_count {
        identities.push((
            MemberId(take_array(input, offset)?),
            decode_public_identity(input, offset)?,
        ));
    }
    Ok(StoredLiveGroupState {
        conversation_id,
        snapshot: AppGroupSnapshot {
            state,
            local_member_id,
            identities,
        },
    })
}

fn encode_public_identity(out: &mut Vec<u8>, identity: &PublicIdentity) {
    out.extend_from_slice(&identity.public_key().0);
}

fn decode_public_identity(input: &[u8], offset: &mut usize) -> AppResult<PublicIdentity> {
    let bytes = take_exact(input, offset, ML_DSA_65_VK_SIZE)?;
    let mut public_key = [0_u8; ML_DSA_65_VK_SIZE];
    public_key.copy_from_slice(bytes);
    PublicIdentity::from_public_key(IdentityPublicKey(public_key))
}

fn encode_session_state(out: &mut Vec<u8>, snapshot: &SessionStateSnapshot) -> AppResult<()> {
    out.push(session_role_to_u8(snapshot.role));
    out.push(session_phase_to_u8(snapshot.phase));
    out.extend_from_slice(&snapshot.session_id);
    out.extend_from_slice(&snapshot.transcript_hash);
    out.extend_from_slice(&snapshot.local_identity_fingerprint);
    out.extend_from_slice(&snapshot.remote_identity_fingerprint);
    out.extend_from_slice(&snapshot.refresh_root);
    encode_direction_chain(out, &snapshot.sending_chain);
    encode_direction_chain(out, &snapshot.receiving_chain);
    put_vec_len(
        out,
        snapshot.skipped_keys.len(),
        "skipped session key count",
    )?;
    for skipped in &snapshot.skipped_keys {
        out.extend_from_slice(&skipped.session_id);
        out.push(direction_to_u8(skipped.direction));
        put_u64(out, skipped.index);
        out.extend_from_slice(&skipped.key);
    }
    encode_replay_window(out, &snapshot.replay);
    match snapshot.active_refresh_id {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id);
        }
        None => out.push(0),
    }
    Ok(())
}

fn decode_session_state(input: &[u8], offset: &mut usize) -> AppResult<SessionStateSnapshot> {
    let role = session_role_from_u8(take_u8(input, offset)?)?;
    let phase = session_phase_from_u8(take_u8(input, offset)?)?;
    let session_id = take_array(input, offset)?;
    let transcript_hash = take_array(input, offset)?;
    let local_identity_fingerprint = take_array(input, offset)?;
    let remote_identity_fingerprint = take_array(input, offset)?;
    let refresh_root = take_array(input, offset)?;
    let sending_chain = decode_direction_chain(input, offset)?;
    let receiving_chain = decode_direction_chain(input, offset)?;
    let skipped_count = take_u32(input, offset)? as usize;
    let mut skipped_keys = Vec::with_capacity(skipped_count);
    for _ in 0..skipped_count {
        skipped_keys.push(SkippedMessageKeySnapshot {
            session_id: take_array(input, offset)?,
            direction: direction_from_u8(take_u8(input, offset)?)?,
            index: take_u64(input, offset)?,
            key: take_array(input, offset)?,
        });
    }
    let replay = decode_replay_window(input, offset)?;
    let active_refresh_id = match take_u8(input, offset)? {
        0 => None,
        1 => Some(take_array(input, offset)?),
        _ => {
            return Err(AppError::InvalidInput(
                "live session refresh flag is invalid",
            ))
        }
    };
    Ok(SessionStateSnapshot {
        role,
        phase,
        session_id,
        transcript_hash,
        local_identity_fingerprint,
        remote_identity_fingerprint,
        refresh_root,
        sending_chain,
        receiving_chain,
        skipped_keys,
        replay,
        active_refresh_id,
    })
}

fn encode_direction_chain(out: &mut Vec<u8>, chain: &DirectionChainSnapshot) {
    out.extend_from_slice(&chain.key);
    put_u64(out, chain.next_index);
}

fn decode_direction_chain(input: &[u8], offset: &mut usize) -> AppResult<DirectionChainSnapshot> {
    Ok(DirectionChainSnapshot {
        key: take_array(input, offset)?,
        next_index: take_u64(input, offset)?,
    })
}

fn encode_group_state(out: &mut Vec<u8>, snapshot: &GroupStateSnapshot) -> AppResult<()> {
    out.extend_from_slice(&snapshot.group_id.0);
    out.push(snapshot.mode as u8);
    out.push(snapshot.mechanism as u8);
    put_u64(out, snapshot.epoch.0);
    put_u64(out, snapshot.state_version.0);
    out.extend_from_slice(&snapshot.last_commit_hash);
    out.extend_from_slice(&snapshot.previous_commit_hash);
    out.extend_from_slice(&snapshot.roster_hash);
    out.extend_from_slice(&snapshot.tree_hash);
    encode_governance_policy(out, &snapshot.governance_policy)?;
    out.extend_from_slice(&snapshot.mode_policy.bytes);
    encode_roster(out, &snapshot.roster)?;
    encode_membership(out, &snapshot.membership)?;
    encode_sender_chains(out, &snapshot.sender_chains)?;
    encode_group_replay(out, &snapshot.replay_state)?;
    out.push(snapshot.phase as u8);
    Ok(())
}

fn decode_group_state(input: &[u8], offset: &mut usize) -> AppResult<GroupStateSnapshot> {
    let group_id = GroupId(take_array(input, offset)?);
    let mode = GroupMode::try_from(take_u8(input, offset)?)?;
    let mechanism = MembershipMechanism::try_from(take_u8(input, offset)?)?;
    let epoch = Epoch(take_u64(input, offset)?);
    let state_version = StateVersion(take_u64(input, offset)?);
    let last_commit_hash = take_array(input, offset)?;
    let previous_commit_hash = take_array(input, offset)?;
    let roster_hash = take_array(input, offset)?;
    let tree_hash = take_array(input, offset)?;
    let governance_policy = decode_governance_policy(input, offset)?;
    let mut mode_policy = ModePolicy::default();
    mode_policy
        .bytes
        .copy_from_slice(take_exact(input, offset, 12)?);
    let roster = decode_roster(input, offset)?;
    let membership = decode_membership(input, offset)?;
    let sender_chains = decode_sender_chains(input, offset)?;
    let replay_state = decode_group_replay(input, offset)?;
    let phase = GroupPhase::try_from(take_u8(input, offset)?)?;
    Ok(GroupStateSnapshot {
        group_id,
        mode,
        mechanism,
        epoch,
        state_version,
        last_commit_hash,
        previous_commit_hash,
        roster_hash,
        tree_hash,
        governance_policy,
        mode_policy,
        roster,
        membership,
        sender_chains,
        replay_state,
        phase,
    })
}

fn encode_governance_policy(out: &mut Vec<u8>, policy: &GovernancePolicy) -> AppResult<()> {
    out.push(policy.policy_version);
    out.push(policy.threshold);
    put_vec_len(
        out,
        policy.authorized_signers.len(),
        "authorized signer count",
    )?;
    for signer in &policy.authorized_signers {
        out.extend_from_slice(&signer.0);
    }
    Ok(())
}

fn decode_governance_policy(input: &[u8], offset: &mut usize) -> AppResult<GovernancePolicy> {
    let policy_version = take_u8(input, offset)?;
    let threshold = take_u8(input, offset)?;
    let signer_count = take_u32(input, offset)? as usize;
    let mut authorized_signers = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        authorized_signers.push(MemberId(take_array(input, offset)?));
    }
    Ok(GovernancePolicy {
        policy_version,
        threshold,
        authorized_signers,
    })
}

fn encode_roster(out: &mut Vec<u8>, roster: &[RosterEntry]) -> AppResult<()> {
    put_vec_len(out, roster.len(), "roster entry count")?;
    for entry in roster {
        out.extend_from_slice(&entry.member_id.0);
        out.extend_from_slice(&entry.device_identity_fingerprint.0);
        out.push(entry.role as u8);
        out.push(entry.status as u8);
        put_u32(out, entry.tree_leaf_slot);
        put_u64(out, entry.joined_epoch.0);
        put_u64(out, entry.removed_epoch.0);
    }
    Ok(())
}

fn decode_roster(input: &[u8], offset: &mut usize) -> AppResult<Vec<RosterEntry>> {
    let count = take_u32(input, offset)? as usize;
    let mut roster = Vec::with_capacity(count);
    for _ in 0..count {
        roster.push(RosterEntry {
            member_id: MemberId(take_array(input, offset)?),
            device_identity_fingerprint: IdentityFingerprint(take_array(input, offset)?),
            role: GroupRole::try_from(take_u8(input, offset)?)?,
            status: MemberStatus::try_from(take_u8(input, offset)?)?,
            tree_leaf_slot: take_u32(input, offset)?,
            joined_epoch: Epoch(take_u64(input, offset)?),
            removed_epoch: Epoch(take_u64(input, offset)?),
        });
    }
    Ok(roster)
}

fn encode_membership(
    out: &mut Vec<u8>,
    membership: &MembershipPrivateStateSnapshot,
) -> AppResult<()> {
    match membership {
        MembershipPrivateStateSnapshot::Empty => out.push(0),
        MembershipPrivateStateSnapshot::DirectWrap { epoch_secret } => {
            out.push(1);
            out.extend_from_slice(epoch_secret);
        }
        MembershipPrivateStateSnapshot::TreeKem {
            public_tree,
            leaf_index,
            path,
        } => {
            out.push(2);
            encode_public_tree(out, public_tree)?;
            match leaf_index {
                Some(index) => {
                    out.push(1);
                    put_u32(out, index.0);
                }
                None => out.push(0),
            }
            put_vec_len(out, path.len(), "private TreeKEM path length")?;
            for node in path {
                encode_private_path_node(out, node);
            }
        }
    }
    Ok(())
}

fn decode_membership(
    input: &[u8],
    offset: &mut usize,
) -> AppResult<MembershipPrivateStateSnapshot> {
    match take_u8(input, offset)? {
        0 => Ok(MembershipPrivateStateSnapshot::Empty),
        1 => Ok(MembershipPrivateStateSnapshot::DirectWrap {
            epoch_secret: take_array(input, offset)?,
        }),
        2 => {
            let public_tree = decode_public_tree(input, offset)?;
            let leaf_index = match take_u8(input, offset)? {
                0 => None,
                1 => Some(LeafIndex(take_u32(input, offset)?)),
                _ => {
                    return Err(AppError::InvalidInput(
                        "live TreeKEM leaf-index flag is invalid",
                    ))
                }
            };
            let path_len = take_u32(input, offset)? as usize;
            let mut path = Vec::with_capacity(path_len);
            for _ in 0..path_len {
                path.push(decode_private_path_node(input, offset)?);
            }
            Ok(MembershipPrivateStateSnapshot::TreeKem {
                public_tree,
                leaf_index,
                path,
            })
        }
        _ => Err(AppError::InvalidInput(
            "live group membership state is invalid",
        )),
    }
}

fn encode_public_tree(out: &mut Vec<u8>, tree: &PublicTree) -> AppResult<()> {
    out.push(tree.mode as u8);
    put_u32(out, tree.leaf_capacity);
    put_u64(out, tree.tree_version);
    match tree.epoch {
        Some(epoch) => {
            out.push(1);
            put_u64(out, epoch.0);
        }
        None => out.push(0),
    }
    put_vec_len(out, tree.nodes.len(), "public tree node count")?;
    for node in &tree.nodes {
        encode_public_tree_node(out, node)?;
    }
    Ok(())
}

fn decode_public_tree(input: &[u8], offset: &mut usize) -> AppResult<PublicTree> {
    let mode = GroupMode::try_from(take_u8(input, offset)?)?;
    let leaf_capacity = take_u32(input, offset)?;
    let tree_version = take_u64(input, offset)?;
    let epoch = match take_u8(input, offset)? {
        0 => None,
        1 => Some(Epoch(take_u64(input, offset)?)),
        _ => {
            return Err(AppError::InvalidInput(
                "live public-tree epoch flag is invalid",
            ))
        }
    };
    let node_count = take_u32(input, offset)? as usize;
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        nodes.push(decode_public_tree_node(input, offset)?);
    }
    Ok(PublicTree {
        mode,
        leaf_capacity,
        tree_version,
        epoch,
        nodes,
    })
}

fn encode_public_tree_node(out: &mut Vec<u8>, node: &PublicTreeNode) -> AppResult<()> {
    put_u32(out, node.node_index);
    encode_node_key(out, node.node_key.as_ref());
    match &node.leaf {
        Some(leaf) => {
            out.push(1);
            encode_public_leaf(out, leaf);
        }
        None => out.push(0),
    }
    Ok(())
}

fn decode_public_tree_node(input: &[u8], offset: &mut usize) -> AppResult<PublicTreeNode> {
    let node_index = take_u32(input, offset)?;
    let node_key = decode_node_key(input, offset)?;
    let leaf = match take_u8(input, offset)? {
        0 => None,
        1 => Some(decode_public_leaf(input, offset)?),
        _ => {
            return Err(AppError::InvalidInput(
                "live public-tree leaf flag is invalid",
            ))
        }
    };
    Ok(PublicTreeNode {
        node_index,
        node_key,
        leaf,
    })
}

fn encode_public_leaf(out: &mut Vec<u8>, leaf: &PublicLeaf) {
    out.extend_from_slice(&leaf.member_id.0);
    out.extend_from_slice(&leaf.device_identity_fingerprint.0);
    out.push(leaf.role as u8);
    put_u64(out, leaf.generation);
    encode_node_key(out, leaf.node_key.as_ref());
}

fn decode_public_leaf(input: &[u8], offset: &mut usize) -> AppResult<PublicLeaf> {
    Ok(PublicLeaf {
        member_id: MemberId(take_array(input, offset)?),
        device_identity_fingerprint: IdentityFingerprint(take_array(input, offset)?),
        role: GroupRole::try_from(take_u8(input, offset)?)?,
        generation: take_u64(input, offset)?,
        node_key: decode_node_key(input, offset)?,
    })
}

fn encode_node_key(out: &mut Vec<u8>, key: Option<&PublicNodeKey>) {
    match key {
        Some(key) => {
            out.push(1);
            out.extend_from_slice(&key.0);
        }
        None => out.push(0),
    }
}

fn decode_node_key(input: &[u8], offset: &mut usize) -> AppResult<Option<PublicNodeKey>> {
    match take_u8(input, offset)? {
        0 => Ok(None),
        1 => Ok(Some(PublicNodeKey(take_array(input, offset)?))),
        _ => Err(AppError::InvalidInput(
            "live public node-key flag is invalid",
        )),
    }
}

fn encode_private_path_node(out: &mut Vec<u8>, node: &PrivatePathNodeSecretSnapshot) {
    put_u32(out, node.node_index);
    out.extend_from_slice(&node.path_secret);
    out.extend_from_slice(&node.node_seed_d);
    out.extend_from_slice(&node.node_seed_z);
}

fn decode_private_path_node(
    input: &[u8],
    offset: &mut usize,
) -> AppResult<PrivatePathNodeSecretSnapshot> {
    Ok(PrivatePathNodeSecretSnapshot {
        node_index: take_u32(input, offset)?,
        path_secret: take_array(input, offset)?,
        node_seed_d: take_array(input, offset)?,
        node_seed_z: take_array(input, offset)?,
    })
}

fn encode_sender_chains(out: &mut Vec<u8>, state: &SenderChainStateSnapshot) -> AppResult<()> {
    put_vec_len(out, state.senders.len(), "sender chain count")?;
    for sender in &state.senders {
        out.extend_from_slice(&sender.sender.0);
        put_u64(out, sender.next_index);
        out.extend_from_slice(&sender.chain_key);
    }
    put_vec_len(out, state.skipped.len(), "skipped group key count")?;
    for skipped in &state.skipped {
        out.extend_from_slice(&skipped.sender.0);
        put_u64(out, skipped.index);
        out.extend_from_slice(&skipped.route_tag);
        out.extend_from_slice(&skipped.message_key);
    }
    Ok(())
}

fn decode_sender_chains(input: &[u8], offset: &mut usize) -> AppResult<SenderChainStateSnapshot> {
    let sender_count = take_u32(input, offset)? as usize;
    let mut senders = Vec::with_capacity(sender_count);
    for _ in 0..sender_count {
        senders.push(SenderChainCursorSnapshot {
            sender: MemberId(take_array(input, offset)?),
            next_index: take_u64(input, offset)?,
            chain_key: take_array(input, offset)?,
        });
    }
    let skipped_count = take_u32(input, offset)? as usize;
    let mut skipped = Vec::with_capacity(skipped_count);
    for _ in 0..skipped_count {
        skipped.push(SkippedGroupMessageKeySnapshot {
            sender: MemberId(take_array(input, offset)?),
            index: take_u64(input, offset)?,
            route_tag: take_array(input, offset)?,
            message_key: take_array(input, offset)?,
        });
    }
    Ok(SenderChainStateSnapshot { senders, skipped })
}

fn encode_group_replay(out: &mut Vec<u8>, state: &GroupReplayStateSnapshot) -> AppResult<()> {
    put_vec_len(out, state.senders.len(), "group replay sender count")?;
    for sender in &state.senders {
        out.extend_from_slice(&sender.sender.0);
        encode_replay_window(out, &sender.replay);
    }
    put_vec_len(
        out,
        state.accepted_messages.len(),
        "accepted group message count",
    )?;
    for accepted in &state.accepted_messages {
        out.extend_from_slice(&accepted.sender.0);
        put_u64(out, accepted.index);
        out.extend_from_slice(&accepted.route_tag);
    }
    Ok(())
}

fn decode_group_replay(input: &[u8], offset: &mut usize) -> AppResult<GroupReplayStateSnapshot> {
    let sender_count = take_u32(input, offset)? as usize;
    let mut senders = Vec::with_capacity(sender_count);
    for _ in 0..sender_count {
        senders.push(SenderReplayStateSnapshot {
            sender: MemberId(take_array(input, offset)?),
            replay: decode_replay_window(input, offset)?,
        });
    }
    let accepted_count = take_u32(input, offset)? as usize;
    let mut accepted_messages = Vec::with_capacity(accepted_count);
    for _ in 0..accepted_count {
        accepted_messages.push(AcceptedGroupMessage {
            sender: MemberId(take_array(input, offset)?),
            index: take_u64(input, offset)?,
            route_tag: take_array(input, offset)?,
        });
    }
    Ok(GroupReplayStateSnapshot {
        senders,
        accepted_messages,
    })
}

fn encode_replay_window(out: &mut Vec<u8>, replay: &ReplayWindowSnapshot) {
    match replay.highest_seen {
        Some(value) => {
            out.push(1);
            put_u64(out, value);
        }
        None => out.push(0),
    }
    put_u32(out, replay.bits.len() as u32);
    for word in replay.bits {
        put_u64(out, word);
    }
}

fn decode_replay_window(input: &[u8], offset: &mut usize) -> AppResult<ReplayWindowSnapshot> {
    let highest_seen = match take_u8(input, offset)? {
        0 => None,
        1 => Some(take_u64(input, offset)?),
        _ => return Err(AppError::InvalidInput("live replay flag is invalid")),
    };
    let word_count = take_u32(input, offset)? as usize;
    let mut bits = [0_u64; hydra_core::REPLAY_WINDOW_WORDS];
    if word_count != bits.len() {
        return Err(AppError::InvalidInput("live replay window size is invalid"));
    }
    for word in &mut bits {
        *word = take_u64(input, offset)?;
    }
    Ok(ReplayWindowSnapshot { highest_seen, bits })
}

fn write_checkpoint(
    path: &Path,
    rollback_counter: u64,
    file: &[u8],
    key: &SecretBytes<32>,
) -> AppResult<()> {
    let checkpoint = encode_checkpoint(rollback_counter, file, key);
    crash_safe_atomic_write(
        &checkpoint_path(path),
        &checkpoint,
        "live state checkpoint cannot be written",
    )?;
    append_rollback_log_entry(path, rollback_counter, file, key)
}

fn verify_checkpoint(
    path: &Path,
    rollback_counter: u64,
    file: &[u8],
    key: &SecretBytes<32>,
) -> AppResult<()> {
    let checkpoint_path = checkpoint_path(path);
    let bytes = fs::read(&checkpoint_path)
        .map_err(|_| AppError::InvalidInput("live state checkpoint is missing"))?;
    let expected = encode_checkpoint(rollback_counter, file, key);
    if bytes != expected {
        return Err(AppError::InvalidState(
            "live state rollback checkpoint mismatch",
        ));
    }
    verify_rollback_logs(path, rollback_counter, file, key)
}

fn encode_checkpoint(rollback_counter: u64, file: &[u8], key: &SecretBytes<32>) -> Vec<u8> {
    let file_hash = live_state_file_hash(rollback_counter, file);
    let mut body = Vec::with_capacity(CHECKPOINT_MAGIC.len() + 8 + 32);
    body.extend_from_slice(CHECKPOINT_MAGIC);
    body.extend_from_slice(&rollback_counter.to_be_bytes());
    body.extend_from_slice(&file_hash);
    let tag = RustCryptoBackend::hmac_sha3_256(key, &body);
    body.extend_from_slice(&tag);
    body
}

fn append_rollback_log_entry(
    path: &Path,
    rollback_counter: u64,
    file: &[u8],
    key: &SecretBytes<32>,
) -> AppResult<()> {
    let primary_path = rollback_log_path(path);
    let mirror_path = rollback_log_mirror_path(path);
    let primary = fs::read(&primary_path).unwrap_or_default();
    let mirror = fs::read(&mirror_path).unwrap_or_default();
    let base = choose_log_base(&primary, &mirror, key)?;
    let prev_hash = latest_log_entry_hash(&base).unwrap_or(ROLLBACK_ZERO_PREV);
    let entry = encode_rollback_log_entry(rollback_counter, &prev_hash, file, key);
    let mut next = base;
    next.extend_from_slice(&entry);
    crash_safe_atomic_write(
        &primary_path,
        &next,
        "live state rollback log cannot be written",
    )?;
    crash_safe_atomic_write(
        &mirror_path,
        &next,
        "live state rollback mirror cannot be written",
    )
}

fn verify_rollback_logs(
    path: &Path,
    rollback_counter: u64,
    file: &[u8],
    key: &SecretBytes<32>,
) -> AppResult<()> {
    let primary = fs::read(rollback_log_path(path)).unwrap_or_default();
    let mirror = fs::read(rollback_log_mirror_path(path)).unwrap_or_default();
    let primary_latest = parse_rollback_log(&primary, key)?;
    let mirror_latest = parse_rollback_log(&mirror, key)?;
    let latest = match (primary_latest, mirror_latest) {
        (Some(primary), Some(mirror)) => {
            if primary != mirror {
                return Err(AppError::InvalidState(
                    "live state rollback log quorum mismatch",
                ));
            }
            primary
        }
        (Some(latest), None) | (None, Some(latest)) => latest,
        (None, None) => return Err(AppError::InvalidInput("live state rollback log is missing")),
    };
    let expected_file_hash = live_state_file_hash(rollback_counter, file);
    if latest.counter != rollback_counter || latest.file_hash != expected_file_hash {
        return Err(AppError::InvalidState(
            "live state rollback log does not match database",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RollbackLogLatest {
    counter: u64,
    file_hash: [u8; 32],
    entry_hash: [u8; 32],
}

fn choose_log_base(primary: &[u8], mirror: &[u8], key: &SecretBytes<32>) -> AppResult<Vec<u8>> {
    let primary_latest = parse_rollback_log(primary, key)?;
    let mirror_latest = parse_rollback_log(mirror, key)?;
    match (primary_latest, mirror_latest) {
        (Some(primary_latest), Some(mirror_latest)) => {
            if primary_latest != mirror_latest {
                return Err(AppError::InvalidState("live state rollback logs diverged"));
            }
            Ok(primary.to_vec())
        }
        (Some(_), None) => Ok(primary.to_vec()),
        (None, Some(_)) => Ok(mirror.to_vec()),
        (None, None) => Ok(Vec::new()),
    }
}

fn parse_rollback_log(bytes: &[u8], key: &SecretBytes<32>) -> AppResult<Option<RollbackLogLatest>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if !bytes.len().is_multiple_of(ROLLBACK_LOG_ENTRY_SIZE) {
        return Err(AppError::InvalidState(
            "live state rollback log is truncated",
        ));
    }
    let mut prev_hash = ROLLBACK_ZERO_PREV;
    let mut latest = None;
    for chunk in bytes.chunks_exact(ROLLBACK_LOG_ENTRY_SIZE) {
        let parsed = parse_rollback_log_entry(chunk, &prev_hash, key)?;
        prev_hash = parsed.entry_hash;
        latest = Some(parsed);
    }
    Ok(latest)
}

fn parse_rollback_log_entry(
    entry: &[u8],
    expected_prev_hash: &[u8; 32],
    key: &SecretBytes<32>,
) -> AppResult<RollbackLogLatest> {
    if entry.len() != ROLLBACK_LOG_ENTRY_SIZE
        || &entry[..ROLLBACK_LOG_MAGIC.len()] != ROLLBACK_LOG_MAGIC.as_slice()
    {
        return Err(AppError::InvalidState(
            "live state rollback log entry is invalid",
        ));
    }
    let mut offset = ROLLBACK_LOG_MAGIC.len();
    let counter = u64::from_be_bytes(
        entry[offset..offset + 8]
            .try_into()
            .expect("fixed rollback counter"),
    );
    offset += 8;
    let prev_hash: [u8; 32] = entry[offset..offset + 32]
        .try_into()
        .expect("fixed prev hash");
    offset += 32;
    let file_hash: [u8; 32] = entry[offset..offset + 32]
        .try_into()
        .expect("fixed file hash");
    offset += 32;
    let tag = &entry[offset..offset + 32];
    if &prev_hash != expected_prev_hash {
        return Err(AppError::InvalidState(
            "live state rollback log chain is broken",
        ));
    }
    let expected_tag = RustCryptoBackend::hmac_sha3_256(key, &entry[..offset]);
    if tag != expected_tag.as_slice() {
        return Err(AppError::InvalidState(
            "live state rollback log tag is invalid",
        ));
    }
    Ok(RollbackLogLatest {
        counter,
        file_hash,
        entry_hash: RustCryptoBackend::sha3_256(entry),
    })
}

fn encode_rollback_log_entry(
    rollback_counter: u64,
    prev_hash: &[u8; 32],
    file: &[u8],
    key: &SecretBytes<32>,
) -> Vec<u8> {
    let file_hash = live_state_file_hash(rollback_counter, file);
    let mut entry = Vec::with_capacity(ROLLBACK_LOG_ENTRY_SIZE);
    entry.extend_from_slice(ROLLBACK_LOG_MAGIC);
    entry.extend_from_slice(&rollback_counter.to_be_bytes());
    entry.extend_from_slice(prev_hash);
    entry.extend_from_slice(&file_hash);
    let tag = RustCryptoBackend::hmac_sha3_256(key, &entry);
    entry.extend_from_slice(&tag);
    entry
}

fn latest_log_entry_hash(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes
        .chunks_exact(ROLLBACK_LOG_ENTRY_SIZE)
        .last()
        .map(RustCryptoBackend::sha3_256)
}

fn live_state_file_hash(rollback_counter: u64, file: &[u8]) -> [u8; 32] {
    let mut hash_input = Vec::with_capacity(8 + file.len());
    hash_input.extend_from_slice(&rollback_counter.to_be_bytes());
    hash_input.extend_from_slice(file);
    let hash = RustCryptoBackend::sha3_256(&hash_input);
    hash_input.zeroize();
    hash
}

fn checkpoint_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}checkpoint",
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    ))
}

fn rollback_log_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}rollback.log",
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    ))
}

fn rollback_log_mirror_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}rollback.mirror.log",
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    ))
}

fn put_vec_len(out: &mut Vec<u8>, len: usize, label: &'static str) -> AppResult<()> {
    let len = u32::try_from(len).map_err(|_| AppError::InvalidInput(label))?;
    put_u32(out, len);
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn take_u8(input: &[u8], offset: &mut usize) -> AppResult<u8> {
    Ok(take_exact(input, offset, 1)?[0])
}

fn take_u32(input: &[u8], offset: &mut usize) -> AppResult<u32> {
    Ok(u32::from_be_bytes(take_array(input, offset)?))
}

fn take_u64(input: &[u8], offset: &mut usize) -> AppResult<u64> {
    Ok(u64::from_be_bytes(take_array(input, offset)?))
}

fn take_array<const N: usize>(input: &[u8], offset: &mut usize) -> AppResult<[u8; N]> {
    let bytes = take_exact(input, offset, N)?;
    let mut out = [0_u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn take_exact<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> AppResult<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(AppError::InvalidInput("live state length overflow"))?;
    if end > input.len() {
        return Err(AppError::InvalidInput("live state is truncated"));
    }
    let bytes = &input[*offset..end];
    *offset = end;
    Ok(bytes)
}

const fn session_role_to_u8(role: SessionRole) -> u8 {
    match role {
        SessionRole::Initiator => 1,
        SessionRole::Responder => 2,
    }
}

fn session_role_from_u8(value: u8) -> AppResult<SessionRole> {
    match value {
        1 => Ok(SessionRole::Initiator),
        2 => Ok(SessionRole::Responder),
        _ => Err(AppError::InvalidInput("live session role is invalid")),
    }
}

const fn session_phase_to_u8(phase: SessionPhase) -> u8 {
    match phase {
        SessionPhase::Established => 1,
        SessionPhase::Refreshing => 2,
        SessionPhase::Closing => 3,
        SessionPhase::Closed => 4,
    }
}

fn session_phase_from_u8(value: u8) -> AppResult<SessionPhase> {
    match value {
        1 => Ok(SessionPhase::Established),
        2 => Ok(SessionPhase::Refreshing),
        3 => Ok(SessionPhase::Closing),
        4 => Ok(SessionPhase::Closed),
        _ => Err(AppError::InvalidInput("live session phase is invalid")),
    }
}

const fn direction_to_u8(direction: Direction) -> u8 {
    match direction {
        Direction::InitiatorToResponder => 1,
        Direction::ResponderToInitiator => 2,
    }
}

fn direction_from_u8(value: u8) -> AppResult<Direction> {
    match value {
        1 => Ok(Direction::InitiatorToResponder),
        2 => Ok(Direction::ResponderToInitiator),
        _ => Err(AppError::InvalidInput(
            "live skipped-key direction is invalid",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppIdentity, AppSessionRole, SessionHandshakeExport};
    use hydra_group::GroupRole;

    fn temp_path(name: &str) -> PathBuf {
        let unique = RustCryptoBackend::sha3_256(name.as_bytes());
        std::env::temp_dir().join(format!("hydra-live-state-{name}-{:02x}.bin", unique[0]))
    }

    #[test]
    fn direct_session_restarts_and_continues_after_live_state_restore() {
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let transcript = [0x42; 64];
        let secret = [0x24; 32];
        let mut alice_session = AppSession::start(
            AppSessionRole::Initiator,
            &alice,
            bob.public_identity(),
            SessionHandshakeExport::from_test_bytes(secret, transcript),
        )
        .unwrap();
        let mut bob_session = AppSession::start(
            AppSessionRole::Responder,
            &bob,
            alice.public_identity(),
            SessionHandshakeExport::from_test_bytes(secret, transcript),
        )
        .unwrap();
        let conversation_id = ConversationId([7; 32]);
        let first = alice_session.send(b"before restart").unwrap();
        assert_eq!(
            bob_session.receive(first.as_envelope()).unwrap().content(),
            b"before restart"
        );

        let path = temp_path("session");
        let password = b"live state password";
        let mut store = LiveStateStore::create(&path, password).unwrap();
        store.upsert_session(conversation_id, &alice_session);
        store.save(password).unwrap();
        let loaded = LiveStateStore::load(&path, password).unwrap();
        let mut restored_alice = loaded.restore_session(conversation_id).unwrap();
        let second = restored_alice.send(b"after restart").unwrap();
        assert_eq!(
            bob_session.receive(second.as_envelope()).unwrap().content(),
            b"after restart"
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(checkpoint_path(&path));
        let _ = fs::remove_file(rollback_log_path(&path));
        let _ = fs::remove_file(rollback_log_mirror_path(&path));
    }

    #[test]
    fn lite_group_restarts_and_continues_after_live_state_restore() {
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let mut alice_group = AppGroup::create_lite(&alice, GroupRole::Member).unwrap();
        let welcome = alice_group
            .add_lite_member(&alice, bob.public_identity(), GroupRole::Member)
            .unwrap();
        let mut bob_group = AppGroup::install_lite_welcome(&bob, welcome).unwrap();
        let conversation_id = ConversationId([8; 32]);
        let first = alice_group.send_signed(&alice, b"before restart").unwrap();
        assert_eq!(
            bob_group
                .receive_signed(first.as_envelope())
                .unwrap()
                .content(),
            b"before restart"
        );

        let path = temp_path("group");
        let password = b"live state password";
        let mut store = LiveStateStore::create(&path, password).unwrap();
        store.upsert_group(conversation_id, &alice_group).unwrap();
        store.save(password).unwrap();
        let loaded = LiveStateStore::load(&path, password).unwrap();
        let mut restored_alice = loaded.restore_group(conversation_id).unwrap();
        let second = restored_alice
            .send_signed(&alice, b"after restart")
            .unwrap();
        assert_eq!(
            bob_group
                .receive_signed(second.as_envelope())
                .unwrap()
                .content(),
            b"after restart"
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(checkpoint_path(&path));
        let _ = fs::remove_file(rollback_log_path(&path));
        let _ = fs::remove_file(rollback_log_mirror_path(&path));
    }

    #[test]
    fn stale_encrypted_live_state_rollback_is_detected() {
        let path = temp_path("rollback");
        let password = b"live state password";
        let mut store = LiveStateStore::create(&path, password).unwrap();
        let old_file = fs::read(&path).unwrap();
        store.save(password).unwrap();
        fs::write(&path, old_file).unwrap();
        let error_class = match LiveStateStore::load(&path, password) {
            Ok(_) => panic!("rollback load unexpectedly succeeded"),
            Err(err) => err.class(),
        };
        assert_eq!(error_class, crate::AppErrorClass::InvalidState);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(checkpoint_path(&path));
        let _ = fs::remove_file(rollback_log_path(&path));
        let _ = fs::remove_file(rollback_log_mirror_path(&path));
    }

    #[test]
    fn rollback_log_detects_checkpoint_and_database_rollback_without_log_rollback() {
        let path = temp_path("rollback-log");
        let password = b"live state password";
        let mut store = LiveStateStore::create(&path, password).unwrap();
        let old_file = fs::read(&path).unwrap();
        let old_checkpoint = fs::read(checkpoint_path(&path)).unwrap();
        store.save(password).unwrap();
        fs::write(&path, old_file).unwrap();
        fs::write(checkpoint_path(&path), old_checkpoint).unwrap();
        let error_class = match LiveStateStore::load(&path, password) {
            Ok(_) => panic!("rollback load unexpectedly succeeded"),
            Err(err) => err.class(),
        };
        assert_eq!(error_class, crate::AppErrorClass::InvalidState);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(checkpoint_path(&path));
        let _ = fs::remove_file(rollback_log_path(&path));
        let _ = fs::remove_file(rollback_log_mirror_path(&path));
    }
}
