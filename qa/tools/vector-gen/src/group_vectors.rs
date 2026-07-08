use super::{VectorMetadata, fixed, sign_digest, tv_draw, write_bytes, write_metadata};
use hydra_core::{
    AEAD_NONCE_SIZE, FULL_MAX_CONTENT_SIZE, LITE_MAX_CONTENT_SIZE, ML_DSA_65_SIG_SIZE,
    ML_KEM_768_EK_SIZE, STANDARD_MAX_CONTENT_SIZE, SUITE_ID,
    types::{EnvelopeClass, Epoch, GroupId, IdentityFingerprint, OuterMode, Secret32},
};
use hydra_crypto::{CryptoBackend, MlDsaVerificationKey, RustCryptoBackend, SecretBytes};
use hydra_envelope::{
    OuterHeader, ProtectedRecord, decode_outer_header, encode_outer_header, encode_protected_record,
};
use hydra_group::{
    ChangePayload, CommitChange, CommitCore, CommitKind, CommitPlan, CommitSignature,
    GovernancePolicy, GroupMode, GroupRole, GroupState, GroupStateConfig, MemberId, MemberStatus,
    MembershipMechanism, MembershipPrivateState, ModePolicy, PrivatePath, PublicLeaf,
    PublicNodeKey, PublicTree, RosterEntry, SenderMessageStep, StateVersion, TreeKemPathContext,
    TreeKemWrapContext, UpdatePath, apply_prepared_commit, change_payload_hash, commit_hash,
    commit_sig_digest, derive_and_install_path, derive_epoch_key_for_context,
    encode_change_payload, encode_commit_core, encode_governance_policy, encode_mode_policy,
    encode_roster, encode_roster_entry, encode_signature_set, encrypt_path_updates,
    group_data_signature_digest, identity_fingerprint, leaf_node_index, lp, prepare_commit,
    treekem_key_schedule_commitment, update_path_hash,
};
use ml_dsa::{MlDsa65, SigningKey, signature::Keypair};
use ml_kem::{FromSeed, MlKem768, kem::KeyExport};
use std::{fs, path::Path};

fn write_owned(
    root: &Path,
    category: &str,
    vector_id: &str,
    metadata: &VectorMetadata<'_>,
    artifacts: &[(String, Vec<u8>)],
) {
    let directory = root.join(category).join(vector_id);
    fs::create_dir_all(&directory).expect("create group vector directory");
    let references = artifacts
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    for (name, bytes) in &references {
        write_bytes(&directory, name, bytes);
    }
    write_metadata(&directory, vector_id, metadata, &references);
}

fn metadata<'a>(
    result: &'a str,
    expected_state: &'a str,
    cleanup: &'a str,
    entropy: &'a [(&'a str, u32, usize, &'a str)],
) -> VectorMetadata<'a> {
    VectorMetadata {
        backend: "hydra-group with hydra-crypto RustCrypto candidate adapter; single backend",
        result,
        expected_state,
        cleanup,
        entropy,
    }
}

fn draw32(vector_id: &str, purpose: &str, occurrence: u32) -> [u8; 32] {
    fixed(&tv_draw(vector_id, purpose, occurrence, 32), purpose)
}

fn draw64(vector_id: &str, purpose: &str, occurrence: u32) -> [u8; 64] {
    fixed(&tv_draw(vector_id, purpose, occurrence, 64), purpose)
}

fn group_id(vector_id: &str) -> GroupId {
    GroupId(draw32(vector_id, "group-id", 0))
}

fn member_id(vector_id: &str, occurrence: u32) -> MemberId {
    MemberId(draw32(vector_id, "member-id", occurrence))
}

fn fingerprint(vector_id: &str, occurrence: u32) -> IdentityFingerprint {
    IdentityFingerprint(draw32(vector_id, "identity-fingerprint", occurrence))
}

fn signature(vector_id: &str, signer: MemberId, occurrence: u32) -> CommitSignature {
    CommitSignature {
        signer,
        signature: fixed(
            &tv_draw(
                vector_id,
                "commit-signature",
                occurrence,
                ML_DSA_65_SIG_SIZE,
            ),
            "commit signature",
        ),
    }
}

fn direct_secret(vector_id: &str, occurrence: u32) -> [u8; 32] {
    draw32(vector_id, "direct-epoch-secret", occurrence)
}

fn nonce(vector_id: &str, occurrence: u32) -> [u8; 32] {
    draw32(vector_id, "commit-nonce", occurrence)
}

fn entry(
    member_id: MemberId,
    identity_fingerprint: IdentityFingerprint,
    role: GroupRole,
    slot: u32,
    joined_epoch: Epoch,
) -> RosterEntry {
    RosterEntry {
        member_id,
        device_identity_fingerprint: identity_fingerprint,
        role,
        status: MemberStatus::Active,
        tree_leaf_slot: slot,
        joined_epoch,
        removed_epoch: Epoch(0),
    }
}

fn empty_lite_state(vector_id: &str, signer: MemberId) -> GroupState {
    GroupState::new_empty(
        group_id(vector_id),
        GroupMode::Lite,
        MembershipMechanism::DirectWrap,
        GovernancePolicy::single_signer(signer),
        ModePolicy::default(),
    )
    .expect("empty Lite group state")
}

fn raw_roster_state_commitment(roster: &[RosterEntry]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(
        &u16::try_from(roster.len())
            .expect("state-commitment roster count fits u16")
            .to_be_bytes(),
    );
    for entry in roster {
        encoded.extend_from_slice(&encode_roster_entry(entry));
    }
    encoded
}

fn state_commitment(state: &GroupState) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"HYDRA-MSG/test/group-state");
    encoded.extend_from_slice(&state.group_id.0);
    encoded.push(state.mode as u8);
    encoded.push(state.mechanism as u8);
    encoded.extend_from_slice(&state.epoch.0.to_be_bytes());
    encoded.extend_from_slice(&state.state_version.0.to_be_bytes());
    encoded.extend_from_slice(&state.last_commit_hash);
    encoded.extend_from_slice(&state.previous_commit_hash);
    encoded.extend_from_slice(&state.roster_hash);
    encoded.extend_from_slice(&state.tree_hash);
    encoded.extend_from_slice(
        &encode_governance_policy(&state.governance_policy).expect("governance encodes"),
    );
    encoded.extend_from_slice(&encode_mode_policy(state.mode_policy));
    match encode_roster(state.mode, &state.roster) {
        Ok(roster) => {
            encoded.push(1);
            encoded.extend_from_slice(&roster);
        }
        Err(_) => {
            encoded.push(0);
            encoded.extend_from_slice(&raw_roster_state_commitment(&state.roster));
        }
    }
    encoded.push(state.phase as u8);
    state.sender_chains.append_test_commitment(&mut encoded);
    encoded.extend_from_slice(&(state.replay_state.senders.len() as u64).to_be_bytes());
    for sender in &state.replay_state.senders {
        encoded.extend_from_slice(&sender.sender.0);
    }
    RustCryptoBackend::sha3_256(&encoded).to_vec()
}

fn commit_artifacts(
    prefix: &str,
    prepared: &hydra_group::PreparedCommit,
) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            format!("{prefix}_commit_core"),
            prepared.encoded_core.clone(),
        ),
        (
            format!("{prefix}_signature_digest"),
            prepared.signature_digest.to_vec(),
        ),
        (
            format!("{prefix}_commit_hash"),
            prepared.commit_hash.to_vec(),
        ),
        (
            format!("{prefix}_signature_set"),
            encode_signature_set(&prepared.signatures).expect("signature set encodes"),
        ),
    ]
}

fn generate_group_create(root: &Path) {
    const ID: &str = "TV-GROUP-CREATE-000";
    let alice = member_id(ID, 0);
    let alice_entry = entry(alice, fingerprint(ID, 0), GroupRole::Member, 0, Epoch(0));
    let governance = GovernancePolicy::single_signer(alice);
    let mut state = empty_lite_state(ID, alice);
    let before = state_commitment(&state);
    let direct_epoch_secret = direct_secret(ID, 0);
    let plan = CommitPlan {
        committer: alice,
        commit_nonce: nonce(ID, 0),
        change: CommitChange::Create {
            new_roster: vec![alice_entry],
            new_governance_policy: governance.clone(),
            new_mode_policy: ModePolicy::default(),
            new_tree_hash: [0; 64],
        },
        signatures: vec![signature(ID, alice, 0)],
        update_path: None,
        direct_epoch_secret: Some(direct_epoch_secret),
    };
    let prepared = prepare_commit(&state, plan).expect("prepare group create");
    assert_eq!(prepared.core.new_epoch, Epoch(0));
    assert_eq!(prepared.core.new_state_version, StateVersion(0));
    let mut artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.0.to_vec()),
        (
            "alice_identity_fingerprint".to_owned(),
            fingerprint(ID, 0).0.to_vec(),
        ),
        (
            "direct_epoch_secret".to_owned(),
            direct_epoch_secret.to_vec(),
        ),
        ("state_before".to_owned(), before),
    ];
    artifacts.extend(commit_artifacts("create", &prepared));
    apply_prepared_commit(&mut state, prepared).expect("apply group create");
    assert_eq!(state.roster.len(), 1);
    assert_eq!(state.sender_chains.len(), 1);
    artifacts.extend([
        (
            "canonical_roster".to_owned(),
            encode_roster(state.mode, &state.roster).expect("roster encodes"),
        ),
        (
            "canonical_governance_policy".to_owned(),
            encode_governance_policy(&governance).expect("governance encodes"),
        ),
        (
            "canonical_mode_policy".to_owned(),
            encode_mode_policy(state.mode_policy).to_vec(),
        ),
        ("state_after".to_owned(), state_commitment(&state)),
    ]);
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Lite group create commit prepared and applied deterministically",
            "epoch/state_version remain 0 for create; one sender chain installed",
            "direct epoch secret retained only as vector artifact",
            &[
                ("group-id", 0, 32, "group_id"),
                ("member-id", 0, 32, "alice_member_id"),
                ("identity-fingerprint", 0, 32, "alice_identity_fingerprint"),
                ("direct-epoch-secret", 0, 32, "direct_epoch_secret"),
                ("commit-nonce", 0, 32, "create_commit_core"),
                (
                    "commit-signature",
                    0,
                    ML_DSA_65_SIG_SIZE,
                    "create_signature_set",
                ),
            ],
        ),
        &artifacts,
    );
}

fn create_lite_state_for_join(vector_id: &str) -> (GroupState, MemberId, MemberId) {
    let alice = member_id(vector_id, 0);
    let bob = member_id(vector_id, 1);
    let alice_entry = entry(
        alice,
        fingerprint(vector_id, 0),
        GroupRole::Member,
        0,
        Epoch(0),
    );
    let mut state = empty_lite_state(vector_id, alice);
    let create = CommitPlan {
        committer: alice,
        commit_nonce: nonce(vector_id, 0),
        change: CommitChange::Create {
            new_roster: vec![alice_entry],
            new_governance_policy: GovernancePolicy::single_signer(alice),
            new_mode_policy: ModePolicy::default(),
            new_tree_hash: [0; 64],
        },
        signatures: vec![signature(vector_id, alice, 0)],
        update_path: None,
        direct_epoch_secret: Some(direct_secret(vector_id, 0)),
    };
    let prepared = prepare_commit(&state, create).expect("prepare base create");
    apply_prepared_commit(&mut state, prepared).expect("apply base create");
    (state, alice, bob)
}

fn generate_group_join(root: &Path) {
    const ID: &str = "TV-GROUP-JOIN-000";
    let (mut state, alice, bob) = create_lite_state_for_join(ID);
    let before = state_commitment(&state);
    let bob_entry = entry(bob, fingerprint(ID, 1), GroupRole::Member, 1, Epoch(1));
    let direct_epoch_secret = direct_secret(ID, 1);
    let plan = CommitPlan {
        committer: alice,
        commit_nonce: nonce(ID, 1),
        change: CommitChange::Join {
            new_entry: bob_entry,
        },
        signatures: vec![signature(ID, alice, 1)],
        update_path: None,
        direct_epoch_secret: Some(direct_epoch_secret),
    };
    let prepared = prepare_commit(&state, plan).expect("prepare group join");
    assert_eq!(prepared.core.old_epoch, Epoch(0));
    assert_eq!(prepared.core.new_epoch, Epoch(1));
    assert_eq!(prepared.core.old_state_version, StateVersion(0));
    assert_eq!(prepared.core.new_state_version, StateVersion(1));
    let mut artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.0.to_vec()),
        ("bob_member_id".to_owned(), bob.0.to_vec()),
        (
            "bob_identity_fingerprint".to_owned(),
            fingerprint(ID, 1).0.to_vec(),
        ),
        (
            "direct_epoch_secret".to_owned(),
            direct_epoch_secret.to_vec(),
        ),
        ("state_before".to_owned(), before),
    ];
    artifacts.extend(commit_artifacts("join", &prepared));
    apply_prepared_commit(&mut state, prepared).expect("apply group join");
    assert_eq!(state.roster.len(), 2);
    assert_eq!(state.sender_chains.len(), 2);
    artifacts.extend([
        (
            "canonical_roster".to_owned(),
            encode_roster(state.mode, &state.roster).expect("roster encodes"),
        ),
        ("state_after".to_owned(), state_commitment(&state)),
    ]);
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Lite group join commit prepared and applied deterministically",
            "epoch advances 0->1, state_version advances 0->1, and two sender chains are installed",
            "direct epoch secret retained only as vector artifact",
            &[
                ("group-id", 0, 32, "group_id"),
                ("member-id", 0, 32, "alice_member_id"),
                ("member-id", 1, 32, "bob_member_id"),
                ("identity-fingerprint", 1, 32, "bob_identity_fingerprint"),
                ("direct-epoch-secret", 1, 32, "direct_epoch_secret"),
                ("commit-nonce", 1, 32, "join_commit_core"),
                (
                    "commit-signature",
                    1,
                    ML_DSA_65_SIG_SIZE,
                    "join_signature_set",
                ),
            ],
        ),
        &artifacts,
    );
}

fn generate_invalid_join(root: &Path) {
    const ID: &str = "TV-GROUP-BAD-000";
    let (state, alice, bob) = create_lite_state_for_join(ID);
    let before = state_commitment(&state);
    let bad_entry = entry(bob, fingerprint(ID, 1), GroupRole::Audience, 1, Epoch(1));
    let plan = CommitPlan {
        committer: alice,
        commit_nonce: nonce(ID, 1),
        change: CommitChange::Join {
            new_entry: bad_entry,
        },
        signatures: vec![signature(ID, alice, 1)],
        update_path: None,
        direct_epoch_secret: Some(direct_secret(ID, 1)),
    };
    assert!(prepare_commit(&state, plan).is_err());
    let after = state_commitment(&state);
    assert_eq!(before, after);
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.0.to_vec()),
        ("bad_bob_member_id".to_owned(), bob.0.to_vec()),
        ("state_before".to_owned(), before),
        ("state_after".to_owned(), after),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "invalid Lite join role rejected before commit preparation",
            "parent state commitment remains unchanged",
            "candidate direct epoch secret is not installed",
            &[
                ("group-id", 0, 32, "group_id"),
                ("member-id", 0, 32, "alice_member_id"),
                ("member-id", 1, 32, "bad_bob_member_id"),
            ],
        ),
        &artifacts,
    );
}

struct IdentityMaterial {
    member_id: MemberId,
    signing_key: SigningKey<MlDsa65>,
    verification_key: Vec<u8>,
    fingerprint: IdentityFingerprint,
}

fn identity_material(vector_id: &str, occurrence: u32) -> IdentityMaterial {
    let xi: [u8; 32] = fixed(
        &tv_draw(vector_id, "mldsa-xi", occurrence, 32),
        "identity xi",
    );
    let signing_key = SigningKey::<MlDsa65>::from_seed(&xi.into());
    let verification_key = signing_key.verifying_key().encode();
    let verification_key_bytes = AsRef::<[u8]>::as_ref(&verification_key).to_vec();
    let verification = MlDsaVerificationKey::from_bytes(&verification_key_bytes)
        .expect("generated ML-DSA verification key decodes");
    IdentityMaterial {
        member_id: member_id(vector_id, occurrence),
        signing_key,
        verification_key: verification_key_bytes,
        fingerprint: identity_fingerprint(&verification),
    }
}

fn real_commit_signature(
    vector_id: &str,
    signer: &IdentityMaterial,
    digest: &[u8; 64],
    occurrence: u32,
) -> CommitSignature {
    let rnd: [u8; 32] = fixed(
        &tv_draw(vector_id, "mldsa-rnd", occurrence, 32),
        "commit signature randomness",
    );
    CommitSignature {
        signer: signer.member_id,
        signature: sign_digest(&signer.signing_key, digest, &rnd),
    }
}

fn node_key_from_seed(vector_id: &str, purpose: &str, occurrence: u32) -> PublicNodeKey {
    let d: [u8; 32] = fixed(&tv_draw(vector_id, purpose, occurrence * 2, 32), "ML-KEM d");
    let z: [u8; 32] = fixed(
        &tv_draw(vector_id, purpose, occurrence * 2 + 1, 32),
        "ML-KEM z",
    );
    let mut seed_bytes = [0_u8; 64];
    seed_bytes[..32].copy_from_slice(&d);
    seed_bytes[32..].copy_from_slice(&z);
    let seed: ml_kem::Seed = seed_bytes.into();
    let (_dk, ek) = MlKem768::from_seed(&seed);
    let ek_bytes = ek.to_bytes();
    let mut out = [0_u8; ML_KEM_768_EK_SIZE];
    out.copy_from_slice(ek_bytes.as_ref());
    PublicNodeKey(out)
}

fn tree_leaf(identity: &IdentityMaterial, role: GroupRole, node_key: PublicNodeKey) -> PublicLeaf {
    PublicLeaf {
        member_id: identity.member_id,
        device_identity_fingerprint: identity.fingerprint,
        role,
        generation: 0,
        node_key: Some(node_key),
    }
}

fn entry_for_identity(
    identity: &IdentityMaterial,
    role: GroupRole,
    slot: u32,
    joined_epoch: Epoch,
) -> RosterEntry {
    entry(
        identity.member_id,
        identity.fingerprint,
        role,
        slot,
        joined_epoch,
    )
}

struct JoinWelcomeEncoding<'a> {
    mode: GroupMode,
    mechanism: MembershipMechanism,
    recipient: MemberId,
    encoded_core: &'a [u8],
    change_payload: &'a [u8],
    signature_set: &'a [u8],
    commit_hash: &'a [u8; 64],
    roster: &'a [RosterEntry],
    governance_policy: &'a GovernancePolicy,
    mode_policy: ModePolicy,
    update_path: Option<&'a UpdatePath>,
    direct_epoch_secret: Option<&'a [u8; 32]>,
    tree_root_secret: Option<&'a [u8; 32]>,
    public_tree_hash: &'a [u8; 64],
}

fn encode_join_welcome(input: &JoinWelcomeEncoding<'_>) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"HYDRA-MSG/v1/group/welcome-candidate");
    encoded.push(input.mode as u8);
    encoded.push(input.mechanism as u8);
    encoded.extend_from_slice(&input.recipient.0);
    encoded.extend_from_slice(&length_prefixed_bytes(input.encoded_core));
    encoded.extend_from_slice(&length_prefixed_bytes(input.change_payload));
    encoded.extend_from_slice(&length_prefixed_bytes(input.signature_set));
    encoded.extend_from_slice(input.commit_hash);
    encoded.extend_from_slice(&length_prefixed_bytes(
        &encode_roster(input.mode, input.roster).expect("welcome roster encodes"),
    ));
    encoded.extend_from_slice(&length_prefixed_bytes(
        &encode_governance_policy(input.governance_policy).expect("welcome governance encodes"),
    ));
    encoded.extend_from_slice(&encode_mode_policy(input.mode_policy));
    match input.mechanism {
        MembershipMechanism::DirectWrap => {
            encoded.push(0x01);
            encoded.extend_from_slice(input.direct_epoch_secret.expect("direct secret present"));
        }
        MembershipMechanism::TreeKem => {
            encoded.push(0x02);
            encoded.extend_from_slice(input.public_tree_hash);
            encoded.extend_from_slice(input.tree_root_secret.expect("tree root secret present"));
            encoded.extend_from_slice(&length_prefixed_bytes(
                &hydra_group::encode_update_path(input.update_path.expect("update path present"))
                    .expect("update path encodes"),
            ));
        }
    }
    encoded
}

fn length_prefixed_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("vector artifact length fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    out
}

fn verify_welcome_recipient(
    welcome: &[u8],
    expected_recipient: MemberId,
) -> Result<(), &'static str> {
    let prefix = b"HYDRA-MSG/v1/group/welcome-candidate";
    if welcome.len() < prefix.len() + 2 + 32 || &welcome[..prefix.len()] != prefix {
        return Err("invalid welcome prefix");
    }
    let recipient_start = prefix.len() + 2;
    let recipient_end = recipient_start + 32;
    if &welcome[recipient_start..recipient_end] != expected_recipient.0.as_slice() {
        return Err("wrong recipient");
    }
    Ok(())
}

fn build_tree_parent_state(
    vector_id: &str,
    mode: GroupMode,
    alice_role: GroupRole,
    carol_role: GroupRole,
) -> (
    GroupState,
    IdentityMaterial,
    IdentityMaterial,
    IdentityMaterial,
    [u8; 64],
) {
    let alice = identity_material(vector_id, 0);
    let bob = identity_material(vector_id, 1);
    let carol = identity_material(vector_id, 2);
    let alice_entry = entry_for_identity(&alice, alice_role, 0, Epoch(0));
    let carol_entry = entry_for_identity(&carol, carol_role, 2, Epoch(0));
    let governance = GovernancePolicy::single_signer(alice.member_id);
    let mut tree = PublicTree::new(mode, Some(Epoch(0))).expect("TreeKEM tree");
    tree.occupy_leaf(
        0,
        tree_leaf(
            &alice,
            alice_role,
            node_key_from_seed(vector_id, "alice-leaf-key", 0),
        ),
    )
    .expect("occupy alice leaf");
    tree.occupy_leaf(
        2,
        tree_leaf(
            &carol,
            carol_role,
            node_key_from_seed(vector_id, "carol-leaf-key", 0),
        ),
    )
    .expect("occupy carol leaf");
    let before_path_hash = tree.tree_hash().expect("tree hash");
    let mut private_path = PrivatePath::default();
    let parent_leaf_secret = Secret32::new(draw32(vector_id, "parent-leaf-secret", 0));
    let parent_context = TreeKemPathContext {
        group_id: group_id(vector_id),
        mode,
        epoch: Epoch(0),
        state_version: StateVersion(0),
        leaf_slot: 0,
        commit_nonce: nonce(vector_id, 0),
        tree_hash: before_path_hash,
    };
    let parent_update = derive_and_install_path(
        &mut tree,
        &mut private_path,
        parent_context,
        &parent_leaf_secret,
    )
    .expect("derive parent private path");
    let tree_hash = parent_update.tree_hash_after;
    let mut state = GroupState::new_validated(GroupStateConfig {
        group_id: group_id(vector_id),
        mode,
        mechanism: MembershipMechanism::TreeKem,
        epoch: Epoch(0),
        state_version: StateVersion(0),
        governance_policy: governance,
        mode_policy: ModePolicy::default(),
        roster: vec![alice_entry, carol_entry],
    })
    .expect("validated TreeKEM parent state");
    state.tree_hash = tree_hash;
    state.membership = MembershipPrivateState::TreeKem {
        public_tree: tree,
        private_path,
    };
    (state, alice, bob, carol, tree_hash)
}

type SignedTreeJoinCore = (Vec<u8>, [u8; 64], [u8; 64], Vec<CommitSignature>, Vec<u8>);

fn sign_tree_join_core(
    vector_id: &str,
    signer: &IdentityMaterial,
    core: CommitCore,
    sig_occurrence: u32,
) -> SignedTreeJoinCore {
    let encoded_core = encode_commit_core(&core).expect("commit core encodes");
    let signature_digest = commit_sig_digest(&encoded_core).expect("signature digest");
    let commit_hash_value = commit_hash(&encoded_core).expect("commit hash");
    let signature = real_commit_signature(vector_id, signer, &signature_digest, sig_occurrence);
    let signatures = vec![signature];
    let signature_set = encode_signature_set(&signatures).expect("signature set encodes");
    (
        encoded_core,
        signature_digest,
        commit_hash_value,
        signatures,
        signature_set,
    )
}

struct TreeJoinInstallState<'a> {
    roster: Vec<RosterEntry>,
    roster_hash_value: [u8; 64],
    tree: PublicTree,
    private_path: PrivatePath,
    root_secret: &'a [u8; 32],
    commit_hash_value: [u8; 64],
    tree_hash_value: [u8; 64],
}

fn install_tree_join_state(state: &mut GroupState, install: TreeJoinInstallState<'_>) {
    state.previous_commit_hash = state.last_commit_hash;
    state.last_commit_hash = install.commit_hash_value;
    state.epoch = Epoch(1);
    state.state_version = StateVersion(1);
    state.roster = install.roster;
    state.roster_hash = install.roster_hash_value;
    state.tree_hash = install.tree_hash_value;
    state.membership = MembershipPrivateState::TreeKem {
        public_tree: install.tree,
        private_path: install.private_path,
    };
    let epoch_key = derive_epoch_key_for_context(
        &Secret32::new(*install.root_secret),
        &state.epoch_key_context(),
    )
    .expect("derive TreeKEM epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("install TreeKEM sender chains");
}

fn recipient_tree_state_from_welcome(
    parent: &GroupState,
    roster: Vec<RosterEntry>,
    roster_hash_value: [u8; 64],
    public_tree: PublicTree,
    root_secret: &[u8; 32],
    commit_hash_value: [u8; 64],
    tree_hash_value: [u8; 64],
) -> GroupState {
    let mut state = GroupState::new_validated(GroupStateConfig {
        group_id: parent.group_id,
        mode: parent.mode,
        mechanism: MembershipMechanism::TreeKem,
        epoch: Epoch(1),
        state_version: StateVersion(1),
        governance_policy: parent.governance_policy.clone(),
        mode_policy: parent.mode_policy,
        roster,
    })
    .expect("recipient TreeKEM state validates");
    state.last_commit_hash = commit_hash_value;
    state.roster_hash = roster_hash_value;
    state.tree_hash = tree_hash_value;
    state.membership = MembershipPrivateState::TreeKem {
        public_tree,
        private_path: PrivatePath::default(),
    };
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(*root_secret), &state.epoch_key_context())
            .expect("derive recipient TreeKEM epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("recipient sender chains install");
    state
}

fn generate_treekem_join_mode(
    root: &Path,
    vector_id: &str,
    mode: GroupMode,
    alice_role: GroupRole,
    bob_role: GroupRole,
    carol_role: GroupRole,
) {
    let (mut parent, alice, bob, _carol, _parent_tree_hash) =
        build_tree_parent_state(vector_id, mode, alice_role, carol_role);
    let parent_hash = state_commitment(&parent);
    let bob_entry = entry_for_identity(&bob, bob_role, 1, Epoch(1));
    let mut candidate_roster = parent.roster.clone();
    candidate_roster.push(bob_entry.clone());
    let canonical_roster =
        encode_roster(mode, &candidate_roster).expect("candidate roster encodes");
    let roster_hash_value = hydra_group::roster_hash(&canonical_roster).expect("roster hash");
    let mut candidate_tree = match &parent.membership {
        MembershipPrivateState::TreeKem { public_tree, .. } => public_tree.clone(),
        _ => panic!("TreeKEM parent expected"),
    };
    candidate_tree
        .occupy_leaf(
            1,
            tree_leaf(
                &bob,
                bob_role,
                node_key_from_seed(vector_id, "bob-leaf-key", 0),
            ),
        )
        .expect("occupy joined leaf");
    let before_update_hash = candidate_tree.tree_hash().expect("candidate tree hash");
    let mut candidate_private_path = PrivatePath::default();
    let leaf_secret = Secret32::new(draw32(vector_id, "join-leaf-secret", 0));
    let path_context = TreeKemPathContext {
        group_id: parent.group_id,
        mode,
        epoch: Epoch(1),
        state_version: StateVersion(1),
        leaf_slot: 0,
        commit_nonce: nonce(vector_id, 1),
        tree_hash: before_update_hash,
    };
    let path_update = derive_and_install_path(
        &mut candidate_tree,
        &mut candidate_private_path,
        path_context,
        &leaf_secret,
    )
    .expect("derive join update path");
    let root_secret = *path_update.root_secret.expose_for_backend();
    let wrap_context = TreeKemWrapContext {
        group_id: parent.group_id,
        mode,
        new_epoch: Epoch(1),
        new_state_version: StateVersion(1),
        commit_nonce: nonce(vector_id, 1),
        tree_hash: path_update.tree_hash_after,
    };
    let joined_leaf_node = candidate_tree
        .leaf_capacity
        .checked_add(1)
        .expect("joined leaf node index fits u32");
    let update_path = encrypt_path_updates(
        &candidate_tree,
        &candidate_private_path,
        wrap_context,
        &path_update,
        &[joined_leaf_node],
    )
    .expect("wrap update path");
    let update_path_bytes =
        hydra_group::encode_update_path(&update_path).expect("update path encodes");
    let change_payload = encode_change_payload(&ChangePayload::Join {
        new_entry: &bob_entry,
    })
    .expect("join payload encodes");
    let change_payload_hash_value = change_payload_hash(&change_payload).expect("change hash");
    let update_path_hash_value = update_path_hash(&update_path).expect("update path hash");
    let key_schedule_commitment = treekem_key_schedule_commitment(
        parent.group_id,
        mode,
        Epoch(1),
        path_update.tree_hash_after,
        update_path_hash_value,
    );
    let governance_bytes =
        encode_governance_policy(&parent.governance_policy).expect("governance encodes");
    let core = CommitCore {
        commit_kind: CommitKind::Join,
        group_id: parent.group_id,
        old_group_mode: Some(mode),
        new_group_mode: mode,
        new_membership_mechanism: MembershipMechanism::TreeKem,
        old_epoch: parent.epoch,
        new_epoch: Epoch(1),
        old_state_version: parent.state_version,
        new_state_version: StateVersion(1),
        parent_commit_hash: parent.last_commit_hash,
        old_roster_hash: parent.roster_hash,
        new_roster_hash: roster_hash_value,
        old_tree_hash: parent.tree_hash,
        new_tree_hash: path_update.tree_hash_after,
        commit_nonce: nonce(vector_id, 1),
        change_payload_hash: change_payload_hash_value,
        key_schedule_commitment,
        governance_policy_hash: hydra_group::governance_policy_hash(&governance_bytes)
            .expect("governance hash"),
        mode_policy_hash: hydra_group::mode_policy_hash(parent.mode_policy).expect("mode hash"),
    };
    let (encoded_core, signature_digest, commit_hash_value, _signatures, signature_set) =
        sign_tree_join_core(vector_id, &alice, core, 1);
    let welcome = encode_join_welcome(&JoinWelcomeEncoding {
        mode,
        mechanism: MembershipMechanism::TreeKem,
        recipient: bob.member_id,
        encoded_core: &encoded_core,
        change_payload: &change_payload,
        signature_set: &signature_set,
        commit_hash: &commit_hash_value,
        roster: &candidate_roster,
        governance_policy: &parent.governance_policy,
        mode_policy: parent.mode_policy,
        update_path: Some(&update_path),
        direct_epoch_secret: None,
        tree_root_secret: Some(&root_secret),
        public_tree_hash: &path_update.tree_hash_after,
    });
    let wrong_recipient = member_id(vector_id, 9);
    let wrong_welcome = encode_join_welcome(&JoinWelcomeEncoding {
        mode,
        mechanism: MembershipMechanism::TreeKem,
        recipient: wrong_recipient,
        encoded_core: &encoded_core,
        change_payload: &change_payload,
        signature_set: &signature_set,
        commit_hash: &commit_hash_value,
        roster: &candidate_roster,
        governance_policy: &parent.governance_policy,
        mode_policy: parent.mode_policy,
        update_path: Some(&update_path),
        direct_epoch_secret: None,
        tree_root_secret: Some(&root_secret),
        public_tree_hash: &path_update.tree_hash_after,
    });

    let wrong_before = state_commitment(&parent);
    assert!(verify_welcome_recipient(&wrong_welcome, bob.member_id).is_err());
    assert_eq!(wrong_before, state_commitment(&parent));

    let recipient_state = recipient_tree_state_from_welcome(
        &parent,
        candidate_roster.clone(),
        roster_hash_value,
        candidate_tree.clone(),
        &root_secret,
        commit_hash_value,
        path_update.tree_hash_after,
    );
    install_tree_join_state(
        &mut parent,
        TreeJoinInstallState {
            roster: candidate_roster.clone(),
            roster_hash_value,
            tree: candidate_tree,
            private_path: candidate_private_path,
            root_secret: &root_secret,
            commit_hash_value,
            tree_hash_value: path_update.tree_hash_after,
        },
    );
    assert_eq!(verify_welcome_recipient(&welcome, bob.member_id), Ok(()));
    assert_eq!(parent.epoch, Epoch(1));
    assert_eq!(recipient_state.epoch, Epoch(1));
    assert_eq!(parent.last_commit_hash, recipient_state.last_commit_hash);
    assert_eq!(parent.roster_hash, recipient_state.roster_hash);
    assert_eq!(parent.tree_hash, recipient_state.tree_hash);

    let artifacts = vec![
        ("group_id".to_owned(), parent.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        (
            "alice_verification_key".to_owned(),
            alice.verification_key.clone(),
        ),
        ("bob_member_id".to_owned(), bob.member_id.0.to_vec()),
        (
            "bob_verification_key".to_owned(),
            bob.verification_key.clone(),
        ),
        ("parent_state_hash".to_owned(), parent_hash),
        ("join_payload".to_owned(), change_payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        ("update_path".to_owned(), update_path_bytes),
        ("tree_root_secret".to_owned(), root_secret.to_vec()),
        ("welcome_object".to_owned(), welcome),
        (
            "recipient_installed_state_hash".to_owned(),
            state_commitment(&recipient_state),
        ),
        (
            "existing_member_installed_state_hash".to_owned(),
            state_commitment(&parent),
        ),
        ("wrong_recipient_welcome".to_owned(), wrong_welcome),
        (
            "wrong_recipient_state_before".to_owned(),
            wrong_before.clone(),
        ),
        ("wrong_recipient_state_after".to_owned(), wrong_before),
    ];
    let result = match mode {
        GroupMode::Interactive => {
            "Interactive TreeKEM join installs existing and recipient candidate states"
        }
        GroupMode::Broadcast => {
            "Broadcast TreeKEM join installs existing and recipient candidate states"
        }
        GroupMode::Lite => unreachable!("TreeKEM vector is not Lite"),
    };
    write_owned(
        root,
        "group",
        vector_id,
        &metadata(
            result,
            "existing member and joining recipient converge on commit, roster, tree, epoch, and state version; wrong recipient welcome preserves parent state",
            "tree root secret and leaf secret retained only as deterministic candidate vector artifacts",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("mldsa-xi", 1, 32, "bob_verification_key"),
                ("join-leaf-secret", 0, 32, "tree_root_secret"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 1, 32, "signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn prepare_lite_join_with_real_signature(
    vector_id: &str,
    state: &GroupState,
    alice: &IdentityMaterial,
    bob_entry: RosterEntry,
    direct_epoch_secret: [u8; 32],
) -> hydra_group::PreparedCommit {
    let bootstrap_signature = CommitSignature {
        signer: alice.member_id,
        signature: [0; ML_DSA_65_SIG_SIZE],
    };
    let build_plan = |signature: CommitSignature| CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(vector_id, 2),
        change: CommitChange::Join {
            new_entry: bob_entry.clone(),
        },
        signatures: vec![signature],
        update_path: None,
        direct_epoch_secret: Some(direct_epoch_secret),
    };
    let draft = prepare_commit(state, build_plan(bootstrap_signature)).expect("draft Lite join");
    let real = real_commit_signature(vector_id, alice, &draft.signature_digest, 2);
    prepare_commit(state, build_plan(real)).expect("real Lite join")
}

fn recipient_lite_state_from_welcome(
    parent: &GroupState,
    roster: Vec<RosterEntry>,
    direct_epoch_secret: [u8; 32],
    commit_hash_value: [u8; 64],
    roster_hash_value: [u8; 64],
) -> GroupState {
    let mut state = GroupState::new_validated(GroupStateConfig {
        group_id: parent.group_id,
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        epoch: Epoch(1),
        state_version: StateVersion(1),
        governance_policy: parent.governance_policy.clone(),
        mode_policy: parent.mode_policy,
        roster,
    })
    .expect("Lite recipient state validates");
    state.last_commit_hash = commit_hash_value;
    state.roster_hash = roster_hash_value;
    state.membership = MembershipPrivateState::DirectWrap {
        epoch_secret: Secret32::new(direct_epoch_secret),
    };
    let epoch_key = derive_epoch_key_for_context(
        &Secret32::new(direct_epoch_secret),
        &state.epoch_key_context(),
    )
    .expect("derive Lite epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("Lite recipient sender chains install");
    state
}

fn generate_lite_join_vector(root: &Path) {
    const ID: &str = "TV-GROUP-JOIN-LITE-000";
    let alice = identity_material(ID, 0);
    let bob = identity_material(ID, 1);
    let alice_entry = entry_for_identity(&alice, GroupRole::Member, 0, Epoch(0));
    let mut state = empty_lite_state(ID, alice.member_id);
    let create_plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(ID, 0),
        change: CommitChange::Create {
            new_roster: vec![alice_entry],
            new_governance_policy: GovernancePolicy::single_signer(alice.member_id),
            new_mode_policy: ModePolicy::default(),
            new_tree_hash: [0; 64],
        },
        signatures: vec![signature(ID, alice.member_id, 0)],
        update_path: None,
        direct_epoch_secret: Some(direct_secret(ID, 0)),
    };
    let create = prepare_commit(&state, create_plan).expect("prepare Lite create");
    apply_prepared_commit(&mut state, create).expect("apply Lite create");
    let parent_hash = state_commitment(&state);
    let bob_entry = entry_for_identity(&bob, GroupRole::Member, 1, Epoch(1));
    let direct_epoch_secret = direct_secret(ID, 1);
    let prepared = prepare_lite_join_with_real_signature(
        ID,
        &state,
        &alice,
        bob_entry.clone(),
        direct_epoch_secret,
    );
    let join_payload = encode_change_payload(&ChangePayload::Join {
        new_entry: &bob_entry,
    })
    .expect("Lite join payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let commit_hash_value = prepared.commit_hash;
    let signature_set = encode_signature_set(&prepared.signatures).expect("signature set");
    let mut candidate_roster = state.roster.clone();
    candidate_roster.push(bob_entry);
    let roster_hash_value = prepared.core.new_roster_hash;
    let welcome = encode_join_welcome(&JoinWelcomeEncoding {
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        recipient: bob.member_id,
        encoded_core: &prepared.encoded_core,
        change_payload: &join_payload,
        signature_set: &signature_set,
        commit_hash: &prepared.commit_hash,
        roster: &candidate_roster,
        governance_policy: &state.governance_policy,
        mode_policy: state.mode_policy,
        update_path: None,
        direct_epoch_secret: Some(&direct_epoch_secret),
        tree_root_secret: None,
        public_tree_hash: &[0; 64],
    });
    let wrong_welcome = encode_join_welcome(&JoinWelcomeEncoding {
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        recipient: member_id(ID, 9),
        encoded_core: &prepared.encoded_core,
        change_payload: &join_payload,
        signature_set: &signature_set,
        commit_hash: &prepared.commit_hash,
        roster: &candidate_roster,
        governance_policy: &state.governance_policy,
        mode_policy: state.mode_policy,
        update_path: None,
        direct_epoch_secret: Some(&direct_epoch_secret),
        tree_root_secret: None,
        public_tree_hash: &[0; 64],
    });
    let wrong_before = state_commitment(&state);
    assert!(verify_welcome_recipient(&wrong_welcome, bob.member_id).is_err());
    assert_eq!(wrong_before, state_commitment(&state));
    let recipient_state = recipient_lite_state_from_welcome(
        &state,
        candidate_roster.clone(),
        direct_epoch_secret,
        prepared.commit_hash,
        roster_hash_value,
    );
    apply_prepared_commit(&mut state, prepared).expect("existing Lite member applies join");
    assert_eq!(verify_welcome_recipient(&welcome, bob.member_id), Ok(()));
    assert_eq!(state.last_commit_hash, recipient_state.last_commit_hash);
    assert_eq!(state.roster_hash, recipient_state.roster_hash);
    assert_eq!(state.epoch, recipient_state.epoch);
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        ("bob_member_id".to_owned(), bob.member_id.0.to_vec()),
        ("bob_verification_key".to_owned(), bob.verification_key),
        ("parent_state_hash".to_owned(), parent_hash),
        ("join_payload".to_owned(), join_payload),
        ("commit_core".to_owned(), encoded_core),
    ];
    let mut artifacts = artifacts;
    artifacts.extend([
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        (
            "direct_wrap_material".to_owned(),
            direct_epoch_secret.to_vec(),
        ),
        ("welcome_object".to_owned(), welcome),
        (
            "recipient_installed_state_hash".to_owned(),
            state_commitment(&recipient_state),
        ),
        (
            "existing_member_installed_state_hash".to_owned(),
            state_commitment(&state),
        ),
        ("wrong_recipient_welcome".to_owned(), wrong_welcome),
        (
            "wrong_recipient_state_before".to_owned(),
            wrong_before.clone(),
        ),
        ("wrong_recipient_state_after".to_owned(), wrong_before),
    ]);
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Lite direct-wrap join installs existing and recipient candidate states",
            "existing member and joining recipient converge on commit, roster, epoch, and state version; wrong recipient welcome preserves parent state",
            "direct epoch secret retained only as deterministic candidate vector artifact",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("mldsa-xi", 1, 32, "bob_verification_key"),
                ("direct-epoch-secret", 1, 32, "direct_wrap_material"),
                ("commit-nonce", 2, 32, "commit_core"),
                ("mldsa-rnd", 2, 32, "signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn generate_join_vectors_m8_2(root: &Path) {
    generate_treekem_join_mode(
        root,
        "TV-GROUP-JOIN-INTERACTIVE-000",
        GroupMode::Interactive,
        GroupRole::Moderator,
        GroupRole::Member,
        GroupRole::Member,
    );
    generate_treekem_join_mode(
        root,
        "TV-GROUP-JOIN-BROADCAST-000",
        GroupMode::Broadcast,
        GroupRole::Moderator,
        GroupRole::Audience,
        GroupRole::Presenter,
    );
    generate_lite_join_vector(root);
}

fn sorted_governance_policy(mut signers: Vec<MemberId>, threshold: u8) -> GovernancePolicy {
    signers.sort_by_key(|member| member.0);
    GovernancePolicy {
        policy_version: 1,
        threshold,
        authorized_signers: signers,
    }
}

fn error_artifact(error: impl core::fmt::Debug) -> Vec<u8> {
    format!("{error:?}").into_bytes()
}

fn build_lite_parent_state(
    vector_id: &str,
    governance_policy: GovernancePolicy,
) -> (GroupState, IdentityMaterial, IdentityMaterial, [u8; 32]) {
    let alice = identity_material(vector_id, 0);
    let bob = identity_material(vector_id, 1);
    let alice_entry = entry_for_identity(&alice, GroupRole::Member, 0, Epoch(1));
    let bob_entry = entry_for_identity(&bob, GroupRole::Member, 1, Epoch(1));
    let parent_secret = direct_secret(vector_id, 0);
    let mut state = GroupState::new_validated(GroupStateConfig {
        group_id: group_id(vector_id),
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        epoch: Epoch(1),
        state_version: StateVersion(1),
        governance_policy,
        mode_policy: ModePolicy::default(),
        roster: vec![alice_entry, bob_entry],
    })
    .expect("Lite parent validates");
    state.last_commit_hash = draw64(vector_id, "parent-commit-hash", 0);
    state.membership = MembershipPrivateState::DirectWrap {
        epoch_secret: Secret32::new(parent_secret),
    };
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(parent_secret), &state.epoch_key_context())
            .expect("Lite parent epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("Lite parent sender chains");
    (state, alice, bob, parent_secret)
}

fn sign_direct_plan(
    vector_id: &str,
    state: &GroupState,
    mut plan: CommitPlan,
    signer: &IdentityMaterial,
    occurrence: u32,
) -> hydra_group::PreparedCommit {
    plan.signatures = vec![signature(vector_id, signer.member_id, occurrence)];
    let draft = prepare_commit(
        state,
        CommitPlan {
            committer: plan.committer,
            commit_nonce: plan.commit_nonce,
            change: plan.change.clone(),
            signatures: plan.signatures.clone(),
            update_path: plan.update_path.clone(),
            direct_epoch_secret: plan.direct_epoch_secret,
        },
    )
    .expect("draft direct commit");
    plan.signatures = vec![real_commit_signature(
        vector_id,
        signer,
        &draft.signature_digest,
        occurrence,
    )];
    prepare_commit(state, plan).expect("signed direct commit")
}

fn encode_removed_entry(state: &GroupState, member: MemberId) -> Vec<u8> {
    let removed = state
        .roster
        .iter()
        .find(|entry| entry.member_id == member)
        .expect("removed entry exists");
    assert_eq!(removed.status, MemberStatus::Removed);
    encode_roster_entry(removed).to_vec()
}

fn generate_lite_leave_vector(root: &Path) {
    const ID: &str = "TV-GROUP-LEAVE-LITE-000";
    let alice0 = identity_material(ID, 0);
    let bob0 = identity_material(ID, 1);
    let governance = sorted_governance_policy(vec![alice0.member_id, bob0.member_id], 1);
    let (mut state, alice, bob, _parent_secret) = build_lite_parent_state(ID, governance.clone());
    let (mut removed_view, _, _, _) = build_lite_parent_state(ID, governance);
    let parent_state_hash = state_commitment(&state);
    let new_secret = direct_secret(ID, 1);
    let change = CommitChange::Leave {
        member_id: bob.member_id,
    };
    let missing_actor_plan = CommitPlan {
        committer: bob.member_id,
        commit_nonce: nonce(ID, 1),
        change: change.clone(),
        signatures: vec![real_commit_signature(ID, &alice, &[0x33; 64], 1)],
        update_path: None,
        direct_epoch_secret: Some(new_secret),
    };
    let missing_actor_error = match prepare_commit(&state, missing_actor_plan) {
        Ok(_) => panic!("leave without actor signature unexpectedly prepared"),
        Err(error) => error,
    };
    let plan = CommitPlan {
        committer: bob.member_id,
        commit_nonce: nonce(ID, 1),
        change,
        signatures: Vec::new(),
        update_path: None,
        direct_epoch_secret: Some(new_secret),
    };
    let prepared = sign_direct_plan(ID, &state, plan, &bob, 2);
    let leave_payload = encode_change_payload(&ChangePayload::Leave {
        member_id: bob.member_id,
    })
    .expect("leave payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set = encode_signature_set(&prepared.signatures).expect("leave signature set");
    let commit_hash_value = prepared.commit_hash;
    apply_prepared_commit(&mut state, prepared).expect("apply leave");
    let send_error = state
        .seal_group_data(bob.member_id, b"removed sender")
        .expect_err("removed member cannot send");
    let alice_message = state
        .seal_group_data(alice.member_id, b"post-leave secret")
        .expect("active member sends after leave");
    let decrypt_error = removed_view
        .open_group_data(&alice_message.envelope)
        .expect_err("removed view cannot decrypt new epoch");
    let removed_entry = state
        .roster
        .iter()
        .find(|entry| entry.member_id == bob.member_id)
        .expect("removed Bob retained");
    assert_eq!(removed_entry.role, GroupRole::Member);
    assert_eq!(removed_entry.device_identity_fingerprint, bob.fingerprint);
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("bob_member_id".to_owned(), bob.member_id.0.to_vec()),
        ("bob_verification_key".to_owned(), bob.verification_key),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("leave_payload".to_owned(), leave_payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("actor_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        ("direct_wrap_material".to_owned(), new_secret.to_vec()),
        (
            "removed_member_new_message".to_owned(),
            alice_message.envelope,
        ),
        (
            "removed_member_decrypt_error".to_owned(),
            error_artifact(decrypt_error),
        ),
        (
            "removed_member_send_error".to_owned(),
            error_artifact(send_error),
        ),
        (
            "missing_actor_signature_error".to_owned(),
            error_artifact(missing_actor_error),
        ),
        (
            "removed_entry_archival_encoding".to_owned(),
            encode_removed_entry(&state, bob.member_id),
        ),
        (
            "existing_member_installed_state_hash".to_owned(),
            state_commitment(&state),
        ),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Lite voluntary leave with actor signature applies and archives the removed entry",
            "removed member cannot decrypt new epoch material or send new group data; missing actor signature rejects before mutation",
            "direct-wrap parent and replacement epoch secrets retained only as deterministic candidate vector artifacts",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 1, 32, "bob_verification_key"),
                ("direct-epoch-secret", 1, 32, "direct_wrap_material"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 2, 32, "actor_signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn generate_lite_remove_vector(root: &Path) {
    const ID: &str = "TV-GROUP-REMOVE-LITE-000";
    let alice0 = identity_material(ID, 0);
    let governance = GovernancePolicy::single_signer(alice0.member_id);
    let (mut state, alice, bob, _parent_secret) = build_lite_parent_state(ID, governance.clone());
    let (mut removed_view, _, _, _) = build_lite_parent_state(ID, governance);
    let parent_state_hash = state_commitment(&state);
    let new_secret = direct_secret(ID, 1);
    let change = CommitChange::RemoveOrRevoke {
        member_id: bob.member_id,
        reason_code: 7,
    };
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(ID, 1),
        change,
        signatures: Vec::new(),
        update_path: None,
        direct_epoch_secret: Some(new_secret),
    };
    let prepared = sign_direct_plan(ID, &state, plan, &alice, 1);
    let remove_payload = encode_change_payload(&ChangePayload::RemoveOrRevoke {
        member_id: bob.member_id,
        reason_code: 7,
    })
    .expect("remove payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set = encode_signature_set(&prepared.signatures).expect("remove signature set");
    let commit_hash_value = prepared.commit_hash;
    apply_prepared_commit(&mut state, prepared).expect("apply Lite remove");
    let send_error = state
        .seal_group_data(bob.member_id, b"removed sender")
        .expect_err("removed member cannot send");
    let alice_message = state
        .seal_group_data(alice.member_id, b"post-remove secret")
        .expect("active member sends after remove");
    let decrypt_error = removed_view
        .open_group_data(&alice_message.envelope)
        .expect_err("removed view cannot decrypt new epoch");
    let removed_entry = state
        .roster
        .iter()
        .find(|entry| entry.member_id == bob.member_id)
        .expect("removed Bob retained");
    assert_eq!(removed_entry.role, GroupRole::Member);
    assert_eq!(removed_entry.device_identity_fingerprint, bob.fingerprint);
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        ("bob_member_id".to_owned(), bob.member_id.0.to_vec()),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("remove_payload".to_owned(), remove_payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("governance_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        ("direct_wrap_material".to_owned(), new_secret.to_vec()),
        (
            "removed_member_new_message".to_owned(),
            alice_message.envelope,
        ),
        (
            "removed_member_decrypt_error".to_owned(),
            error_artifact(decrypt_error),
        ),
        (
            "removed_member_send_error".to_owned(),
            error_artifact(send_error),
        ),
        (
            "removed_entry_archival_encoding".to_owned(),
            encode_removed_entry(&state, bob.member_id),
        ),
        (
            "existing_member_installed_state_hash".to_owned(),
            state_commitment(&state),
        ),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Lite governance remove/revoke applies with direct-wrap replacement material",
            "removed member cannot decrypt new epoch material or send new group data; removed roster entry remains archived",
            "direct-wrap parent and replacement epoch secrets retained only as deterministic candidate vector artifacts",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("direct-epoch-secret", 1, 32, "direct_wrap_material"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 1, 32, "governance_signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn build_tree_three_member_state(
    vector_id: &str,
    mode: GroupMode,
    alice_role: GroupRole,
    bob_role: GroupRole,
    carol_role: GroupRole,
) -> (
    GroupState,
    IdentityMaterial,
    IdentityMaterial,
    IdentityMaterial,
    [u8; 32],
) {
    let alice = identity_material(vector_id, 0);
    let bob = identity_material(vector_id, 1);
    let carol = identity_material(vector_id, 2);
    let alice_entry = entry_for_identity(&alice, alice_role, 0, Epoch(1));
    let bob_entry = entry_for_identity(&bob, bob_role, 1, Epoch(1));
    let carol_entry = entry_for_identity(&carol, carol_role, 2, Epoch(1));
    let mut tree = PublicTree::new(mode, Some(Epoch(1))).expect("TreeKEM tree");
    tree.occupy_leaf(
        0,
        tree_leaf(
            &alice,
            alice_role,
            node_key_from_seed(vector_id, "alice-leaf-key", 0),
        ),
    )
    .expect("occupy Alice");
    tree.occupy_leaf(
        1,
        tree_leaf(
            &bob,
            bob_role,
            node_key_from_seed(vector_id, "bob-leaf-key", 0),
        ),
    )
    .expect("occupy Bob");
    tree.occupy_leaf(
        2,
        tree_leaf(
            &carol,
            carol_role,
            node_key_from_seed(vector_id, "carol-leaf-key", 0),
        ),
    )
    .expect("occupy Carol");
    let before_hash = tree.tree_hash().expect("initial tree hash");
    let mut private_path = PrivatePath::default();
    let parent_leaf_secret = Secret32::new(draw32(vector_id, "parent-leaf-secret", 0));
    let parent_update = derive_and_install_path(
        &mut tree,
        &mut private_path,
        TreeKemPathContext {
            group_id: group_id(vector_id),
            mode,
            epoch: Epoch(1),
            state_version: StateVersion(1),
            leaf_slot: 0,
            commit_nonce: nonce(vector_id, 0),
            tree_hash: before_hash,
        },
        &parent_leaf_secret,
    )
    .expect("derive parent TreeKEM path");
    let parent_root = *parent_update.root_secret.expose_for_backend();
    let mut state = GroupState::new_validated(GroupStateConfig {
        group_id: group_id(vector_id),
        mode,
        mechanism: MembershipMechanism::TreeKem,
        epoch: Epoch(1),
        state_version: StateVersion(1),
        governance_policy: GovernancePolicy::single_signer(alice.member_id),
        mode_policy: ModePolicy::default(),
        roster: vec![alice_entry, bob_entry, carol_entry],
    })
    .expect("TreeKEM parent validates");
    state.last_commit_hash = draw64(vector_id, "parent-commit-hash", 0);
    state.tree_hash = parent_update.tree_hash_after;
    state.membership = MembershipPrivateState::TreeKem {
        public_tree: tree,
        private_path,
    };
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(parent_root), &state.epoch_key_context())
            .expect("TreeKEM parent epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("TreeKEM parent sender chains");
    (state, alice, bob, carol, parent_root)
}

fn sign_tree_plan(
    vector_id: &str,
    state: &GroupState,
    mut plan: CommitPlan,
    signer: &IdentityMaterial,
    occurrence: u32,
) -> hydra_group::PreparedCommit {
    plan.signatures = vec![signature(vector_id, signer.member_id, occurrence)];
    let draft = prepare_commit(
        state,
        CommitPlan {
            committer: plan.committer,
            commit_nonce: plan.commit_nonce,
            change: plan.change.clone(),
            signatures: plan.signatures.clone(),
            update_path: plan.update_path.clone(),
            direct_epoch_secret: plan.direct_epoch_secret,
        },
    )
    .expect("draft TreeKEM commit");
    plan.signatures = vec![real_commit_signature(
        vector_id,
        signer,
        &draft.signature_digest,
        occurrence,
    )];
    prepare_commit(state, plan).expect("signed TreeKEM commit")
}

fn generate_treekem_remove_vector(
    root: &Path,
    vector_id: &str,
    mode: GroupMode,
    alice_role: GroupRole,
    bob_role: GroupRole,
    carol_role: GroupRole,
) {
    let (mut state, alice, bob, _carol, _parent_root) =
        build_tree_three_member_state(vector_id, mode, alice_role, bob_role, carol_role);
    let (mut removed_view, _, _, _, _) =
        build_tree_three_member_state(vector_id, mode, alice_role, bob_role, carol_role);
    let parent_state_hash = state_commitment(&state);
    let mut candidate_tree = match &state.membership {
        MembershipPrivateState::TreeKem { public_tree, .. } => public_tree.clone(),
        _ => panic!("TreeKEM parent expected"),
    };
    candidate_tree
        .vacate_leaf(1)
        .expect("vacate removed member leaf");
    let removal_base_hash = candidate_tree.tree_hash().expect("removal base tree hash");
    let mut candidate_private_path = PrivatePath::default();
    let leaf_secret = Secret32::new(draw32(vector_id, "remove-leaf-secret", 0));
    let path_update = derive_and_install_path(
        &mut candidate_tree,
        &mut candidate_private_path,
        TreeKemPathContext {
            group_id: state.group_id,
            mode,
            epoch: Epoch(2),
            state_version: StateVersion(2),
            leaf_slot: 0,
            commit_nonce: nonce(vector_id, 1),
            tree_hash: removal_base_hash,
        },
        &leaf_secret,
    )
    .expect("derive removal path");
    let root_secret = *path_update.root_secret.expose_for_backend();
    let removed_leaf_node = leaf_node_index(mode, 1).expect("removed leaf node");
    let wrap_context = TreeKemWrapContext {
        group_id: state.group_id,
        mode,
        new_epoch: Epoch(2),
        new_state_version: StateVersion(2),
        commit_nonce: nonce(vector_id, 1),
        tree_hash: path_update.tree_hash_after,
    };
    let update_path = encrypt_path_updates(
        &candidate_tree,
        &candidate_private_path,
        wrap_context,
        &path_update,
        &[removed_leaf_node],
    )
    .expect("wrap removal path with exclusion");
    assert!(
        update_path
            .path_ciphertexts
            .iter()
            .all(|ciphertext| ciphertext.target_node_index != removed_leaf_node)
    );
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(vector_id, 1),
        change: CommitChange::RemoveOrRevoke {
            member_id: bob.member_id,
            reason_code: 9,
        },
        signatures: Vec::new(),
        update_path: Some(update_path.clone()),
        direct_epoch_secret: None,
    };
    let prepared = sign_tree_plan(vector_id, &state, plan, &alice, 1);
    let remove_payload = encode_change_payload(&ChangePayload::RemoveOrRevoke {
        member_id: bob.member_id,
        reason_code: 9,
    })
    .expect("TreeKEM remove payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set =
        encode_signature_set(&prepared.signatures).expect("TreeKEM remove signature set");
    let commit_hash_value = prepared.commit_hash;
    apply_prepared_commit(&mut state, prepared).expect("apply TreeKEM remove");
    if let MembershipPrivateState::TreeKem { private_path, .. } = &mut state.membership {
        *private_path = candidate_private_path;
    } else {
        panic!("TreeKEM membership expected after removal commit");
    }
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(root_secret), &state.epoch_key_context())
            .expect("derive TreeKEM removal epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("install TreeKEM removal sender chains");
    let send_error = state
        .seal_group_data(bob.member_id, b"removed sender")
        .expect_err("removed TreeKEM member cannot send");
    let alice_message = state
        .seal_group_data(alice.member_id, b"post-remove treekem secret")
        .expect("active TreeKEM member sends after remove");
    let decrypt_error = removed_view
        .open_group_data(&alice_message.envelope)
        .expect_err("removed TreeKEM view cannot decrypt new epoch");
    let removed_entry = state
        .roster
        .iter()
        .find(|entry| entry.member_id == bob.member_id)
        .expect("removed Bob retained");
    assert_eq!(removed_entry.role, bob_role);
    assert_eq!(removed_entry.device_identity_fingerprint, bob.fingerprint);
    let mut target_nodes = Vec::new();
    for ciphertext in &update_path.path_ciphertexts {
        target_nodes.extend_from_slice(&ciphertext.parent_node_index.to_be_bytes());
        target_nodes.extend_from_slice(&ciphertext.target_node_index.to_be_bytes());
    }
    let result = match mode {
        GroupMode::Interactive => {
            "Interactive TreeKEM governance remove/revoke uses exclusion-filtered resolution"
        }
        GroupMode::Broadcast => {
            "Broadcast TreeKEM governance remove/revoke uses exclusion-filtered resolution"
        }
        GroupMode::Lite => unreachable!("Lite is direct-wrap"),
    };
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        ("bob_member_id".to_owned(), bob.member_id.0.to_vec()),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("remove_payload".to_owned(), remove_payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("governance_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        (
            "update_path".to_owned(),
            hydra_group::encode_update_path(&update_path).expect("update path encodes"),
        ),
        ("exclusion_filtered_targets".to_owned(), target_nodes),
        (
            "removed_leaf_node".to_owned(),
            removed_leaf_node.to_be_bytes().to_vec(),
        ),
        ("tree_root_secret".to_owned(), root_secret.to_vec()),
        (
            "removed_member_new_message".to_owned(),
            alice_message.envelope,
        ),
        (
            "removed_member_decrypt_error".to_owned(),
            error_artifact(decrypt_error),
        ),
        (
            "removed_member_send_error".to_owned(),
            error_artifact(send_error),
        ),
        (
            "removed_entry_archival_encoding".to_owned(),
            encode_removed_entry(&state, bob.member_id),
        ),
        (
            "existing_member_installed_state_hash".to_owned(),
            state_commitment(&state),
        ),
    ];
    write_owned(
        root,
        "group",
        vector_id,
        &metadata(
            result,
            "removed member is archived, receives no decryptable new path secret, and cannot send new group data",
            "TreeKEM root and leaf secrets retained only as deterministic candidate vector artifacts",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("remove-leaf-secret", 0, 32, "tree_root_secret"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 1, 32, "governance_signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn generate_remove_vectors_m8_3(root: &Path) {
    generate_lite_leave_vector(root);
    generate_lite_remove_vector(root);
    generate_treekem_remove_vector(
        root,
        "TV-GROUP-REMOVE-INTERACTIVE-000",
        GroupMode::Interactive,
        GroupRole::Moderator,
        GroupRole::Member,
        GroupRole::Member,
    );
    generate_treekem_remove_vector(
        root,
        "TV-GROUP-REMOVE-BROADCAST-000",
        GroupMode::Broadcast,
        GroupRole::Moderator,
        GroupRole::Audience,
        GroupRole::Presenter,
    );
}

fn generate_lite_role_change_vector(root: &Path) {
    const ID: &str = "TV-GROUP-ROLE-LITE-000";
    let alice0 = identity_material(ID, 0);
    let governance = GovernancePolicy::single_signer(alice0.member_id);
    let (mut state, alice, bob, _parent_secret) = build_lite_parent_state(ID, governance);
    let parent_state_hash = state_commitment(&state);

    let invalid_before = state_commitment(&state);
    let invalid_plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(ID, 2),
        change: CommitChange::RoleChange {
            member_id: bob.member_id,
            new_role: GroupRole::Audience,
        },
        signatures: vec![signature(ID, alice.member_id, 2)],
        update_path: None,
        direct_epoch_secret: Some(direct_secret(ID, 2)),
    };
    let invalid_role_error = match prepare_commit(&state, invalid_plan) {
        Ok(_) => panic!("Lite role change to Audience unexpectedly prepared"),
        Err(error) => error,
    };
    assert_eq!(invalid_before, state_commitment(&state));

    let new_secret = direct_secret(ID, 1);
    let change = CommitChange::RoleChange {
        member_id: bob.member_id,
        new_role: GroupRole::Moderator,
    };
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(ID, 1),
        change,
        signatures: Vec::new(),
        update_path: None,
        direct_epoch_secret: Some(new_secret),
    };
    let prepared = sign_direct_plan(ID, &state, plan, &alice, 1);
    let role_payload = encode_change_payload(&ChangePayload::RoleChange {
        member_id: bob.member_id,
        old_role: GroupRole::Member,
        new_role: GroupRole::Moderator,
    })
    .expect("Lite role-change payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set = encode_signature_set(&prepared.signatures).expect("role signature set");
    let commit_hash_value = prepared.commit_hash;
    apply_prepared_commit(&mut state, prepared).expect("apply Lite role change");
    let changed_entry = state
        .roster
        .iter()
        .find(|entry| entry.member_id == bob.member_id)
        .expect("changed Bob entry exists");
    assert_eq!(changed_entry.role, GroupRole::Moderator);
    assert_eq!(changed_entry.device_identity_fingerprint, bob.fingerprint);
    let changed_entry_encoding = encode_roster_entry(changed_entry).to_vec();
    let promoted_message = state
        .seal_group_data(bob.member_id, b"promoted moderator sends")
        .expect("promoted Lite moderator can send");

    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        ("bob_member_id".to_owned(), bob.member_id.0.to_vec()),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("role_change_payload".to_owned(), role_payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("governance_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        ("direct_wrap_material".to_owned(), new_secret.to_vec()),
        ("changed_entry_encoding".to_owned(), changed_entry_encoding),
        (
            "post_role_change_message".to_owned(),
            promoted_message.envelope,
        ),
        (
            "invalid_role_error".to_owned(),
            error_artifact(invalid_role_error),
        ),
        (
            "invalid_role_state_before".to_owned(),
            invalid_before.clone(),
        ),
        ("invalid_role_state_after".to_owned(), invalid_before),
        (
            "existing_member_installed_state_hash".to_owned(),
            state_commitment(&state),
        ),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Lite direct-wrap role change promotes an active member and rejects an invalid Audience role",
            "role change advances epoch/state version, installs a fresh direct-wrap epoch, and invalid role rejection preserves parent state",
            "direct-wrap replacement epoch secret retained only as deterministic candidate vector artifact",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("direct-epoch-secret", 1, 32, "direct_wrap_material"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 1, 32, "governance_signature_set"),
            ],
        ),
        &artifacts,
    );
}

struct TreeKemRoleChangeVector<'a> {
    vector_id: &'a str,
    mode: GroupMode,
    alice_role: GroupRole,
    bob_old_role: GroupRole,
    bob_new_role: GroupRole,
    invalid_role: GroupRole,
    carol_role: GroupRole,
}

fn generate_treekem_role_change_vector(root: &Path, spec: TreeKemRoleChangeVector<'_>) {
    let vector_id = spec.vector_id;
    let mode = spec.mode;
    let (mut state, alice, bob, carol, _parent_root) = build_tree_three_member_state(
        vector_id,
        mode,
        spec.alice_role,
        spec.bob_old_role,
        spec.carol_role,
    );
    let parent_state_hash = state_commitment(&state);

    let invalid_before = state_commitment(&state);
    let invalid_plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(vector_id, 2),
        change: CommitChange::RoleChange {
            member_id: bob.member_id,
            new_role: spec.invalid_role,
        },
        signatures: vec![signature(vector_id, alice.member_id, 2)],
        update_path: None,
        direct_epoch_secret: None,
    };
    let invalid_role_error = match prepare_commit(&state, invalid_plan) {
        Ok(_) => panic!("invalid TreeKEM role change unexpectedly prepared"),
        Err(error) => error,
    };
    assert_eq!(invalid_before, state_commitment(&state));

    let mut candidate_tree = match &state.membership {
        MembershipPrivateState::TreeKem { public_tree, .. } => public_tree.clone(),
        _ => panic!("TreeKEM parent expected"),
    };
    let bob_slot = state
        .roster
        .iter()
        .find(|entry| entry.member_id == bob.member_id)
        .expect("Bob roster entry exists")
        .tree_leaf_slot;
    candidate_tree
        .update_leaf_role(bob_slot, spec.bob_new_role)
        .expect("update public-tree leaf role");
    let role_base_tree_hash = candidate_tree.tree_hash().expect("role base tree hash");
    let mut candidate_private_path = PrivatePath::default();
    let leaf_secret = Secret32::new(draw32(vector_id, "role-change-leaf-secret", 0));
    let path_update = derive_and_install_path(
        &mut candidate_tree,
        &mut candidate_private_path,
        TreeKemPathContext {
            group_id: state.group_id,
            mode,
            epoch: Epoch(2),
            state_version: StateVersion(2),
            leaf_slot: 0,
            commit_nonce: nonce(vector_id, 1),
            tree_hash: role_base_tree_hash,
        },
        &leaf_secret,
    )
    .expect("derive role-change path");
    let root_secret = *path_update.root_secret.expose_for_backend();
    let wrap_context = TreeKemWrapContext {
        group_id: state.group_id,
        mode,
        new_epoch: Epoch(2),
        new_state_version: StateVersion(2),
        commit_nonce: nonce(vector_id, 1),
        tree_hash: path_update.tree_hash_after,
    };
    let update_path = encrypt_path_updates(
        &candidate_tree,
        &candidate_private_path,
        wrap_context,
        &path_update,
        &[],
    )
    .expect("wrap role-change path");
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(vector_id, 1),
        change: CommitChange::RoleChange {
            member_id: bob.member_id,
            new_role: spec.bob_new_role,
        },
        signatures: Vec::new(),
        update_path: Some(update_path.clone()),
        direct_epoch_secret: None,
    };
    let prepared = sign_tree_plan(vector_id, &state, plan, &alice, 1);
    let role_payload = encode_change_payload(&ChangePayload::RoleChange {
        member_id: bob.member_id,
        old_role: spec.bob_old_role,
        new_role: spec.bob_new_role,
    })
    .expect("TreeKEM role-change payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set =
        encode_signature_set(&prepared.signatures).expect("TreeKEM role signature set");
    let commit_hash_value = prepared.commit_hash;
    apply_prepared_commit(&mut state, prepared).expect("apply TreeKEM role change");
    if let MembershipPrivateState::TreeKem { private_path, .. } = &mut state.membership {
        *private_path = candidate_private_path;
    } else {
        panic!("TreeKEM membership expected after role change");
    }
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(root_secret), &state.epoch_key_context())
            .expect("derive TreeKEM role-change epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("install TreeKEM role-change sender chains");
    let changed_entry = state
        .roster
        .iter()
        .find(|entry| entry.member_id == bob.member_id)
        .expect("changed Bob entry exists");
    assert_eq!(changed_entry.role, spec.bob_new_role);
    assert_eq!(changed_entry.device_identity_fingerprint, bob.fingerprint);
    let changed_entry_encoding = encode_roster_entry(changed_entry).to_vec();

    let mut post_role_artifacts = Vec::new();
    match (mode, spec.bob_new_role.can_send_in_mode(mode)) {
        (GroupMode::Broadcast, false) => {
            let send_error = state
                .seal_group_data(bob.member_id, b"demoted audience cannot send")
                .expect_err("Broadcast audience cannot send");
            let presenter_message = state
                .seal_group_data(carol.member_id, b"presenter still sends")
                .expect("remaining presenter sends");
            post_role_artifacts.push((
                "post_role_sender_error".to_owned(),
                error_artifact(send_error),
            ));
            post_role_artifacts.push((
                "post_role_active_sender_message".to_owned(),
                presenter_message.envelope,
            ));
        }
        _ => {
            let message = state
                .seal_group_data(bob.member_id, b"role-changed member sends")
                .expect("role-changed member can send");
            post_role_artifacts.push((
                "post_role_active_sender_message".to_owned(),
                message.envelope,
            ));
        }
    }

    let mut artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        ("bob_member_id".to_owned(), bob.member_id.0.to_vec()),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("role_change_payload".to_owned(), role_payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("governance_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        (
            "update_path".to_owned(),
            hydra_group::encode_update_path(&update_path).expect("update path encodes"),
        ),
        ("tree_root_secret".to_owned(), root_secret.to_vec()),
        ("changed_entry_encoding".to_owned(), changed_entry_encoding),
        (
            "invalid_role_error".to_owned(),
            error_artifact(invalid_role_error),
        ),
        (
            "invalid_role_state_before".to_owned(),
            invalid_before.clone(),
        ),
        ("invalid_role_state_after".to_owned(), invalid_before),
        (
            "existing_member_installed_state_hash".to_owned(),
            state_commitment(&state),
        ),
    ];
    artifacts.extend(post_role_artifacts);
    let result = match mode {
        GroupMode::Interactive => {
            "Interactive TreeKEM role change updates roster, public-tree leaf role, and update path"
        }
        GroupMode::Broadcast => {
            "Broadcast TreeKEM role change demotes a presenter to audience and refreshes path secrets"
        }
        GroupMode::Lite => unreachable!("Lite role change is direct-wrap"),
    };
    write_owned(
        root,
        "group",
        vector_id,
        &metadata(
            result,
            "role change advances epoch/state version, changes canonical roster entry, refreshes membership material, and invalid role rejection preserves parent state",
            "TreeKEM root and leaf secrets retained only as deterministic candidate vector artifacts",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("role-change-leaf-secret", 0, 32, "tree_root_secret"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 1, 32, "governance_signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn generate_role_change_vectors_m8_4(root: &Path) {
    generate_lite_role_change_vector(root);
    generate_treekem_role_change_vector(
        root,
        TreeKemRoleChangeVector {
            vector_id: "TV-GROUP-ROLE-INTERACTIVE-000",
            mode: GroupMode::Interactive,
            alice_role: GroupRole::Moderator,
            bob_old_role: GroupRole::Member,
            bob_new_role: GroupRole::Moderator,
            invalid_role: GroupRole::Audience,
            carol_role: GroupRole::Member,
        },
    );
    generate_treekem_role_change_vector(
        root,
        TreeKemRoleChangeVector {
            vector_id: "TV-GROUP-ROLE-BROADCAST-000",
            mode: GroupMode::Broadcast,
            alice_role: GroupRole::Moderator,
            bob_old_role: GroupRole::Presenter,
            bob_new_role: GroupRole::Audience,
            invalid_role: GroupRole::Member,
            carol_role: GroupRole::Presenter,
        },
    );
}

fn remapped_roster_for_mode(mode: GroupMode, source: &[RosterEntry]) -> Vec<RosterEntry> {
    let mut roster = source.to_vec();
    let mut active = roster
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry.status == MemberStatus::Active).then_some(index))
        .collect::<Vec<_>>();
    active.sort_by_key(|index| roster[*index].member_id.0);
    match mode.required_mechanism() {
        MembershipMechanism::TreeKem => {
            for (slot, index) in active.into_iter().enumerate() {
                roster[index].tree_leaf_slot =
                    u32::try_from(slot).expect("mode-change slot fits u32");
            }
        }
        MembershipMechanism::DirectWrap => {
            for index in active {
                roster[index].tree_leaf_slot = u32::MAX;
            }
        }
    }
    roster
}

fn active_slot_artifact(roster: &[RosterEntry]) -> Vec<u8> {
    let mut entries = roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.member_id.0);
    let mut encoded = Vec::new();
    for entry in entries {
        encoded.extend_from_slice(&entry.member_id.0);
        encoded.extend_from_slice(&entry.tree_leaf_slot.to_be_bytes());
    }
    encoded
}

fn active_tree_slots_are_compact_by_member_id(roster: &[RosterEntry]) -> bool {
    let mut entries = roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.member_id.0);
    entries.into_iter().enumerate().all(|(slot, entry)| {
        entry.tree_leaf_slot == u32::try_from(slot).expect("active slot fits u32")
    })
}

fn sender_chain_index_artifact(state: &GroupState) -> Vec<u8> {
    let mut encoded = Vec::new();
    for sender in &state.sender_chains.senders {
        encoded.extend_from_slice(&sender.sender.0);
        encoded.extend_from_slice(&sender.next_index.to_be_bytes());
    }
    encoded
}

fn membership_mechanism_artifact(state: &GroupState) -> Vec<u8> {
    vec![
        state
            .membership
            .mechanism()
            .map_or(0, |mechanism| mechanism as u8),
    ]
}

fn old_leaf_for_member(state: &GroupState, member_id: MemberId) -> Option<PublicLeaf> {
    let MembershipPrivateState::TreeKem { public_tree, .. } = &state.membership else {
        return None;
    };
    public_tree
        .nodes
        .iter()
        .filter_map(|node| node.leaf.as_ref())
        .find(|leaf| leaf.member_id == member_id)
        .cloned()
}

fn mode_change_public_tree(
    state: &GroupState,
    new_mode: GroupMode,
    roster: &[RosterEntry],
) -> PublicTree {
    let mut tree =
        PublicTree::new(new_mode, Some(Epoch(state.epoch.0 + 1))).expect("mode-change tree");
    for entry in roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active)
    {
        let old_leaf = old_leaf_for_member(state, entry.member_id);
        let leaf = PublicLeaf {
            member_id: entry.member_id,
            device_identity_fingerprint: entry.device_identity_fingerprint,
            role: entry.role,
            generation: old_leaf.as_ref().map_or(0, |leaf| leaf.generation),
            node_key: old_leaf.and_then(|leaf| leaf.node_key),
        };
        tree.occupy_leaf(entry.tree_leaf_slot, leaf)
            .expect("occupy mode-change leaf");
    }
    tree
}

fn prepare_mode_change_update_path(
    vector_id: &str,
    state: &GroupState,
    new_mode: GroupMode,
    signer: MemberId,
    nonce_occurrence: u32,
    secret_purpose: &str,
) -> (
    Vec<RosterEntry>,
    PublicTree,
    PrivatePath,
    UpdatePath,
    [u8; 32],
) {
    let roster = remapped_roster_for_mode(new_mode, &state.roster);
    let mut tree = mode_change_public_tree(state, new_mode, &roster);
    let base_tree_hash = tree.tree_hash().expect("mode-change base tree hash");
    let signer_slot = roster
        .iter()
        .find(|entry| entry.member_id == signer)
        .expect("mode-change signer remains active")
        .tree_leaf_slot;
    let mut private_path = PrivatePath::default();
    let leaf_secret = Secret32::new(draw32(vector_id, secret_purpose, 0));
    let path_update = derive_and_install_path(
        &mut tree,
        &mut private_path,
        TreeKemPathContext {
            group_id: state.group_id,
            mode: new_mode,
            epoch: Epoch(state.epoch.0 + 1),
            state_version: StateVersion(state.state_version.0 + 1),
            leaf_slot: signer_slot,
            commit_nonce: nonce(vector_id, nonce_occurrence),
            tree_hash: base_tree_hash,
        },
        &leaf_secret,
    )
    .expect("derive mode-change update path");
    let root_secret = *path_update.root_secret.expose_for_backend();
    let update_path = encrypt_path_updates(
        &tree,
        &private_path,
        TreeKemWrapContext {
            group_id: state.group_id,
            mode: new_mode,
            new_epoch: Epoch(state.epoch.0 + 1),
            new_state_version: StateVersion(state.state_version.0 + 1),
            commit_nonce: nonce(vector_id, nonce_occurrence),
            tree_hash: path_update.tree_hash_after,
        },
        &path_update,
        &[],
    )
    .expect("wrap mode-change update path");
    (roster, tree, private_path, update_path, root_secret)
}

fn build_lite_mode_parent_state(
    vector_id: &str,
) -> (GroupState, IdentityMaterial, IdentityMaterial, [u8; 32]) {
    let alice = identity_material(vector_id, 0);
    let bob = identity_material(vector_id, 1);
    let mut alice_entry = entry_for_identity(&alice, GroupRole::Moderator, u32::MAX, Epoch(1));
    let mut bob_entry = entry_for_identity(&bob, GroupRole::Member, u32::MAX, Epoch(1));
    alice_entry.tree_leaf_slot = u32::MAX;
    bob_entry.tree_leaf_slot = u32::MAX;
    let parent_secret = direct_secret(vector_id, 0);
    let mut state = GroupState::new_validated(GroupStateConfig {
        group_id: group_id(vector_id),
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        epoch: Epoch(1),
        state_version: StateVersion(1),
        governance_policy: GovernancePolicy::single_signer(alice.member_id),
        mode_policy: ModePolicy::default(),
        roster: vec![alice_entry, bob_entry],
    })
    .expect("Lite mode-change parent validates");
    state.last_commit_hash = draw64(vector_id, "parent-commit-hash", 0);
    state.membership = MembershipPrivateState::DirectWrap {
        epoch_secret: Secret32::new(parent_secret),
    };
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(parent_secret), &state.epoch_key_context())
            .expect("Lite mode-change parent epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("Lite mode-change parent sender chains");
    (state, alice, bob, parent_secret)
}

fn generate_lite_to_interactive_mode_change_vector(root: &Path) {
    const ID: &str = "TV-GROUP-MODE-LITE-INTERACTIVE-000";
    let (mut state, alice, _bob, _parent_secret) = build_lite_mode_parent_state(ID);
    let pre_mode_message = state
        .seal_group_data(alice.member_id, b"advance old Lite sender chain")
        .expect("advance Lite sender chain before mode change");
    assert!(
        state
            .sender_chains
            .senders
            .iter()
            .any(|sender| sender.next_index == 1)
    );
    let parent_state_hash = state_commitment(&state);
    let parent_slots = active_slot_artifact(&state.roster);
    assert!(
        state
            .roster
            .iter()
            .filter(|entry| entry.status == MemberStatus::Active)
            .all(|entry| entry.tree_leaf_slot == u32::MAX)
    );
    let (_candidate_roster, _candidate_tree, candidate_private_path, update_path, root_secret) =
        prepare_mode_change_update_path(
            ID,
            &state,
            GroupMode::Interactive,
            alice.member_id,
            1,
            "mode-change-leaf-secret",
        );
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(ID, 1),
        change: CommitChange::ModeChange {
            new_mode: GroupMode::Interactive,
            new_mode_policy: ModePolicy::default(),
        },
        signatures: Vec::new(),
        update_path: Some(update_path.clone()),
        direct_epoch_secret: None,
    };
    let prepared = sign_direct_plan(ID, &state, plan, &alice, 1);
    let payload = encode_change_payload(&ChangePayload::ModeChange {
        old_mode: GroupMode::Lite,
        new_mode: GroupMode::Interactive,
        new_mode_policy: ModePolicy::default(),
    })
    .expect("Lite->Interactive payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set = encode_signature_set(&prepared.signatures).expect("signature set");
    let commit_hash_value = prepared.commit_hash;
    apply_prepared_commit(&mut state, prepared).expect("apply Lite->Interactive mode change");
    if let MembershipPrivateState::TreeKem { private_path, .. } = &mut state.membership {
        *private_path = candidate_private_path;
    } else {
        panic!("Lite->Interactive installed TreeKEM material");
    }
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(root_secret), &state.epoch_key_context())
            .expect("Lite->Interactive epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("Lite->Interactive sender chains");
    assert_eq!(state.mode, GroupMode::Interactive);
    assert_eq!(state.mechanism, MembershipMechanism::TreeKem);
    assert!(active_tree_slots_are_compact_by_member_id(&state.roster));
    assert!(
        state
            .sender_chains
            .senders
            .iter()
            .all(|sender| sender.next_index == 0)
    );
    assert_eq!(
        state.membership.mechanism(),
        Some(MembershipMechanism::TreeKem)
    );
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        (
            "parent_lite_sender_message".to_owned(),
            pre_mode_message.envelope,
        ),
        ("parent_lite_active_slots".to_owned(), parent_slots),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("mode_change_payload".to_owned(), payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("governance_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        (
            "update_path".to_owned(),
            hydra_group::encode_update_path(&update_path).expect("update path encodes"),
        ),
        ("tree_root_secret".to_owned(), root_secret.to_vec()),
        (
            "installed_active_slots".to_owned(),
            active_slot_artifact(&state.roster),
        ),
        (
            "installed_sender_chain_indices".to_owned(),
            sender_chain_index_artifact(&state),
        ),
        (
            "installed_membership_mechanism".to_owned(),
            membership_mechanism_artifact(&state),
        ),
        ("installed_state_hash".to_owned(), state_commitment(&state)),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Lite direct-wrap mode changes to Interactive TreeKEM with contiguous active slots",
            "old direct-wrap state is replaced, sender chains reset to index 0, and TreeKEM material is installed",
            "TreeKEM root secret retained only as deterministic candidate vector artifact",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("mode-change-leaf-secret", 0, 32, "tree_root_secret"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 1, 32, "governance_signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn generate_interactive_to_lite_mode_change_vector(root: &Path) {
    const ID: &str = "TV-GROUP-MODE-INTERACTIVE-LITE-000";
    let (mut state, alice, _bob, _carol, _parent_root) = build_tree_three_member_state(
        ID,
        GroupMode::Interactive,
        GroupRole::Moderator,
        GroupRole::Member,
        GroupRole::Member,
    );
    let pre_mode_message = state
        .seal_group_data(alice.member_id, b"advance old Interactive sender chain")
        .expect("advance Interactive sender chain before mode change");
    let parent_state_hash = state_commitment(&state);
    assert!(
        state
            .sender_chains
            .senders
            .iter()
            .any(|sender| sender.next_index == 1)
    );
    let direct_epoch_secret = direct_secret(ID, 1);
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(ID, 1),
        change: CommitChange::ModeChange {
            new_mode: GroupMode::Lite,
            new_mode_policy: ModePolicy::default(),
        },
        signatures: Vec::new(),
        update_path: None,
        direct_epoch_secret: Some(direct_epoch_secret),
    };
    let prepared = sign_tree_plan(ID, &state, plan, &alice, 1);
    let payload = encode_change_payload(&ChangePayload::ModeChange {
        old_mode: GroupMode::Interactive,
        new_mode: GroupMode::Lite,
        new_mode_policy: ModePolicy::default(),
    })
    .expect("Interactive->Lite payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set = encode_signature_set(&prepared.signatures).expect("signature set");
    let commit_hash_value = prepared.commit_hash;
    apply_prepared_commit(&mut state, prepared).expect("apply Interactive->Lite mode change");
    assert_eq!(state.mode, GroupMode::Lite);
    assert_eq!(state.mechanism, MembershipMechanism::DirectWrap);
    assert!(
        state
            .roster
            .iter()
            .filter(|entry| entry.status == MemberStatus::Active)
            .all(|entry| entry.tree_leaf_slot == u32::MAX)
    );
    assert!(
        state
            .sender_chains
            .senders
            .iter()
            .all(|sender| sender.next_index == 0)
    );
    assert_eq!(
        state.membership.mechanism(),
        Some(MembershipMechanism::DirectWrap)
    );
    let message = state
        .seal_group_data(alice.member_id, b"post mode-change Lite data")
        .expect("Lite sender works after mode change");
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        (
            "parent_interactive_sender_message".to_owned(),
            pre_mode_message.envelope,
        ),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("mode_change_payload".to_owned(), payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("governance_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        (
            "direct_wrap_material".to_owned(),
            direct_epoch_secret.to_vec(),
        ),
        (
            "installed_active_slots".to_owned(),
            active_slot_artifact(&state.roster),
        ),
        (
            "installed_sender_chain_indices".to_owned(),
            sender_chain_index_artifact(&state),
        ),
        (
            "installed_membership_mechanism".to_owned(),
            membership_mechanism_artifact(&state),
        ),
        ("post_mode_group_message".to_owned(), message.envelope),
        ("installed_state_hash".to_owned(), state_commitment(&state)),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Interactive TreeKEM mode changes to Lite direct-wrap with active slots set to 0xffffffff",
            "old TreeKEM private state is replaced, sender chains reset to index 0, and direct-wrap material is installed",
            "direct-wrap replacement epoch secret retained only as deterministic candidate vector artifact",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("direct-epoch-secret", 1, 32, "direct_wrap_material"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 1, 32, "governance_signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn generate_interactive_to_broadcast_mode_change_vector(root: &Path) {
    const ID: &str = "TV-GROUP-MODE-INTERACTIVE-BROADCAST-000";
    let (mut state, alice, _bob, _carol, _parent_root) = build_tree_three_member_state(
        ID,
        GroupMode::Interactive,
        GroupRole::Moderator,
        GroupRole::Moderator,
        GroupRole::Moderator,
    );
    let pre_mode_message = state
        .seal_group_data(alice.member_id, b"advance old Interactive sender chain")
        .expect("advance Interactive sender chain before mode change");
    let parent_state_hash = state_commitment(&state);
    let (_candidate_roster, _candidate_tree, candidate_private_path, update_path, root_secret) =
        prepare_mode_change_update_path(
            ID,
            &state,
            GroupMode::Broadcast,
            alice.member_id,
            1,
            "mode-change-leaf-secret",
        );
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(ID, 1),
        change: CommitChange::ModeChange {
            new_mode: GroupMode::Broadcast,
            new_mode_policy: ModePolicy::default(),
        },
        signatures: Vec::new(),
        update_path: Some(update_path.clone()),
        direct_epoch_secret: None,
    };
    let prepared = sign_tree_plan(ID, &state, plan, &alice, 1);
    let payload = encode_change_payload(&ChangePayload::ModeChange {
        old_mode: GroupMode::Interactive,
        new_mode: GroupMode::Broadcast,
        new_mode_policy: ModePolicy::default(),
    })
    .expect("Interactive->Broadcast payload");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set = encode_signature_set(&prepared.signatures).expect("signature set");
    let commit_hash_value = prepared.commit_hash;
    apply_prepared_commit(&mut state, prepared).expect("apply Interactive->Broadcast mode change");
    if let MembershipPrivateState::TreeKem { private_path, .. } = &mut state.membership {
        *private_path = candidate_private_path;
    } else {
        panic!("Interactive->Broadcast keeps TreeKEM material");
    }
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(root_secret), &state.epoch_key_context())
            .expect("Interactive->Broadcast epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("Interactive->Broadcast sender chains");
    assert_eq!(state.mode, GroupMode::Broadcast);
    assert_eq!(state.mechanism, MembershipMechanism::TreeKem);
    assert!(active_tree_slots_are_compact_by_member_id(&state.roster));
    assert!(
        state
            .sender_chains
            .senders
            .iter()
            .all(|sender| sender.next_index == 0)
    );
    let message = state
        .seal_group_data(alice.member_id, b"post mode-change Broadcast data")
        .expect("Broadcast moderator sends after mode change");
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        (
            "parent_interactive_sender_message".to_owned(),
            pre_mode_message.envelope,
        ),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("mode_change_payload".to_owned(), payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("governance_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        (
            "update_path".to_owned(),
            hydra_group::encode_update_path(&update_path).expect("update path encodes"),
        ),
        ("tree_root_secret".to_owned(), root_secret.to_vec()),
        (
            "installed_active_slots".to_owned(),
            active_slot_artifact(&state.roster),
        ),
        (
            "installed_sender_chain_indices".to_owned(),
            sender_chain_index_artifact(&state),
        ),
        (
            "installed_membership_mechanism".to_owned(),
            membership_mechanism_artifact(&state),
        ),
        ("post_mode_group_message".to_owned(), message.envelope),
        ("installed_state_hash".to_owned(), state_commitment(&state)),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Interactive TreeKEM mode changes to Broadcast TreeKEM with contiguous active slots",
            "TreeKEM capacity changes to Broadcast, sender chains reset to index 0, and old epoch chains are replaced",
            "TreeKEM root secret retained only as deterministic candidate vector artifact",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("mode-change-leaf-secret", 0, 32, "tree_root_secret"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("mldsa-rnd", 1, 32, "governance_signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn generate_invalid_mode_change_vector(root: &Path) {
    const ID: &str = "TV-GROUP-MODE-BAD-000";
    let (state, alice, _bob, _carol, _parent_root) = build_tree_three_member_state(
        ID,
        GroupMode::Interactive,
        GroupRole::Moderator,
        GroupRole::Member,
        GroupRole::Member,
    );
    let before = state_commitment(&state);
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(ID, 1),
        change: CommitChange::ModeChange {
            new_mode: GroupMode::Broadcast,
            new_mode_policy: ModePolicy::default(),
        },
        signatures: vec![signature(ID, alice.member_id, 1)],
        update_path: None,
        direct_epoch_secret: None,
    };
    let error = match prepare_commit(&state, plan) {
        Ok(_) => panic!("incompatible mode change unexpectedly prepared"),
        Err(error) => error,
    };
    let after = state_commitment(&state);
    assert_eq!(before, after);
    let payload = encode_change_payload(&ChangePayload::ModeChange {
        old_mode: GroupMode::Interactive,
        new_mode: GroupMode::Broadcast,
        new_mode_policy: ModePolicy::default(),
    })
    .expect("invalid mode payload still encodes");
    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("mode_change_payload".to_owned(), payload),
        ("invalid_mode_error".to_owned(), error_artifact(error)),
        ("state_before".to_owned(), before.clone()),
        ("state_after".to_owned(), after),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "Interactive to Broadcast mode change rejects when active Member roles are incompatible with Broadcast",
            "invalid mode transition preserves the parent state commitment",
            "no candidate membership material is installed after rejection",
            &[
                ("group-id", 0, 32, "group_id"),
                ("member-id", 0, 32, "alice_member_id"),
                ("commit-nonce", 1, 32, "mode_change_payload"),
            ],
        ),
        &artifacts,
    );
}

fn encode_u32_list(values: &[u32]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(
        &u32::try_from(values.len())
            .expect("u32 list length fits")
            .to_be_bytes(),
    );
    for value in values {
        encoded.extend_from_slice(&value.to_be_bytes());
    }
    encoded
}

fn generate_treekem_self_update_vector(
    root: &Path,
    vector_id: &str,
    mode: GroupMode,
    alice_role: GroupRole,
    bob_role: GroupRole,
    carol_role: GroupRole,
) {
    let (mut state, alice, _bob, _carol, _parent_root) =
        build_tree_three_member_state(vector_id, mode, alice_role, bob_role, carol_role);
    let parent_state_hash = state_commitment(&state);
    let parent_roster = encode_roster(mode, &state.roster).expect("parent roster encodes");

    let missing_before = state_commitment(&state);
    let missing_path_plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(vector_id, 2),
        change: CommitChange::TreeSelfUpdate {
            committer_member_id: alice.member_id,
        },
        signatures: vec![signature(vector_id, alice.member_id, 2)],
        update_path: None,
        direct_epoch_secret: None,
    };
    let missing_update_path_error = match prepare_commit(&state, missing_path_plan) {
        Ok(_) => panic!("TreeKEM self-update without update path unexpectedly prepared"),
        Err(error) => error,
    };
    assert_eq!(missing_before, state_commitment(&state));

    let mut candidate_tree = match &state.membership {
        MembershipPrivateState::TreeKem { public_tree, .. } => public_tree.clone(),
        _ => panic!("TreeKEM parent expected"),
    };
    let base_tree_hash = candidate_tree
        .tree_hash()
        .expect("self-update base tree hash");
    assert_eq!(base_tree_hash, state.tree_hash);
    let mut candidate_private_path = PrivatePath::default();
    let leaf_secret = Secret32::new(draw32(vector_id, "self-update-leaf-secret", 0));
    let path_update = derive_and_install_path(
        &mut candidate_tree,
        &mut candidate_private_path,
        TreeKemPathContext {
            group_id: state.group_id,
            mode,
            epoch: Epoch(2),
            state_version: StateVersion(2),
            leaf_slot: 0,
            commit_nonce: nonce(vector_id, 1),
            tree_hash: base_tree_hash,
        },
        &leaf_secret,
    )
    .expect("derive TreeKEM self-update path");
    let root_secret = *path_update.root_secret.expose_for_backend();
    let wrap_context = TreeKemWrapContext {
        group_id: state.group_id,
        mode,
        new_epoch: Epoch(2),
        new_state_version: StateVersion(2),
        commit_nonce: nonce(vector_id, 1),
        tree_hash: path_update.tree_hash_after,
    };
    let update_path = encrypt_path_updates(
        &candidate_tree,
        &candidate_private_path,
        wrap_context,
        &path_update,
        &[],
    )
    .expect("wrap TreeKEM self-update path");
    assert_eq!(
        update_path.updated_nodes.len(),
        path_update.updated_nodes.len()
    );
    assert_eq!(update_path.candidate_tree_hash, path_update.tree_hash_after);

    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(vector_id, 1),
        change: CommitChange::TreeSelfUpdate {
            committer_member_id: alice.member_id,
        },
        signatures: Vec::new(),
        update_path: Some(update_path.clone()),
        direct_epoch_secret: None,
    };
    let prepared = sign_tree_plan(vector_id, &state, plan, &alice, 1);
    let self_update_payload = encode_change_payload(&ChangePayload::TreeSelfUpdate {
        committer_member_id: alice.member_id,
    })
    .expect("self-update payload encodes");
    let encoded_core = prepared.encoded_core.clone();
    let signature_digest = prepared.signature_digest;
    let signature_set =
        encode_signature_set(&prepared.signatures).expect("self-update signatures encode");
    let commit_hash_value = prepared.commit_hash;
    let update_path_bytes =
        hydra_group::encode_update_path(&update_path).expect("self-update path encodes");
    let update_path_hash_value = update_path_hash(&update_path).expect("self-update path hashes");

    apply_prepared_commit(&mut state, prepared).expect("apply TreeKEM self-update");
    if let MembershipPrivateState::TreeKem { private_path, .. } = &mut state.membership {
        *private_path = candidate_private_path;
        assert_eq!(private_path.node_indices(), path_update.direct_path);
    } else {
        panic!("TreeKEM membership expected after self-update");
    }
    let epoch_key =
        derive_epoch_key_for_context(&Secret32::new(root_secret), &state.epoch_key_context())
            .expect("derive TreeKEM self-update epoch key");
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("install TreeKEM self-update sender chains");
    assert_eq!(state.epoch, Epoch(2));
    assert_eq!(state.state_version, StateVersion(2));
    assert_eq!(
        encode_roster(mode, &state.roster).expect("new roster encodes"),
        parent_roster
    );
    assert_eq!(state.tree_hash, path_update.tree_hash_after);
    let installed_state_hash = state_commitment(&state);
    let first_post_update_message = state
        .seal_group_data(alice.member_id, b"post self-update group data")
        .expect("self-updater sends after refreshed sender chains");
    assert_eq!(first_post_update_message.index, 0);

    let artifacts = vec![
        ("group_id".to_owned(), state.group_id.0.to_vec()),
        ("alice_member_id".to_owned(), alice.member_id.0.to_vec()),
        ("alice_verification_key".to_owned(), alice.verification_key),
        ("parent_state_hash".to_owned(), parent_state_hash),
        ("parent_roster".to_owned(), parent_roster),
        ("self_update_payload".to_owned(), self_update_payload),
        ("commit_core".to_owned(), encoded_core),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("governance_signature_set".to_owned(), signature_set),
        ("commit_hash".to_owned(), commit_hash_value.to_vec()),
        ("update_path".to_owned(), update_path_bytes),
        (
            "update_path_hash".to_owned(),
            update_path_hash_value.to_vec(),
        ),
        (
            "direct_path_nodes".to_owned(),
            encode_u32_list(&path_update.direct_path),
        ),
        ("tree_root_secret".to_owned(), root_secret.to_vec()),
        (
            "tree_hash_after".to_owned(),
            path_update.tree_hash_after.to_vec(),
        ),
        (
            "sender_chain_probe_message".to_owned(),
            first_post_update_message.envelope,
        ),
        ("installed_state_hash".to_owned(), installed_state_hash),
        (
            "missing_update_path_error".to_owned(),
            error_artifact(missing_update_path_error),
        ),
        (
            "missing_update_path_state_before".to_owned(),
            missing_before.clone(),
        ),
        ("missing_update_path_state_after".to_owned(), missing_before),
    ];
    let result = match mode {
        GroupMode::Interactive => {
            "Interactive TreeKEM self-update refreshes the committer path and sender chains"
        }
        GroupMode::Broadcast => {
            "Broadcast TreeKEM self-update refreshes the moderator path and sender chains"
        }
        GroupMode::Lite => unreachable!("Lite has no TreeKEM self-update"),
    };
    write_owned(
        root,
        "group",
        vector_id,
        &metadata(
            result,
            "roster is unchanged, epoch/state version advance by one, tree hash changes, sender chains reset to index 0, and missing update path preserves parent state",
            "TreeKEM root and leaf secrets retained only as deterministic candidate vector artifacts",
            &[
                ("group-id", 0, 32, "group_id"),
                ("member-id", 0, 32, "alice_member_id"),
                ("mldsa-xi", 0, 32, "alice_verification_key"),
                ("parent-leaf-secret", 0, 32, "parent_state_hash"),
                ("self-update-leaf-secret", 0, 32, "tree_root_secret"),
                ("commit-nonce", 1, 32, "commit_core"),
                ("commit-nonce", 2, 32, "missing_update_path_error"),
                ("mldsa-rnd", 1, 32, "governance_signature_set"),
            ],
        ),
        &artifacts,
    );
}

fn generate_self_update_vectors_m8_6(root: &Path) {
    generate_treekem_self_update_vector(
        root,
        "TV-GROUP-SELF-UPDATE-INTERACTIVE-000",
        GroupMode::Interactive,
        GroupRole::Moderator,
        GroupRole::Member,
        GroupRole::Member,
    );
    generate_treekem_self_update_vector(
        root,
        "TV-GROUP-SELF-UPDATE-BROADCAST-000",
        GroupMode::Broadcast,
        GroupRole::Moderator,
        GroupRole::Audience,
        GroupRole::Presenter,
    );
}

const GROUP_DATA_SIGNED_OVERHEAD: usize = 4 + ML_DSA_65_SIG_SIZE;

fn app_limit_for_group_class(class: EnvelopeClass) -> usize {
    class
        .max_content_size()
        .checked_sub(GROUP_DATA_SIGNED_OVERHEAD)
        .expect("group DATA signed overhead fits every class")
}

fn group_data_class_for_mode(mode: GroupMode, application_len: usize) -> Option<EnvelopeClass> {
    let signed_len = GROUP_DATA_SIGNED_OVERHEAD.checked_add(application_len)?;
    match mode {
        GroupMode::Lite => {
            if application_len <= app_limit_for_group_class(EnvelopeClass::Lite)
                && signed_len <= LITE_MAX_CONTENT_SIZE
            {
                Some(EnvelopeClass::Lite)
            } else {
                None
            }
        }
        GroupMode::Interactive => {
            if signed_len <= STANDARD_MAX_CONTENT_SIZE {
                Some(EnvelopeClass::Standard)
            } else if signed_len <= FULL_MAX_CONTENT_SIZE {
                Some(EnvelopeClass::Full)
            } else {
                None
            }
        }
        GroupMode::Broadcast => {
            if signed_len <= LITE_MAX_CONTENT_SIZE {
                Some(EnvelopeClass::Lite)
            } else if signed_len <= STANDARD_MAX_CONTENT_SIZE {
                Some(EnvelopeClass::Standard)
            } else if signed_len <= FULL_MAX_CONTENT_SIZE {
                Some(EnvelopeClass::Full)
            } else {
                None
            }
        }
    }
}

fn group_skip_bound_for_vector(mode: GroupMode) -> u64 {
    match mode {
        GroupMode::Lite => 32,
        GroupMode::Interactive => 64,
        GroupMode::Broadcast => 256,
    }
}

fn deterministic_group_message_aead_key(state: &GroupState, step: &SenderMessageStep) -> [u8; 32] {
    let mut context = Vec::new();
    context.extend_from_slice(&SUITE_ID);
    context.extend_from_slice(&state.group_id.0);
    context.push(state.mode as u8);
    context.extend_from_slice(&state.epoch.0.to_be_bytes());
    context.extend_from_slice(&state.state_version.0.to_be_bytes());
    context.extend_from_slice(&step.sender.0);
    context.extend_from_slice(&step.index.to_be_bytes());
    let mut info = Vec::new();
    info.extend_from_slice(&lp(b"HYDRA-MSG/v1/group/message/aead-key").unwrap());
    info.extend_from_slice(&lp(&context).unwrap());
    let output = RustCryptoBackend::hkdf_expand(step.message_key.expose_for_backend(), &info, 32)
        .expect("group message AEAD key derives");
    fixed(&output, "group message AEAD key")
}

fn seal_deterministic_signed_group_data(
    vector_id: &str,
    state: &mut GroupState,
    sender: &IdentityMaterial,
    signature_occurrence: u32,
    application_content: &[u8],
) -> hydra_group::GroupResult<(hydra_group::GroupOutboundMessage, EnvelopeClass, [u8; 64])> {
    let class = group_data_class_for_mode(state.mode, application_content.len())
        .ok_or(hydra_group::GroupError::InvalidEnvelope)?;
    let step = state.next_sender_message_step(sender.member_id)?;
    let digest = group_data_signature_digest(state, class, &step, application_content)?;
    let rnd: [u8; 32] = fixed(
        &tv_draw(
            vector_id,
            "group-message-signature-rnd",
            signature_occurrence,
            32,
        ),
        "group message signature randomness",
    );
    let signature = sign_digest(&sender.signing_key, &digest, &rnd);
    let mut signed_content =
        Vec::with_capacity(GROUP_DATA_SIGNED_OVERHEAD + application_content.len());
    signed_content.extend_from_slice(
        &u32::try_from(application_content.len())
            .expect("application content length fits u32")
            .to_be_bytes(),
    );
    signed_content.extend_from_slice(application_content);
    signed_content.extend_from_slice(&signature);
    let record = ProtectedRecord {
        content_kind: hydra_core::types::ContentKind::GroupData,
        session_or_group_id: state.group_id.0,
        sender_id: sender.member_id.0,
        epoch: state.epoch.0,
        state_version: state.state_version.0,
        message_index: step.index,
        content: signed_content,
    };
    let plaintext = encode_protected_record(class, &record)
        .expect("deterministic signed GROUP_DATA protected record encodes");
    let header = encode_outer_header(&OuterHeader::new(
        OuterMode::Protected,
        class,
        step.route_tag,
        step.index,
    ))
    .expect("deterministic GROUP_DATA header encodes");
    let aead_key = deterministic_group_message_aead_key(state, &step);
    let body = RustCryptoBackend::aead_seal(
        &SecretBytes::from_array(aead_key),
        &[0_u8; AEAD_NONCE_SIZE],
        &header,
        &plaintext,
    )
    .expect("deterministic GROUP_DATA AEAD seals");
    let mut envelope = Vec::with_capacity(class.envelope_size());
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&body);
    Ok((
        hydra_group::GroupOutboundMessage {
            sender: sender.member_id,
            index: step.index,
            envelope,
        },
        class,
        digest,
    ))
}

fn group_message_state(
    vector_id: &str,
    mode: GroupMode,
) -> (GroupState, Vec<IdentityMaterial>, Secret32) {
    let alice = identity_material(vector_id, 0);
    let bob = identity_material(vector_id, 1);
    let carol = identity_material(vector_id, 2);
    let (mechanism, roster) = match mode {
        GroupMode::Lite => (
            MembershipMechanism::DirectWrap,
            vec![
                entry_for_identity(&alice, GroupRole::Member, u32::MAX, Epoch(3)),
                entry_for_identity(&bob, GroupRole::Moderator, u32::MAX, Epoch(3)),
            ],
        ),
        GroupMode::Interactive => (
            MembershipMechanism::TreeKem,
            vec![
                entry_for_identity(&alice, GroupRole::Moderator, 0, Epoch(3)),
                entry_for_identity(&bob, GroupRole::Member, 1, Epoch(3)),
            ],
        ),
        GroupMode::Broadcast => (
            MembershipMechanism::TreeKem,
            vec![
                entry_for_identity(&alice, GroupRole::Moderator, 0, Epoch(3)),
                entry_for_identity(&bob, GroupRole::Presenter, 1, Epoch(3)),
                entry_for_identity(&carol, GroupRole::Audience, 2, Epoch(3)),
            ],
        ),
    };
    let mut state = GroupState::new_validated(GroupStateConfig {
        group_id: group_id(vector_id),
        mode,
        mechanism,
        epoch: Epoch(3),
        state_version: StateVersion(5),
        governance_policy: GovernancePolicy::single_signer(alice.member_id),
        mode_policy: ModePolicy::default(),
        roster,
    })
    .expect("group message state validates");
    state.tree_hash = match mode {
        GroupMode::Lite => [0; 64],
        _ => draw64(vector_id, "message-tree-hash", 0),
    };
    state.last_commit_hash = draw64(vector_id, "message-commit-hash", 0);
    let epoch_key = Secret32::new(draw32(vector_id, "message-epoch-key", 0));
    state
        .install_epoch_sender_chains(&epoch_key)
        .expect("group message sender chains install");
    (state, vec![alice, bob, carol], epoch_key)
}

fn verification_resolver(
    identities: &[IdentityMaterial],
    sender: MemberId,
) -> Option<MlDsaVerificationKey> {
    identities
        .iter()
        .find(|identity| identity.member_id == sender)
        .and_then(|identity| MlDsaVerificationKey::from_bytes(&identity.verification_key).ok())
}

fn error_bytes(error: hydra_group::GroupError) -> Vec<u8> {
    format!("{error:?}").into_bytes()
}

fn generate_group_message_vector(
    root: &Path,
    vector_id: &str,
    mode: GroupMode,
    application_len: usize,
    expected_class: EnvelopeClass,
    sender_index: usize,
    result: &str,
) {
    let (mut sender_state, identities, _epoch_key) = group_message_state(vector_id, mode);
    let mut receiver_state = group_message_state(vector_id, mode).0;
    let sender = &identities[sender_index];
    let content = tv_draw(vector_id, "group-message-content", 0, application_len);
    let parent_sender_state = state_commitment(&sender_state);
    let parent_receiver_state = state_commitment(&receiver_state);
    let (outbound, class, signature_digest) =
        seal_deterministic_signed_group_data(vector_id, &mut sender_state, sender, 0, &content)
            .expect("deterministic signed group message seals");
    assert_eq!(class, expected_class);
    let header = decode_outer_header(&outbound.envelope).expect("GROUP_DATA header decodes");
    assert_eq!(header.envelope_class, expected_class);
    assert_eq!(outbound.envelope.len(), expected_class.envelope_size());
    let received = receiver_state
        .open_signed_group_data(&outbound.envelope, |member_id| {
            verification_resolver(&identities, member_id)
        })
        .expect("signed GROUP_DATA verifies");
    assert_eq!(received.sender, sender.member_id);
    assert_eq!(received.content, content);
    let replay_before = state_commitment(&receiver_state);
    let replay_error = receiver_state
        .open_signed_group_data(&outbound.envelope, |member_id| {
            verification_resolver(&identities, member_id)
        })
        .expect_err("duplicate GROUP_DATA rejects");
    assert_eq!(state_commitment(&receiver_state), replay_before);
    let artifacts = vec![
        ("group_id".to_owned(), sender_state.group_id.0.to_vec()),
        ("mode".to_owned(), vec![mode as u8]),
        ("sender_member_id".to_owned(), sender.member_id.0.to_vec()),
        (
            "sender_verification_key".to_owned(),
            sender.verification_key.clone(),
        ),
        ("application_content".to_owned(), content),
        ("parent_sender_state_hash".to_owned(), parent_sender_state),
        (
            "parent_receiver_state_hash".to_owned(),
            parent_receiver_state,
        ),
        ("signature_digest".to_owned(), signature_digest.to_vec()),
        ("envelope".to_owned(), outbound.envelope),
        ("envelope_class".to_owned(), vec![expected_class as u8]),
        (
            "sender_state_after".to_owned(),
            state_commitment(&sender_state),
        ),
        (
            "receiver_state_after".to_owned(),
            state_commitment(&receiver_state),
        ),
        ("replay_error".to_owned(), error_bytes(replay_error)),
        (
            "replay_state_after".to_owned(),
            state_commitment(&receiver_state),
        ),
    ];
    write_owned(
        root,
        "group",
        vector_id,
        &metadata(
            result,
            "sender signature verifies, class selection is exact, duplicate replay is rejected without changing receiver state",
            "message key, signature randomness, and sender-chain candidates retained only as deterministic vector artifacts",
            &[
                ("group-id", 0, 32, "group_id"),
                (
                    "mldsa-xi",
                    sender_index as u32,
                    32,
                    "sender_verification_key",
                ),
                ("message-epoch-key", 0, 32, "parent_sender_state_hash"),
                (
                    "group-message-content",
                    0,
                    application_len,
                    "application_content",
                ),
                ("group-message-signature-rnd", 0, 32, "envelope"),
            ],
        ),
        &artifacts,
    );
}

fn generate_group_message_negative_vector(root: &Path) {
    const ID: &str = "TV-GROUP-MSG-BAD-000";
    let (mut sender_state, identities, _epoch_key) = group_message_state(ID, GroupMode::Broadcast);
    let alice = &identities[0];
    let audience = &identities[2];
    let audience_error = seal_deterministic_signed_group_data(
        ID,
        &mut sender_state,
        audience,
        0,
        b"audience must not send",
    )
    .expect_err("broadcast audience send rejects");
    let (outbound, class, _digest) = seal_deterministic_signed_group_data(
        ID,
        &mut sender_state,
        alice,
        1,
        b"context-bound broadcast message",
    )
    .expect("broadcast moderator sends");
    assert_eq!(class, EnvelopeClass::Lite);

    let mut wrong_group = group_message_state(ID, GroupMode::Broadcast).0;
    wrong_group.group_id.0[0] ^= 1;
    let wrong_group_before = state_commitment(&wrong_group);
    let wrong_group_error = wrong_group
        .open_signed_group_data(&outbound.envelope, |member_id| {
            verification_resolver(&identities, member_id)
        })
        .expect_err("wrong group rejects");
    assert_eq!(state_commitment(&wrong_group), wrong_group_before);

    let mut wrong_mode = group_message_state(ID, GroupMode::Broadcast).0;
    wrong_mode.mode = GroupMode::Interactive;
    let wrong_mode_before = state_commitment(&wrong_mode);
    let wrong_mode_error = wrong_mode
        .open_signed_group_data(&outbound.envelope, |member_id| {
            verification_resolver(&identities, member_id)
        })
        .expect_err("wrong mode rejects");
    assert_eq!(state_commitment(&wrong_mode), wrong_mode_before);

    let mut wrong_epoch = group_message_state(ID, GroupMode::Broadcast).0;
    wrong_epoch.epoch = Epoch(wrong_epoch.epoch.0 + 1);
    let wrong_epoch_before = state_commitment(&wrong_epoch);
    let wrong_epoch_error = wrong_epoch
        .open_signed_group_data(&outbound.envelope, |member_id| {
            verification_resolver(&identities, member_id)
        })
        .expect_err("wrong epoch rejects");
    assert_eq!(state_commitment(&wrong_epoch), wrong_epoch_before);

    let mut wrong_state_version = group_message_state(ID, GroupMode::Broadcast).0;
    wrong_state_version.state_version = StateVersion(wrong_state_version.state_version.0 + 1);
    let wrong_state_version_before = state_commitment(&wrong_state_version);
    let wrong_state_version_error = wrong_state_version
        .open_signed_group_data(&outbound.envelope, |member_id| {
            verification_resolver(&identities, member_id)
        })
        .expect_err("wrong state version rejects");
    assert_eq!(
        state_commitment(&wrong_state_version),
        wrong_state_version_before
    );

    let artifacts = vec![
        ("group_id".to_owned(), sender_state.group_id.0.to_vec()),
        ("authorized_sender".to_owned(), alice.member_id.0.to_vec()),
        ("audience_sender".to_owned(), audience.member_id.0.to_vec()),
        ("valid_envelope".to_owned(), outbound.envelope),
        ("wrong_role_error".to_owned(), error_bytes(audience_error)),
        (
            "wrong_group_error".to_owned(),
            error_bytes(wrong_group_error),
        ),
        (
            "wrong_group_state_before".to_owned(),
            wrong_group_before.clone(),
        ),
        ("wrong_group_state_after".to_owned(), wrong_group_before),
        ("wrong_mode_error".to_owned(), error_bytes(wrong_mode_error)),
        (
            "wrong_mode_state_before".to_owned(),
            wrong_mode_before.clone(),
        ),
        ("wrong_mode_state_after".to_owned(), wrong_mode_before),
        (
            "wrong_epoch_error".to_owned(),
            error_bytes(wrong_epoch_error),
        ),
        (
            "wrong_epoch_state_before".to_owned(),
            wrong_epoch_before.clone(),
        ),
        ("wrong_epoch_state_after".to_owned(), wrong_epoch_before),
        (
            "wrong_state_version_error".to_owned(),
            error_bytes(wrong_state_version_error),
        ),
        (
            "wrong_state_version_before".to_owned(),
            wrong_state_version_before.clone(),
        ),
        (
            "wrong_state_version_after".to_owned(),
            wrong_state_version_before,
        ),
    ];
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "GROUP_DATA wrong-role and wrong-context rejection vector",
            "wrong role, group, mode, epoch, and state version reject without receiver state mutation",
            "negative candidates do not install message, replay, or sender-chain state",
            &[
                ("group-id", 0, 32, "group_id"),
                ("mldsa-xi", 0, 32, "authorized_sender"),
                ("mldsa-xi", 2, 32, "audience_sender"),
            ],
        ),
        &artifacts,
    );
}

fn generate_group_message_reorder_vector(root: &Path) {
    const ID: &str = "TV-GROUP-MSG-REORDER-000";
    let mut artifacts = Vec::new();
    for (mode, label, signer_index) in [
        (GroupMode::Lite, "lite", 0_usize),
        (GroupMode::Interactive, "interactive", 0_usize),
        (GroupMode::Broadcast, "broadcast", 1_usize),
    ] {
        let (mut sender_state, identities, _epoch_key) = group_message_state(ID, mode);
        let mut receiver_state = group_message_state(ID, mode).0;
        let signer = &identities[signer_index];
        let first = seal_deterministic_signed_group_data(
            ID,
            &mut sender_state,
            signer,
            10 + signer_index as u32 + mode as u32,
            format!("{label} index zero").as_bytes(),
        )
        .expect("first reorder message seals")
        .0;
        let second = seal_deterministic_signed_group_data(
            ID,
            &mut sender_state,
            signer,
            20 + signer_index as u32 + mode as u32,
            format!("{label} index one").as_bytes(),
        )
        .expect("second reorder message seals")
        .0;
        assert_eq!(first.index, 0);
        assert_eq!(second.index, 1);
        let before_second = state_commitment(&receiver_state);
        let received_second = receiver_state
            .open_signed_group_data(&second.envelope, |member_id| {
                verification_resolver(&identities, member_id)
            })
            .expect("forward gap within bound accepted");
        assert_eq!(received_second.index, 1);
        assert_eq!(receiver_state.sender_chains.skipped_len(), 1);
        let after_second = state_commitment(&receiver_state);
        let received_first = receiver_state
            .open_signed_group_data(&first.envelope, |member_id| {
                verification_resolver(&identities, member_id)
            })
            .expect("skipped index zero accepted once");
        assert_eq!(received_first.index, 0);
        let after_first = state_commitment(&receiver_state);
        let replay_before = state_commitment(&receiver_state);
        let replay_error = receiver_state
            .open_signed_group_data(&first.envelope, |member_id| {
                verification_resolver(&identities, member_id)
            })
            .expect_err("skipped message replay rejected");
        assert_eq!(state_commitment(&receiver_state), replay_before);

        let (mut far_sender, far_identities, _epoch_key) = group_message_state(ID, mode);
        let mut far_receiver = group_message_state(ID, mode).0;
        let far_signer = &far_identities[signer_index];
        let bound = group_skip_bound_for_vector(mode);
        let mut far = None;
        for i in 0..=bound + 1 {
            let sent = seal_deterministic_signed_group_data(
                ID,
                &mut far_sender,
                far_signer,
                1000 + i as u32 + mode as u32,
                b"gap bound probe",
            )
            .expect("far message seals")
            .0;
            if i == bound + 1 {
                far = Some(sent);
            }
        }
        let far = far.expect("far message captured");
        let far_before = state_commitment(&far_receiver);
        let far_error = far_receiver
            .open_signed_group_data(&far.envelope, |member_id| {
                verification_resolver(&far_identities, member_id)
            })
            .expect_err("one beyond mode skip bound rejects");
        assert_eq!(state_commitment(&far_receiver), far_before);

        artifacts.extend([
            (format!("{label}_skip_bound"), bound.to_be_bytes().to_vec()),
            (format!("{label}_first_envelope"), first.envelope),
            (format!("{label}_second_envelope"), second.envelope),
            (format!("{label}_state_before_second"), before_second),
            (format!("{label}_state_after_second"), after_second),
            (format!("{label}_state_after_first"), after_first),
            (format!("{label}_replay_error"), error_bytes(replay_error)),
            (format!("{label}_far_envelope"), far.envelope),
            (format!("{label}_far_error"), error_bytes(far_error)),
            (format!("{label}_far_state_before"), far_before.clone()),
            (format!("{label}_far_state_after"), far_before),
        ]);
    }
    write_owned(
        root,
        "group",
        ID,
        &metadata(
            "GROUP_DATA replay, reordering, skipped-key, and mode-bound vector",
            "within-bound forward messages install skipped keys, skipped messages are one-use, and one-beyond mode skip bound rejects unchanged",
            "skipped message keys are retained only until authenticated delivery and are vector-test committed",
            &[("group-id", 0, 32, "lite_first_envelope")],
        ),
        &artifacts,
    );
}

fn generate_group_message_vectors_m8_7(root: &Path) {
    generate_group_message_vector(
        root,
        "TV-GROUP-MSG-INTERACTIVE-STANDARD-000",
        GroupMode::Interactive,
        32,
        EnvelopeClass::Standard,
        0,
        "Interactive Standard signed GROUP_DATA verifies",
    );
    generate_group_message_vector(
        root,
        "TV-GROUP-MSG-INTERACTIVE-FULL-000",
        GroupMode::Interactive,
        app_limit_for_group_class(EnvelopeClass::Full),
        EnvelopeClass::Full,
        0,
        "Interactive Full signed GROUP_DATA boundary verifies",
    );
    generate_group_message_vector(
        root,
        "TV-GROUP-MSG-BROADCAST-LITE-000",
        GroupMode::Broadcast,
        app_limit_for_group_class(EnvelopeClass::Lite),
        EnvelopeClass::Lite,
        1,
        "Broadcast Lite signed GROUP_DATA boundary verifies",
    );
    generate_group_message_vector(
        root,
        "TV-GROUP-MSG-BROADCAST-STANDARD-000",
        GroupMode::Broadcast,
        app_limit_for_group_class(EnvelopeClass::Standard),
        EnvelopeClass::Standard,
        1,
        "Broadcast Standard signed GROUP_DATA boundary verifies",
    );
    generate_group_message_vector(
        root,
        "TV-GROUP-MSG-BROADCAST-FULL-000",
        GroupMode::Broadcast,
        app_limit_for_group_class(EnvelopeClass::Full),
        EnvelopeClass::Full,
        1,
        "Broadcast Full signed GROUP_DATA boundary verifies",
    );
    generate_group_message_vector(
        root,
        "TV-GROUP-MSG-LITE-MAX-000",
        GroupMode::Lite,
        app_limit_for_group_class(EnvelopeClass::Lite),
        EnvelopeClass::Lite,
        0,
        "Lite max-size 607-byte signed GROUP_DATA verifies",
    );

    let (mut lite_state, identities, _epoch_key) =
        group_message_state("TV-GROUP-MSG-LITE-OVERSIZE-000", GroupMode::Lite);
    let lite_oversize = vec![0xa5; app_limit_for_group_class(EnvelopeClass::Lite) + 1];
    assert_eq!(
        seal_deterministic_signed_group_data(
            "TV-GROUP-MSG-LITE-OVERSIZE-000",
            &mut lite_state,
            &identities[0],
            0,
            &lite_oversize,
        ),
        Err(hydra_group::GroupError::InvalidEnvelope)
    );
    generate_group_message_negative_vector(root);
    generate_group_message_reorder_vector(root);
}

fn numbered_member(index: u32) -> MemberId {
    let mut bytes = [0_u8; 32];
    bytes[28..32].copy_from_slice(&index.to_be_bytes());
    MemberId(bytes)
}

fn numbered_fingerprint(index: u32) -> IdentityFingerprint {
    let mut bytes = [0xf0_u8; 32];
    bytes[28..32].copy_from_slice(&index.to_be_bytes());
    IdentityFingerprint(bytes)
}

fn numbered_entry(index: u32, role: GroupRole, slot: u32) -> RosterEntry {
    RosterEntry {
        member_id: numbered_member(index),
        device_identity_fingerprint: numbered_fingerprint(index),
        role,
        status: MemberStatus::Active,
        tree_leaf_slot: slot,
        joined_epoch: Epoch(1),
        removed_epoch: Epoch(0),
    }
}

fn raw_roster_candidate(mode: GroupMode, roster: &[RosterEntry]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"HYDRA-MSG/v1/group/negative/roster");
    encoded.push(mode as u8);
    encoded.extend_from_slice(
        &u16::try_from(roster.len())
            .expect("negative roster count fits u16")
            .to_be_bytes(),
    );
    for entry in roster {
        encoded.extend_from_slice(&encode_roster_entry(entry));
    }
    encoded
}

fn raw_governance_candidate(policy: &GovernancePolicy) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"HYDRA-MSG/v1/group/negative/governance");
    encoded.push(policy.policy_version);
    encoded.push(policy.threshold);
    encoded.push(u8::try_from(policy.authorized_signers.len()).expect("signer count fits u8"));
    encoded.push(0);
    for signer in &policy.authorized_signers {
        encoded.extend_from_slice(&signer.0);
    }
    encoded
}

fn raw_signature_set_candidate(signatures: &[CommitSignature]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"HYDRA-MSG/v1/group/negative/signature-set");
    encoded.push(u8::try_from(signatures.len()).expect("signature count fits u8"));
    for signature in signatures {
        encoded.extend_from_slice(&signature.signer.0);
        encoded.extend_from_slice(&signature.signature);
    }
    encoded
}

fn raw_attachment_fragment_candidate(vector_id: &str, object_len: usize) -> Vec<u8> {
    let media_type = b"application/octet-stream";
    let fragment = tv_draw(vector_id, "attachment-fragment", 0, object_len.min(64));
    let object_id = draw32(vector_id, "attachment-object-id", 0);
    let complete_object = tv_draw(vector_id, "attachment-object", 0, object_len.clamp(1, 256));
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(b"HYDRA-MSG/v1/group/attachment-hash");
    digest_input.extend_from_slice(&SUITE_ID);
    digest_input.extend_from_slice(&object_id);
    digest_input.extend_from_slice(&(object_len as u64).to_be_bytes());
    digest_input.extend_from_slice(&length_prefixed_bytes(media_type));
    digest_input.extend_from_slice(&length_prefixed_bytes(&complete_object));
    let digest = RustCryptoBackend::sha3_512(&digest_input);

    let mut encoded = Vec::new();
    encoded.push(0x01);
    encoded.push(0x00);
    encoded.extend_from_slice(&(media_type.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&object_id);
    encoded.extend_from_slice(&(object_len as u64).to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    encoded.extend_from_slice(&0_u64.to_be_bytes());
    encoded.extend_from_slice(&(fragment.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&digest);
    let mut media_slot = [0_u8; 64];
    media_slot[..media_type.len()].copy_from_slice(media_type);
    encoded.extend_from_slice(&media_slot);
    encoded.extend_from_slice(&fragment);
    encoded
}

fn validate_attachment_fragment_for_mode(
    mode: GroupMode,
    candidate: &[u8],
) -> hydra_group::GroupResult<()> {
    if mode == GroupMode::Lite {
        return Err(hydra_group::GroupError::InvalidEnvelope);
    }
    if candidate.len() < 193 || candidate[0] != 0x01 || candidate[1] != 0 {
        return Err(hydra_group::GroupError::InvalidEnvelope);
    }
    Ok(())
}

fn negative_state() -> GroupState {
    group_message_state("TV-GROUP-NEGATIVE-STATE", GroupMode::Lite).0
}

struct NegativeVector<'a> {
    vector_id: &'a str,
    result: &'a str,
    candidate_object: Vec<u8>,
    expected_error: Vec<u8>,
    state_before: Vec<u8>,
    state_after: Vec<u8>,
    expected_result: &'a str,
}

fn write_negative_vector(root: &Path, case: NegativeVector<'_>) {
    if case.expected_result != "Forked" {
        assert_eq!(
            case.state_before, case.state_after,
            "{} must preserve state",
            case.vector_id
        );
    }
    let state_hash_equal_unless_forked =
        case.state_before == case.state_after || case.expected_result == "Forked";
    let artifacts = vec![
        ("candidate_object".to_owned(), case.candidate_object),
        ("expected_error_class".to_owned(), case.expected_error),
        ("state_hash_before".to_owned(), case.state_before.clone()),
        ("state_hash_after".to_owned(), case.state_after.clone()),
        (
            "state_hash_equal_unless_forked".to_owned(),
            vec![u8::from(state_hash_equal_unless_forked)],
        ),
        (
            "expected_result".to_owned(),
            case.expected_result.as_bytes().to_vec(),
        ),
    ];
    write_owned(
        root,
        "group",
        case.vector_id,
        &metadata(
            case.result,
            "negative candidate rejects; state hash before equals state hash after unless the expected result is Forked",
            "rejected candidate material is not installed; temporary candidate bytes are retained only as vector artifacts",
            &[],
        ),
        &artifacts,
    );
}

fn write_roster_negative(
    root: &Path,
    vector_id: &str,
    mode: GroupMode,
    roster: Vec<RosterEntry>,
    result: &str,
) {
    let state = negative_state();
    let before = state_commitment(&state);
    let error = hydra_group::validate_roster_for_mode(mode, Epoch(1), &roster)
        .expect_err("roster negative must reject");
    let after = state_commitment(&state);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id,
            result,
            candidate_object: raw_roster_candidate(mode, &roster),
            expected_error: error_artifact(error),
            state_before: before,
            state_after: after,
            expected_result: "Rejected",
        },
    );
}

fn write_policy_negative(root: &Path, vector_id: &str, policy: GovernancePolicy, result: &str) {
    let state = negative_state();
    let before = state_commitment(&state);
    let error = hydra_group::validate_governance_policy(&policy)
        .expect_err("governance negative must reject");
    let after = state_commitment(&state);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id,
            result,
            candidate_object: raw_governance_candidate(&policy),
            expected_error: error_artifact(error),
            state_before: before,
            state_after: after,
            expected_result: "Rejected",
        },
    );
}

fn write_signature_negative(
    root: &Path,
    vector_id: &str,
    signatures: Vec<CommitSignature>,
    result: &str,
) {
    let state = negative_state();
    let before = state_commitment(&state);
    let error = hydra_group::validate_signature_set(&signatures)
        .expect_err("signature negative must reject");
    let after = state_commitment(&state);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id,
            result,
            candidate_object: raw_signature_set_candidate(&signatures),
            expected_error: error_artifact(error),
            state_before: before,
            state_after: after,
            expected_result: "Rejected",
        },
    );
}

fn lite_role_change_candidate(
    vector_id: &str,
    nonce_occurrence: u32,
    secret_occurrence: u32,
    signature_occurrence: u32,
) -> (GroupState, IdentityMaterial, hydra_group::PreparedCommit) {
    let alice0 = identity_material(vector_id, 0);
    let governance = GovernancePolicy::single_signer(alice0.member_id);
    let (state, alice, _bob, _parent_secret) = build_lite_parent_state(vector_id, governance);
    let plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(vector_id, nonce_occurrence),
        change: CommitChange::RoleChange {
            member_id: alice.member_id,
            new_role: GroupRole::Moderator,
        },
        signatures: Vec::new(),
        update_path: None,
        direct_epoch_secret: Some(direct_secret(vector_id, secret_occurrence)),
    };
    let prepared = sign_direct_plan(vector_id, &state, plan, &alice, signature_occurrence);
    (state, alice, prepared)
}

fn write_mutated_commit_negative<F>(
    root: &Path,
    vector_id: &str,
    result: &str,
    expected_error: hydra_group::GroupError,
    mutate: F,
) where
    F: FnOnce(&mut hydra_group::PreparedCommit),
{
    let (mut state, _alice, mut prepared) = lite_role_change_candidate(vector_id, 1, 1, 1);
    mutate(&mut prepared);
    let candidate_object =
        encode_commit_core(&prepared.core).unwrap_or_else(|_| prepared.encoded_core.clone());
    let before = state_commitment(&state);
    let error =
        apply_prepared_commit(&mut state, prepared).expect_err("mutated commit must reject");
    assert_eq!(error, expected_error);
    let after = state_commitment(&state);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id,
            result,
            candidate_object,
            expected_error: error_artifact(error),
            state_before: before,
            state_after: after,
            expected_result: "Rejected",
        },
    );
}

fn generate_roster_and_policy_rejection_vectors_m8_8(root: &Path) {
    let duplicate_member = numbered_member(1);
    write_roster_negative(
        root,
        "TV-GROUP-NEG-DUP-MEMBER-ID-000",
        GroupMode::Lite,
        vec![
            RosterEntry {
                member_id: duplicate_member,
                ..numbered_entry(1, GroupRole::Member, u32::MAX)
            },
            RosterEntry {
                member_id: duplicate_member,
                device_identity_fingerprint: numbered_fingerprint(2),
                ..numbered_entry(2, GroupRole::Member, u32::MAX)
            },
        ],
        "duplicate roster member ID rejects",
    );

    write_roster_negative(
        root,
        "TV-GROUP-NEG-DUP-ACTIVE-FINGERPRINT-000",
        GroupMode::Lite,
        vec![
            numbered_entry(1, GroupRole::Member, u32::MAX),
            RosterEntry {
                device_identity_fingerprint: numbered_fingerprint(1),
                ..numbered_entry(2, GroupRole::Member, u32::MAX)
            },
        ],
        "duplicate active identity fingerprint rejects",
    );

    write_roster_negative(
        root,
        "TV-GROUP-NEG-INVALID-ACTIVE-ROLE-000",
        GroupMode::Lite,
        vec![numbered_entry(1, GroupRole::Audience, u32::MAX)],
        "invalid active role for mode rejects",
    );

    let lite_over_max = (0..=hydra_core::MAX_LITE_MEMBERS)
        .map(|index| numbered_entry(index as u32 + 1, GroupRole::Member, u32::MAX))
        .collect::<Vec<_>>();
    write_roster_negative(
        root,
        "TV-GROUP-NEG-ROSTER-OVER-MAX-000",
        GroupMode::Lite,
        lite_over_max,
        "roster over Lite mode maximum rejects",
    );

    let broadcast_over_senders = (0..=hydra_core::MAX_BROADCAST_PRESENTERS)
        .map(|index| numbered_entry(index as u32 + 1, GroupRole::Moderator, index as u32))
        .collect::<Vec<_>>();
    write_roster_negative(
        root,
        "TV-GROUP-NEG-BROADCAST-SENDERS-OVER-16-000",
        GroupMode::Broadcast,
        broadcast_over_senders,
        "Broadcast presenter/moderator count over 16 rejects",
    );

    write_policy_negative(
        root,
        "TV-GROUP-NEG-GOV-THRESHOLD-ZERO-000",
        GovernancePolicy {
            policy_version: 1,
            threshold: 0,
            authorized_signers: vec![numbered_member(1)],
        },
        "governance threshold zero rejects",
    );
    write_policy_negative(
        root,
        "TV-GROUP-NEG-GOV-THRESHOLD-OVER-COUNT-000",
        GovernancePolicy {
            policy_version: 1,
            threshold: 2,
            authorized_signers: vec![numbered_member(1)],
        },
        "governance threshold over signer count rejects",
    );
}

fn generate_signature_rejection_vectors_m8_8(root: &Path) {
    write_signature_negative(
        root,
        "TV-GROUP-NEG-SIG-COUNT-ZERO-000",
        Vec::new(),
        "signature count zero rejects",
    );
    let eighteen = (1..=hydra_core::MAX_COMMIT_SIGNATURES + 1)
        .map(|index| CommitSignature {
            signer: numbered_member(index as u32),
            signature: [index as u8; ML_DSA_65_SIG_SIZE],
        })
        .collect::<Vec<_>>();
    write_signature_negative(
        root,
        "TV-GROUP-NEG-SIG-COUNT-18-000",
        eighteen,
        "signature count 18 rejects",
    );
    write_signature_negative(
        root,
        "TV-GROUP-NEG-SIG-DUPLICATE-000",
        vec![
            CommitSignature {
                signer: numbered_member(1),
                signature: [0x11; ML_DSA_65_SIG_SIZE],
            },
            CommitSignature {
                signer: numbered_member(1),
                signature: [0x12; ML_DSA_65_SIG_SIZE],
            },
        ],
        "duplicate signatures reject",
    );
    write_signature_negative(
        root,
        "TV-GROUP-NEG-SIG-OUT-OF-ORDER-000",
        vec![
            CommitSignature {
                signer: numbered_member(2),
                signature: [0x22; ML_DSA_65_SIG_SIZE],
            },
            CommitSignature {
                signer: numbered_member(1),
                signature: [0x11; ML_DSA_65_SIG_SIZE],
            },
        ],
        "out-of-order signatures reject",
    );
}

fn generate_commit_rejection_vectors_m8_8(root: &Path) {
    write_mutated_commit_negative(
        root,
        "TV-GROUP-NEG-WRONG-PARENT-COMMIT-HASH-000",
        "wrong parent commit hash rejects",
        hydra_group::GroupError::InvalidCommitParent,
        |prepared| prepared.core.parent_commit_hash[0] ^= 1,
    );
    write_mutated_commit_negative(
        root,
        "TV-GROUP-NEG-WRONG-OLD-EPOCH-STATE-000",
        "wrong old epoch/state version rejects",
        hydra_group::GroupError::InvalidCommitParent,
        |prepared| {
            prepared.core.old_epoch.0 += 1;
            prepared.core.old_state_version.0 += 1;
        },
    );
    write_mutated_commit_negative(
        root,
        "TV-GROUP-NEG-WRONG-NEW-EPOCH-STATE-000",
        "wrong new epoch/state version rejects",
        hydra_group::GroupError::InvalidCommitCore,
        |prepared| {
            prepared.core.new_epoch.0 += 1;
            prepared.core.new_state_version.0 += 1;
        },
    );
    write_mutated_commit_negative(
        root,
        "TV-GROUP-NEG-WRONG-ROSTER-HASH-000",
        "wrong roster hash rejects",
        hydra_group::GroupError::InvalidCommitParent,
        |prepared| prepared.core.old_roster_hash[0] ^= 1,
    );
    write_mutated_commit_negative(
        root,
        "TV-GROUP-NEG-WRONG-TREE-HASH-000",
        "wrong tree hash rejects",
        hydra_group::GroupError::InvalidCommitParent,
        |prepared| prepared.core.old_tree_hash[0] ^= 1,
    );
    write_mutated_commit_negative(
        root,
        "TV-GROUP-NEG-WRONG-UPDATE-PATH-HASH-000",
        "wrong update path hash/key-schedule binding rejects",
        hydra_group::GroupError::InvalidCommitCore,
        |prepared| prepared.core.key_schedule_commitment[0] ^= 1,
    );
}

fn generate_confirmation_and_welcome_rejection_vectors_m8_8(root: &Path) {
    const CONFIRM_ID: &str = "TV-GROUP-NEG-WRONG-CONFIRMATION-TAG-000";
    let (state, _alice, prepared) = lite_role_change_candidate(CONFIRM_ID, 1, 1, 1);
    let before = state_commitment(&state);
    let good_tag = hydra_group::commit_confirmation_tag(
        prepared.core.group_id,
        prepared.commit_hash,
        prepared.core.key_schedule_commitment,
    );
    let mut bad_tag = good_tag;
    bad_tag[0] ^= 1;
    let error = hydra_group::verify_commit_confirmation_tag(
        prepared.core.group_id,
        prepared.commit_hash,
        prepared.core.key_schedule_commitment,
        &bad_tag,
    )
    .expect_err("wrong confirmation tag rejects");
    let after = state_commitment(&state);
    let mut candidate = Vec::new();
    candidate.extend_from_slice(&prepared.encoded_core);
    candidate.extend_from_slice(&bad_tag);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id: CONFIRM_ID,
            result: "wrong confirmation tag rejects",
            candidate_object: candidate,
            expected_error: error_artifact(error),
            state_before: before,
            state_after: after,
            expected_result: "Rejected",
        },
    );

    const WELCOME_ID: &str = "TV-GROUP-NEG-WRONG-WELCOME-RECIPIENT-000";
    let alice = identity_material(WELCOME_ID, 0);
    let joining = identity_material(WELCOME_ID, 2);
    let governance = GovernancePolicy::single_signer(alice.member_id);
    let (state, _, _, _) = build_lite_parent_state(WELCOME_ID, governance);
    let parent_before = state_commitment(&state);
    let joining_entry = entry_for_identity(
        &joining,
        GroupRole::Member,
        u32::MAX,
        Epoch(state.epoch.0 + 1),
    );
    let direct_epoch_secret = direct_secret(WELCOME_ID, 1);
    let prepared = prepare_lite_join_with_real_signature(
        WELCOME_ID,
        &state,
        &alice,
        joining_entry.clone(),
        direct_epoch_secret,
    );
    let mut roster = state.roster.clone();
    roster.push(joining_entry);
    let change_payload = encode_change_payload(&ChangePayload::Join {
        new_entry: roster.last().expect("new entry"),
    })
    .expect("join payload encodes");
    let signature_set = encode_signature_set(&prepared.signatures).expect("signature set encodes");
    let wrong_recipient = member_id(WELCOME_ID, 9);
    let wrong_welcome = encode_join_welcome(&JoinWelcomeEncoding {
        mode: GroupMode::Lite,
        mechanism: MembershipMechanism::DirectWrap,
        recipient: wrong_recipient,
        encoded_core: &prepared.encoded_core,
        change_payload: &change_payload,
        signature_set: &signature_set,
        commit_hash: &prepared.commit_hash,
        roster: &roster,
        governance_policy: &state.governance_policy,
        mode_policy: state.mode_policy,
        update_path: None,
        direct_epoch_secret: Some(&direct_epoch_secret),
        tree_root_secret: None,
        public_tree_hash: &state.tree_hash,
    });
    let expected_error = verify_welcome_recipient(&wrong_welcome, joining.member_id)
        .expect_err("wrong recipient welcome rejects")
        .as_bytes()
        .to_vec();
    assert_eq!(state_commitment(&state), parent_before);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id: WELCOME_ID,
            result: "wrong welcome recipient rejects",
            candidate_object: wrong_welcome,
            expected_error,
            state_before: parent_before.clone(),
            state_after: parent_before,
            expected_result: "Rejected",
        },
    );
}

fn generate_fork_and_message_rejection_vectors_m8_8(root: &Path) {
    const FORK_ID: &str = "TV-GROUP-NEG-FORK-CONFLICT-000";
    let (mut state, alice, first) = lite_role_change_candidate(FORK_ID, 1, 1, 1);
    let sibling_plan = CommitPlan {
        committer: alice.member_id,
        commit_nonce: nonce(FORK_ID, 2),
        change: CommitChange::RoleChange {
            member_id: alice.member_id,
            new_role: GroupRole::Moderator,
        },
        signatures: Vec::new(),
        update_path: None,
        direct_epoch_secret: Some(direct_secret(FORK_ID, 2)),
    };
    let sibling = sign_direct_plan(FORK_ID, &state, sibling_plan, &alice, 2);
    hydra_group::install_prepared_commit(&mut state, first).expect("first sibling applies");
    let before = state_commitment(&state);
    let candidate = sibling.encoded_core.clone();
    let result =
        hydra_group::install_prepared_commit(&mut state, sibling).expect("sibling reports fork");
    assert_eq!(result, hydra_group::CommitInstallResult::Forked);
    let after = state_commitment(&state);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id: FORK_ID,
            result: "fork conflict marks group forked",
            candidate_object: candidate,
            expected_error: b"Forked".to_vec(),
            state_before: before,
            state_after: after,
            expected_result: "Forked",
        },
    );

    const ATTACH_ID: &str = "TV-GROUP-NEG-LITE-ATTACHMENT-000";
    let state = group_message_state(ATTACH_ID, GroupMode::Lite).0;
    let before = state_commitment(&state);
    let candidate = raw_attachment_fragment_candidate(ATTACH_ID, 1024);
    let error = validate_attachment_fragment_for_mode(GroupMode::Lite, &candidate)
        .expect_err("Lite attachment rejects");
    let after = state_commitment(&state);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id: ATTACH_ID,
            result: "Lite attachment fragment attempt rejects",
            candidate_object: candidate,
            expected_error: error_artifact(error),
            state_before: before,
            state_after: after,
            expected_result: "Rejected",
        },
    );

    const LITE_SIZE_ID: &str = "TV-GROUP-NEG-LITE-APP-608-000";
    let (mut lite_state, identities, _epoch_key) =
        group_message_state(LITE_SIZE_ID, GroupMode::Lite);
    let before = state_commitment(&lite_state);
    let candidate = tv_draw(LITE_SIZE_ID, "lite-application-content", 0, 608);
    let error = seal_deterministic_signed_group_data(
        LITE_SIZE_ID,
        &mut lite_state,
        &identities[0],
        0,
        &candidate,
    )
    .expect_err("Lite 608-byte application content rejects");
    let after = state_commitment(&lite_state);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id: LITE_SIZE_ID,
            result: "Lite application size 608 rejects",
            candidate_object: candidate,
            expected_error: error_artifact(error),
            state_before: before,
            state_after: after,
            expected_result: "Rejected",
        },
    );

    const FULL_SIZE_ID: &str = "TV-GROUP-NEG-FULL-APP-143968-000";
    let (mut full_state, identities, _epoch_key) =
        group_message_state(FULL_SIZE_ID, GroupMode::Broadcast);
    let before = state_commitment(&full_state);
    let candidate = tv_draw(FULL_SIZE_ID, "full-application-content", 0, 143_968);
    let error = seal_deterministic_signed_group_data(
        FULL_SIZE_ID,
        &mut full_state,
        &identities[1],
        0,
        &candidate,
    )
    .expect_err("Full application size 143968 rejects");
    let after = state_commitment(&full_state);
    write_negative_vector(
        root,
        NegativeVector {
            vector_id: FULL_SIZE_ID,
            result: "Full application size 143968 rejects",
            candidate_object: candidate,
            expected_error: error_artifact(error),
            state_before: before,
            state_after: after,
            expected_result: "Rejected",
        },
    );
}

fn generate_group_rejection_vectors_m8_8(root: &Path) {
    generate_roster_and_policy_rejection_vectors_m8_8(root);
    generate_signature_rejection_vectors_m8_8(root);
    generate_commit_rejection_vectors_m8_8(root);
    generate_confirmation_and_welcome_rejection_vectors_m8_8(root);
    generate_fork_and_message_rejection_vectors_m8_8(root);
}

fn generate_mode_change_vectors_m8_5(root: &Path) {
    generate_lite_to_interactive_mode_change_vector(root);
    generate_interactive_to_lite_mode_change_vector(root);
    generate_interactive_to_broadcast_mode_change_vector(root);
    generate_invalid_mode_change_vector(root);
}

pub fn generate(root: &Path) {
    generate_group_create(root);
    generate_group_join(root);
    generate_invalid_join(root);
    generate_join_vectors_m8_2(root);
    generate_remove_vectors_m8_3(root);
    generate_role_change_vectors_m8_4(root);
    generate_mode_change_vectors_m8_5(root);
    generate_self_update_vectors_m8_6(root);
    generate_group_message_vectors_m8_7(root);
    generate_group_rejection_vectors_m8_8(root);
}
