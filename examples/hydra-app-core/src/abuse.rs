use std::collections::BTreeSet;

use crate::{AppError, AppResult, ConversationId, StoredConversation};

/// App-layer guard for hostile commit delivery.
///
/// Protocol commits are still verified by `hydra-group`; this guard catches
/// replayed, reordered, forked, or rollback-shaped commit metadata before an
/// application mutates its durable conversation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitDeliveryGuard {
    conversation_id: ConversationId,
    current_epoch: u64,
    current_state_version: u64,
    last_commit_hash: [u8; 64],
    seen_commit_hashes: BTreeSet<[u8; 64]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitDeliveryAttempt {
    pub conversation_id: ConversationId,
    pub epoch: u64,
    pub state_version: u64,
    pub parent_commit_hash: [u8; 64],
    pub commit_hash: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitDeliveryStatus {
    Accepted,
    Duplicate,
}

impl CommitDeliveryGuard {
    #[must_use]
    pub fn from_conversation(
        conversation: &StoredConversation,
        last_commit_hash: [u8; 64],
    ) -> Self {
        Self {
            conversation_id: conversation.id,
            current_epoch: conversation.current_epoch,
            current_state_version: conversation.current_state_version,
            last_commit_hash,
            seen_commit_hashes: BTreeSet::new(),
        }
    }

    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    #[must_use]
    pub const fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    #[must_use]
    pub const fn current_state_version(&self) -> u64 {
        self.current_state_version
    }

    #[must_use]
    pub const fn last_commit_hash(&self) -> [u8; 64] {
        self.last_commit_hash
    }

    pub fn observe_commit(
        &mut self,
        attempt: CommitDeliveryAttempt,
    ) -> AppResult<CommitDeliveryStatus> {
        if attempt.conversation_id != self.conversation_id {
            return Err(AppError::InvalidInput(
                "commit targets a different conversation",
            ));
        }
        if attempt.commit_hash == [0; 64] {
            return Err(AppError::InvalidInput("commit hash must be nonzero"));
        }
        if self.seen_commit_hashes.contains(&attempt.commit_hash) {
            return Ok(CommitDeliveryStatus::Duplicate);
        }
        if attempt.parent_commit_hash != self.last_commit_hash {
            return Err(AppError::InvalidState(
                "commit parent hash does not match current state",
            ));
        }
        if attempt.epoch < self.current_epoch || attempt.state_version <= self.current_state_version
        {
            return Err(AppError::InvalidState(
                "commit would roll back conversation state",
            ));
        }
        let expected_state_version =
            self.current_state_version
                .checked_add(1)
                .ok_or(AppError::InvalidState(
                    "conversation state version exhausted",
                ))?;
        if attempt.state_version != expected_state_version {
            return Err(AppError::InvalidState("commit arrived out of order"));
        }
        if attempt.epoch > self.current_epoch.saturating_add(1) {
            return Err(AppError::InvalidState("commit epoch arrived too far ahead"));
        }
        self.current_epoch = attempt.epoch;
        self.current_state_version = attempt.state_version;
        self.last_commit_hash = attempt.commit_hash;
        self.seen_commit_hashes.insert(attempt.commit_hash);
        Ok(CommitDeliveryStatus::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use hydra_core::{FULL_ENVELOPE_SIZE, LITE_ENVELOPE_SIZE};
    use hydra_group::GroupRole;

    use crate::{
        AppErrorClass, AppGroup, AppIdentity, AppSession, AppSessionRole, AttachmentHandle,
        ConversationKind, DeviceLinkPolicy, DeviceLinkRequest, DeviceRegistry, IdentityStore,
        InMemoryTransport, MailboxId, MessageStore, SessionHandshakeExport, StoredConversation,
        TransportApi, TransportUploadRequest,
    };

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hydra-msg-a7-{name}-{nonce}.db"))
    }

    fn mailbox(byte: u8) -> MailboxId {
        MailboxId([byte; 32])
    }

    fn envelope(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    fn session_pair() -> (AppSession, AppSession) {
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let transcript = [0x41; 64];
        let secret = [0x42; 32];
        let alice_session = AppSession::start(
            AppSessionRole::Initiator,
            &alice,
            bob.public_identity(),
            SessionHandshakeExport::from_test_bytes(secret, transcript),
        )
        .unwrap();
        let bob_session = AppSession::start(
            AppSessionRole::Responder,
            &bob,
            alice.public_identity(),
            SessionHandshakeExport::from_test_bytes(secret, transcript),
        )
        .unwrap();
        (alice_session, bob_session)
    }

    fn conversation(id_byte: u8) -> StoredConversation {
        StoredConversation {
            id: ConversationId([id_byte; 32]),
            kind: ConversationKind::GroupInteractive,
            created_at_ms: 1_000,
            current_epoch: 1,
            current_state_version: 7,
            members: Vec::new(),
        }
    }

    fn commit_attempt(
        conversation_id: ConversationId,
        epoch: u64,
        state_version: u64,
        parent_byte: u8,
        commit_byte: u8,
    ) -> CommitDeliveryAttempt {
        CommitDeliveryAttempt {
            conversation_id,
            epoch,
            state_version,
            parent_commit_hash: [parent_byte; 64],
            commit_hash: [commit_byte; 64],
        }
    }

    #[test]
    fn replay_storm_is_rejected_without_second_acceptance() {
        let (mut alice, mut bob) = session_pair();
        let outbound = alice.send(b"storm me once").unwrap();
        let first = bob.receive(outbound.as_envelope()).unwrap();
        assert_eq!(first.content(), b"storm me once");

        for _ in 0..128 {
            assert_eq!(
                bob.receive(outbound.as_envelope()).unwrap_err().class(),
                AppErrorClass::Replay
            );
        }
    }

    #[test]
    fn commit_guard_rejects_reordered_forked_and_rollback_attempts() {
        let conversation = conversation(0x11);
        let mut guard = CommitDeliveryGuard::from_conversation(&conversation, [0x10; 64]);
        let out_of_order = commit_attempt(conversation.id, 2, 9, 0x10, 0x90);
        assert_eq!(
            guard.observe_commit(out_of_order).unwrap_err().class(),
            AppErrorClass::InvalidState
        );

        let accepted = commit_attempt(conversation.id, 2, 8, 0x10, 0x20);
        assert_eq!(
            guard.observe_commit(accepted).unwrap(),
            CommitDeliveryStatus::Accepted
        );
        assert_eq!(
            guard.observe_commit(accepted).unwrap(),
            CommitDeliveryStatus::Duplicate
        );

        let rollback = commit_attempt(conversation.id, 2, 8, 0x20, 0x21);
        assert_eq!(
            guard.observe_commit(rollback).unwrap_err().class(),
            AppErrorClass::InvalidState
        );
        let fork = commit_attempt(conversation.id, 3, 9, 0x10, 0x22);
        assert_eq!(
            guard.observe_commit(fork).unwrap_err().class(),
            AppErrorClass::InvalidState
        );
        let next = commit_attempt(conversation.id, 3, 9, 0x20, 0x23);
        assert_eq!(
            guard.observe_commit(next).unwrap(),
            CommitDeliveryStatus::Accepted
        );
    }

    #[test]
    fn wrong_recipient_welcome_rejects_before_group_install() {
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let mallory = AppIdentity::generate().unwrap();
        let mut alice_group = AppGroup::create_lite(&alice, GroupRole::Member).unwrap();
        let welcome = alice_group
            .add_lite_member(&alice, bob.public_identity(), GroupRole::Member)
            .unwrap();
        match AppGroup::install_lite_welcome(&mallory, welcome) {
            Ok(_) => panic!("wrong recipient installed Lite welcome"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::InvalidInput),
        }
    }

    #[test]
    fn corrupted_message_database_bytes_reject() {
        let path = temp_path("corrupt-message-store");
        let password = b"a7 message store password";
        let mut store = MessageStore::create(&path, password).unwrap();
        let conversation_id = store
            .create_conversation(ConversationKind::Direct, 1_000)
            .unwrap();
        store
            .append_message(crate::StoredMessage {
                conversation_id,
                direction: crate::MessageDirection::Inbound,
                sender_id: [0x55; 32],
                epoch: 1,
                state_version: 1,
                message_index: 1,
                received_at_ms: 1_001,
                content: b"encrypted db content only".to_vec(),
            })
            .unwrap();
        store.save(password).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 0x80;
        fs::write(&path, bytes).unwrap();
        match MessageStore::load(&path, password) {
            Ok(_) => panic!("corrupted message database loaded"),
            Err(error) => assert_eq!(error.class(), AppErrorClass::Authentication),
        }
        fs::remove_file(path).ok();
    }

    #[test]
    fn duplicate_device_id_link_attempt_rejects() {
        let primary_path = temp_path("primary-device");
        let secondary_path = temp_path("secondary-device");
        let primary = IdentityStore::create(&primary_path, b"primary password").unwrap();
        let secondary = IdentityStore::create(&secondary_path, b"secondary password").unwrap();
        let mut registry = DeviceRegistry::new(&primary, 1_000).unwrap();
        let request = DeviceLinkRequest::create(
            &secondary,
            registry.account_identity_fingerprint(),
            1_010,
            60_000,
        )
        .unwrap();
        let approval = registry
            .approve_link_request(&primary, &request, 1_020, DeviceLinkPolicy::default())
            .unwrap();
        registry
            .install_approved_device(&request, &approval, 1_030)
            .unwrap();
        assert_eq!(
            registry
                .install_approved_device(&request, &approval, 1_040)
                .unwrap_err()
                .class(),
            AppErrorClass::InvalidState
        );
        fs::remove_file(primary_path).ok();
        fs::remove_file(secondary_path).ok();
    }

    #[test]
    fn huge_message_and_plaintext_shaped_uploads_reject() {
        let mut relay = InMemoryTransport::new();
        let huge = TransportUploadRequest::new(
            mailbox(1),
            mailbox(2),
            1_000,
            None,
            envelope(0xee, FULL_ENVELOPE_SIZE + 1),
        );
        assert_eq!(
            relay.upload_envelope(huge).unwrap_err().class(),
            AppErrorClass::InvalidInput
        );

        let plaintext = TransportUploadRequest::new(
            mailbox(1),
            mailbox(2),
            1_000,
            None,
            b"server should never accept app plaintext here".to_vec(),
        );
        assert_eq!(
            relay.upload_envelope(plaintext).unwrap_err().class(),
            AppErrorClass::InvalidInput
        );
    }

    #[test]
    fn randomized_negative_transport_inputs_never_queue() {
        let mut seed = 0x1234_5678_9abc_def0_u64;
        let mut relay = InMemoryTransport::new();
        for case in 0..96_u8 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let len = usize::from((seed >> 24) as u16 % 2048);
            let mut bytes = vec![case; len];
            if matches!(bytes.len(), LITE_ENVELOPE_SIZE | FULL_ENVELOPE_SIZE) {
                bytes.push(0);
            }
            let request = TransportUploadRequest::new(
                mailbox(case.wrapping_add(1)),
                mailbox(case.wrapping_add(2)),
                10_000 + u64::from(case),
                Some(20_000 + u64::from(case)),
                bytes,
            );
            assert!(relay.upload_envelope(request).is_err());
        }
        assert!(relay
            .download_envelopes(mailbox(2), 30_000, 1)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn malformed_attachment_handles_reject_at_transport_boundary() {
        let mut relay = InMemoryTransport::new();
        let bad_handle = AttachmentHandle {
            object_id: [0x01; 32],
            encrypted_size: 0,
            content_hash: [0x02; 32],
            key_commitment: [0x03; 32],
        };
        let request = TransportUploadRequest::new(
            mailbox(7),
            mailbox(8),
            1_000,
            Some(2_000),
            envelope(0xaa, LITE_ENVELOPE_SIZE),
        )
        .with_attachments(vec![bad_handle]);
        assert_eq!(
            relay.upload_envelope(request).unwrap_err().class(),
            AppErrorClass::InvalidInput
        );
    }
}
