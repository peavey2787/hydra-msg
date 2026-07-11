#![forbid(unsafe_code)]
#![deny(dead_code, deprecated, unused)]

use hydra_app_core::{
    CarrierConfig, CarrierKind, ContactId, ConversationRef, HydraApp, HydraLobbyPolicy,
    HydraMessage, HydraMsgError, HydraSessionStatus, IdentityId, NotificationPreferences,
    RememberMePolicy,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hydra-app-core-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test directory");
        Self { path }
    }

    fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Pair {
    alice: HydraApp,
    bob: HydraApp,
    alice_contact: ContactId,
    bob_contact: ContactId,
    _root: TestDir,
}

fn active_app(path: impl AsRef<Path>, state_password: &str, identity_password: &str) -> HydraApp {
    let mut app = HydraApp::open(path, state_password).expect("open app");
    app.generate_identity("primary", identity_password)
        .expect("generate identity");
    app
}

fn connected_pair(label: &str) -> Pair {
    let root = TestDir::new(label);
    let mut alice = active_app(root.child("alice"), "alice-state", "alice-id");
    let mut bob = active_app(root.child("bob"), "bob-state", "bob-id");

    let alice_card = alice
        .create_labeled_contact_card("Alice")
        .expect("alice card");
    let bob_card = bob.create_labeled_contact_card("Bob").expect("bob card");
    let alice_contact = bob.add_contact(alice_card).expect("add alice");
    let bob_contact = alice.add_contact(bob_card).expect("add bob");
    bob.verify_contact(alice_contact.id(), alice_contact.safety_code())
        .expect("verify alice");
    alice
        .verify_contact(bob_contact.id(), bob_contact.safety_code())
        .expect("verify bob");

    let offer = alice
        .handshake_offer(bob_contact.id())
        .expect("handshake offer");
    let answer = bob.handshake_answer(offer).expect("handshake answer");
    alice.finish_handshake(answer).expect("finish handshake");

    Pair {
        alice,
        bob,
        alice_contact: alice_contact.id(),
        bob_contact: bob_contact.id(),
        _root: root,
    }
}

#[test]
fn first_run_identity_creation_uses_sdk_storage() {
    let root = TestDir::new("first-run");
    let mut app = HydraApp::open(root.child("profile"), "state-password").expect("open");
    assert!(app.list_identities().is_empty());

    let id = app
        .generate_identity("Personal", "identity-password")
        .expect("generate");
    assert_eq!(app.active_identity(), Some(id));
    assert_eq!(app.list_identities()[0].label(), "Personal");
    assert!(app.storage_status().encrypted_state);
}

#[test]
fn app_only_retains_valid_process_local_ux_state() {
    let mut pair = connected_pair("ux-state");
    let conversation = ConversationRef::Direct(pair.bob_contact);
    pair.alice
        .select_conversation(Some(conversation))
        .expect("select contact");
    pair.alice
        .set_draft(conversation, "not protocol state")
        .expect("set draft");
    pair.alice.set_carrier_config(CarrierConfig {
        kind: CarrierKind::Relay,
        endpoint: Some("https://relay.invalid".to_owned()),
    });
    pair.alice
        .set_notification_preferences(NotificationPreferences {
            direct_messages: false,
            lobby_messages: true,
        });

    assert_eq!(
        pair.alice.take_draft(conversation).as_deref(),
        Some("not protocol state")
    );
    assert_eq!(pair.alice.ui().selected_conversation, Some(conversation));
    assert_eq!(pair.alice.ui().carrier.kind, CarrierKind::Relay);
    assert!(!pair.alice.ui().notifications.direct_messages);
    assert!(pair.alice.ui().notifications.lobby_messages);
    assert!(pair
        .alice
        .select_conversation(Some(ConversationRef::Direct(ContactId::from_bytes(
            [0_u8; 32],
        ))))
        .is_err());
}

#[test]
fn invalid_identity_labels_do_not_leave_partial_sdk_records() {
    let root = TestDir::new("identity-label-rollback");
    let mut app = HydraApp::open(root.child("profile"), "state").expect("open");
    let oversized_label = "x".repeat(1024 * 1024);
    assert!(app
        .generate_identity(&oversized_label, "identity-password")
        .is_err());
    assert!(app.list_identities().is_empty());

    let existing = app
        .generate_identity("Existing", "identity-password")
        .expect("generate existing identity");
    let exported = app
        .export_identity(existing, "identity-password")
        .expect("export existing identity");
    assert!(app
        .import_identity(exported, "identity-password", oversized_label)
        .is_err());
    assert_eq!(app.list_identities().len(), 1);
    assert_eq!(app.list_identities()[0].id(), existing);
}

#[test]
fn prior_identity_import_and_multiple_identity_switching_work() {
    let root = TestDir::new("identity-import");
    let source = active_app(root.child("source"), "source-state", "source-id");
    let source_id = source.active_identity().expect("source active id");
    let exported = source
        .export_identity(source_id, "source-id")
        .expect("export identity");
    drop(source);

    let mut target = active_app(root.child("target"), "target-state", "target-id");
    let original = target.active_identity().expect("target active id");
    let imported = target
        .import_identity(exported, "imported-id", "Imported")
        .expect("import identity");
    assert_ne!(original, imported);
    assert_eq!(target.list_identities().len(), 2);

    target
        .switch_identity(imported, "imported-id")
        .expect("switch imported");
    assert_eq!(target.active_identity(), Some(imported));
    target
        .switch_identity(original, "target-id")
        .expect("switch original");
    assert_eq!(target.active_identity(), Some(original));
}

#[test]
fn unlock_and_remember_me_are_process_scoped_ux_state() {
    let root = TestDir::new("remember-me");
    let mut app = active_app(root.child("profile"), "state", "identity");
    let id = app.active_identity().expect("active id");
    app.set_remember_me(id, RememberMePolicy::Session)
        .expect("remember identity");
    assert_eq!(app.remember_me(id), RememberMePolicy::Session);

    app.lock_active_identity().expect("lock");
    assert!(app.active_identity().is_none());
    assert_eq!(app.remember_me(id), RememberMePolicy::Never);
    app.unlock_identity(id, "identity").expect("unlock");
    app.switch_identity(id, "identity").expect("activate");
    assert_eq!(app.active_identity(), Some(id));
}

#[test]
fn contact_card_preview_add_verify_export_import_flow_uses_sdk_format() {
    let root = TestDir::new("contacts");
    let alice = active_app(root.child("alice"), "alice-state", "alice-id");
    let mut bob = active_app(root.child("bob"), "bob-state", "bob-id");
    let card = alice
        .create_labeled_contact_card("Alice")
        .expect("contact card");

    let preview = bob.preview_contact_card(&card).expect("preview");
    assert_eq!(preview.label(), "Alice");
    let added = bob.add_contact(card).expect("add");
    bob.set_contact_alias(added.id(), "Work Alice")
        .expect("set contact alias");
    assert_eq!(bob.contact_alias(added.id()), Some("Work Alice"));
    bob.verify_contact(added.id(), added.safety_code())
        .expect("verify");
    assert!(bob.list_contacts()[0].verified());

    let exported = bob.export_contacts().expect("export contacts");
    drop(bob);
    let mut restored = active_app(root.child("restored"), "restored-state", "restored-id");
    restored.import_contacts(exported).expect("import contacts");
    assert_eq!(restored.list_contacts().len(), 1);
}

#[test]
fn handshake_roundtrip_establishes_public_sdk_sessions() {
    let pair = connected_pair("handshake");
    assert_eq!(
        pair.alice
            .session_status(pair.bob_contact)
            .expect("alice status"),
        HydraSessionStatus::Active
    );
    assert_eq!(
        pair.bob
            .session_status(pair.alice_contact)
            .expect("bob status"),
        HydraSessionStatus::Active
    );
}

#[test]
fn direct_packets_are_opaque_at_the_carrier_boundary() {
    let mut pair = connected_pair("direct-message");
    let packets = pair
        .alice
        .send_message(pair.bob_contact, HydraMessage::text("hello"))
        .expect("send");
    assert!(!packets.is_empty());

    let mut received = None;
    for packet in packets {
        received = pair
            .bob
            .receive_message(packet)
            .expect("receive")
            .or(received);
    }
    let received = received.expect("complete message");
    assert_eq!(received.text().expect("text"), "hello");
    assert_eq!(
        pair.alice
            .stored_messages(pair.bob_contact)
            .expect("alice history")
            .len(),
        1
    );
    assert_eq!(
        pair.bob
            .stored_messages(pair.alice_contact)
            .expect("bob history")
            .len(),
        1
    );
    assert_eq!(pair.alice.ui().display_history.len(), 1);
    assert_eq!(pair.bob.ui().display_history.len(), 1);

    let alice_path = pair._root.child("alice");
    drop(pair.alice);
    let reopened = HydraApp::open(alice_path, "alice-state").expect("reopen alice");
    assert_eq!(
        reopened
            .stored_messages(pair.bob_contact)
            .expect("persisted history")
            .len(),
        1
    );
    assert!(reopened.ui().display_history.is_empty());
}

#[test]
fn lobby_invite_join_send_receive_roundtrip_uses_public_sdk() {
    let mut pair = connected_pair("lobby");
    let lobby = pair
        .alice
        .create_lobby(HydraLobbyPolicy::new("Team", 8))
        .expect("create lobby");
    pair.alice
        .add_lobby_member(lobby.id(), pair.bob_contact)
        .expect("add bob");
    let invite = pair.alice.create_lobby_invite(lobby.id()).expect("invite");
    let joined = pair.bob.join_lobby(invite).expect("join");
    pair.bob
        .add_lobby_member(joined.id(), pair.alice_contact)
        .expect("add alice");

    let packets = pair
        .alice
        .send_lobby_message(lobby.id(), HydraMessage::text("hello lobby"))
        .expect("send lobby");
    let packet = packets
        .into_iter()
        .find(|packet| packet.recipient == pair.bob_contact)
        .expect("bob packet");
    let received = pair
        .bob
        .receive_lobby_message(packet.bytes)
        .expect("receive lobby")
        .expect("complete lobby message");
    assert_eq!(received.lobby_id(), Some(lobby.id()));
    assert_eq!(received.text().expect("text"), "hello lobby");
}

#[test]
fn backup_export_verify_import_and_state_password_rotation_work() {
    let root = TestDir::new("backup");
    let mut source = active_app(root.child("source"), "old-state", "identity");
    let backup = source
        .export_backup("backup-password")
        .expect("export backup");
    source
        .verify_backup(&backup, "backup-password")
        .expect("verify backup");
    source
        .change_state_password("old-state", "new-state")
        .expect("rotate state password");
    drop(source);

    assert!(HydraApp::open(root.child("source"), "old-state").is_err());
    let reopened = HydraApp::open(root.child("source"), "new-state").expect("new password");
    assert_eq!(reopened.list_identities().len(), 1);
    drop(reopened);

    let mut target = HydraApp::open(root.child("target"), "target-state").expect("target");
    target
        .import_backup(backup, "backup-password")
        .expect("import backup");
    assert_eq!(target.list_identities().len(), 1);
}

#[test]
fn locking_active_identity_clears_selection_and_send_fails_closed() {
    let mut pair = connected_pair("locked-misuse");
    let stored_before = pair
        .alice
        .stored_messages(pair.bob_contact)
        .expect("history before locked send")
        .len();

    pair.alice.lock_active_identity().expect("lock");
    assert_eq!(pair.alice.active_identity(), None);

    let error = pair
        .alice
        .send_message(pair.bob_contact, HydraMessage::text("must fail"))
        .expect_err("locked send must fail");
    assert_eq!(error, HydraMsgError::IdentityNotFound);
    assert_eq!(
        pair.alice
            .stored_messages(pair.bob_contact)
            .expect("history after locked send")
            .len(),
        stored_before
    );
}

#[test]
fn deleted_identity_contact_and_lobby_cannot_be_reused() {
    let mut pair = connected_pair("deleted-misuse");
    let lobby = pair
        .alice
        .create_lobby(HydraLobbyPolicy::new("Temporary", 4))
        .expect("create lobby");
    pair.alice.leave_lobby(lobby.id()).expect("delete lobby");
    assert_eq!(
        pair.alice
            .send_lobby_message(lobby.id(), HydraMessage::text("must fail"))
            .expect_err("deleted lobby must fail"),
        HydraMsgError::LobbyNotFound
    );

    pair.alice
        .remove_contact(pair.bob_contact)
        .expect("delete contact");
    assert_eq!(
        pair.alice
            .send_message(pair.bob_contact, HydraMessage::text("must fail"))
            .expect_err("deleted contact must fail"),
        HydraMsgError::ContactNotFound
    );

    let identity = pair.alice.active_identity().expect("active identity");
    pair.alice
        .delete_identity(identity, "alice-id")
        .expect("delete identity");
    assert_eq!(
        pair.alice
            .delete_identity(identity, "alice-id")
            .expect_err("deleted identity must fail"),
        HydraMsgError::IdentityNotFound
    );
}

#[test]
fn one_time_contact_card_creates_an_sdk_managed_identity() {
    let root = TestDir::new("one-time-card");
    let mut app = active_app(root.child("profile"), "state", "identity");
    let initial_count = app.list_identities().len();
    let one_time = app
        .create_one_time_contact_card("one-time-password")
        .expect("one-time card");
    assert_eq!(app.list_identities().len(), initial_count + 1);
    assert_eq!(app.active_identity(), Some(one_time.identity_id()));
    assert!(!one_time.card().is_empty());
}

#[test]
fn identity_password_rotation_and_imported_id_locking_work() {
    let root = TestDir::new("identity-password");
    let mut app = active_app(root.child("profile"), "state", "old-id-password");
    let id: IdentityId = app.active_identity().expect("active id");
    app.change_identity_password(id, "old-id-password", "new-id-password")
        .expect("rotate identity password");
    app.lock_active_identity().expect("lock");
    assert!(matches!(
        app.switch_identity(id, "old-id-password"),
        Err(HydraMsgError::InvalidPassword)
    ));
    app.switch_identity(id, "new-id-password")
        .expect("new identity password");
}
