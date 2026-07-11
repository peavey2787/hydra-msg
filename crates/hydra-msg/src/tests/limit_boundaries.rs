use super::*;
use crate::{
    codec::*,
    limits::*,
    messages::{MessageUsage, StoredMessage},
};
use hydra_core::{LITE_ENVELOPE_SIZE, ML_DSA_65_VK_SIZE};
use std::{collections::HashMap, fs};

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn dummy_contact(index: usize) -> HydraContact {
    let mut bytes = [0_u8; hydra_core::HASH_SIZE];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    HydraContact {
        id: ContactId::from_bytes(bytes),
        label: format!("dummy-{index}"),
        public_key: [0_u8; ML_DSA_65_VK_SIZE],
        verified: false,
        blocked: false,
    }
}

fn dummy_lobby(index: usize) -> HydraLobby {
    let mut bytes = [0_u8; hydra_core::HASH_SIZE];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    HydraLobby {
        id: LobbyId::from_bytes(bytes),
        policy: HydraLobbyPolicy::new(format!("dummy-{index}"), 2),
        members: Vec::new(),
    }
}

#[test]
fn primitive_size_guards_accept_exact_limit_and_reject_limit_plus_one_and_overflow() {
    assert!(reject_input_size(MAX_BACKUP_BYTES - 1, MAX_BACKUP_BYTES, "backup").is_ok());
    assert!(reject_input_size(MAX_BACKUP_BYTES, MAX_BACKUP_BYTES, "backup").is_ok());
    assert_eq!(
        reject_input_size(MAX_BACKUP_BYTES + 1, MAX_BACKUP_BYTES, "backup"),
        Err(HydraMsgError::InvalidInput("backup"))
    );
    assert!(reject_encoded_size(
        MAX_ENCRYPTED_STATE_BYTES,
        MAX_ENCRYPTED_STATE_BYTES,
        "state"
    )
    .is_ok());
    assert_eq!(
        reject_encoded_size(
            MAX_ENCRYPTED_STATE_BYTES + 1,
            MAX_ENCRYPTED_STATE_BYTES,
            "state"
        ),
        Err(HydraMsgError::InvalidEncoding("state"))
    );
    assert!(reject_collection_growth(MAX_CONTACTS - 1, 1, MAX_CONTACTS, "contacts").is_ok());
    assert_eq!(
        reject_collection_growth(MAX_CONTACTS, 1, MAX_CONTACTS, "contacts"),
        Err(HydraMsgError::InvalidInput("contacts"))
    );
    assert_eq!(
        reject_collection_growth(usize::MAX, 1, usize::MAX, "overflow"),
        Err(HydraMsgError::InvalidInput("overflow"))
    );
}

#[test]
fn hex_boundaries_reject_odd_wrong_and_oversized_ids() {
    let good = "00".repeat(hydra_core::HASH_SIZE);
    assert!(ContactId::from_hex(&good).is_ok());
    assert!(ContactId::from_hex(format!("{good}0")).is_err());
    assert!(ContactId::from_hex(&good[..good.len() - 1]).is_err());
    assert!(IdentityId::from_hex(&good).is_ok());
    assert!(IdentityId::from_hex(format!("{good}00")).is_err());
    assert!(LobbyId::from_hex(&good).is_ok());
    assert!(LobbyId::from_hex("zz").is_err());
}

#[test]
fn attachment_boundaries_cover_count_size_and_filename_edges() {
    let max_name = "a".repeat(MAX_ATTACHMENT_FILENAME_BYTES);
    assert!(HydraAttachment::from_named_bytes(&max_name, Vec::new()).is_ok());
    assert!(HydraAttachment::from_named_bytes(format!("{max_name}b"), Vec::new()).is_err());

    assert!(HydraAttachment::from_named_bytes("max.bin", vec![0; MAX_ATTACHMENT_BYTES]).is_ok());
    assert!(
        HydraAttachment::from_named_bytes("too-large.bin", vec![0; MAX_ATTACHMENT_BYTES + 1])
            .is_err()
    );

    let mut message = HydraMessage::text("attachments");
    for index in 0..MAX_ATTACHMENTS_PER_MESSAGE {
        message = message
            .attach_bytes(format!("{index}.bin"), Vec::new())
            .unwrap();
    }
    assert_eq!(message.attachments().len(), MAX_ATTACHMENTS_PER_MESSAGE);
    assert!(message.attach_bytes("overflow.bin", Vec::new()).is_err());
}

#[test]
fn contact_and_lobby_collection_boundaries_are_exact() {
    let mut donor = fresh("target/hydra-msg-test-limit-boundary-donor");
    let donor_id = donor.generate_id("pw").unwrap();
    donor.set_active_id(donor_id, "pw").unwrap();
    let card = donor.create_contact_card().unwrap();

    let mut contacts = fresh("target/hydra-msg-test-limit-boundary-contacts");
    for index in 0..(MAX_CONTACTS - 1) {
        let contact = dummy_contact(index);
        contacts.contacts.insert(contact.id(), contact);
    }
    assert!(contacts.add_contact(&card).is_ok());
    assert_eq!(contacts.contacts.len(), MAX_CONTACTS);

    let mut full_contacts = fresh("target/hydra-msg-test-limit-boundary-contacts-full");
    for index in 0..MAX_CONTACTS {
        let contact = dummy_contact(index);
        full_contacts.contacts.insert(contact.id(), contact);
    }
    assert!(full_contacts.add_contact(card).is_err());

    let mut lobbies = fresh("target/hydra-msg-test-limit-boundary-lobbies");
    for index in 0..(MAX_LOBBIES - 1) {
        let lobby = dummy_lobby(index);
        lobbies.lobbies.insert(lobby.id(), lobby);
    }
    assert!(lobbies
        .create_lobby(HydraLobbyPolicy::new("last", 2))
        .is_ok());
    assert_eq!(lobbies.lobbies.len(), MAX_LOBBIES);

    let mut full_lobbies = fresh("target/hydra-msg-test-limit-boundary-lobbies-full");
    for index in 0..MAX_LOBBIES {
        let lobby = dummy_lobby(index);
        full_lobbies.lobbies.insert(lobby.id(), lobby);
    }
    assert!(full_lobbies
        .create_lobby(HydraLobbyPolicy::new("overflow", 2))
        .is_err());
}

#[test]
fn message_collection_boundaries_are_exact_without_session_work() {
    let mut hydra = fresh("target/hydra-msg-test-limit-boundary-messages");
    let contact_id = ContactId::from_bytes([7; hydra_core::HASH_SIZE]);
    hydra.messages = (0..MAX_MESSAGES - 1)
        .map(|index| StoredMessage {
            id: MessageId::from_u64(index as u64),
            contact_id,
            inbound: true,
            plaintext: Vec::new(),
            attachments: Vec::new(),
        })
        .collect();
    assert!(hydra.ensure_message_capacity(contact_id, 0).is_ok());
    hydra.messages.push(StoredMessage {
        id: MessageId::from_u64((MAX_MESSAGES - 1) as u64),
        contact_id,
        inbound: true,
        plaintext: Vec::new(),
        attachments: Vec::new(),
    });
    assert!(hydra.ensure_message_capacity(contact_id, 0).is_err());

    let mut per_contact = fresh("target/hydra-msg-test-limit-boundary-per-contact-messages");
    per_contact.message_usage = HashMap::from([(
        contact_id,
        MessageUsage {
            count: MAX_MESSAGES_PER_CONTACT - 1,
            bytes: 0,
        },
    )]);
    assert!(per_contact.ensure_message_capacity(contact_id, 0).is_ok());
    per_contact.message_usage.insert(
        contact_id,
        MessageUsage {
            count: MAX_MESSAGES_PER_CONTACT,
            bytes: 0,
        },
    );
    assert!(per_contact.ensure_message_capacity(contact_id, 0).is_err());
}

#[test]
fn parser_entry_boundaries_are_checked_before_expensive_work() {
    assert!(decode_handshake_offer(&vec![0; MAX_HANDSHAKE_OFFER_BYTES]).is_err());
    assert!(decode_handshake_offer(&vec![0; MAX_HANDSHAKE_OFFER_BYTES + 1]).is_err());
    assert!(decode_handshake_answer(&vec![0; MAX_HANDSHAKE_ANSWER_BYTES]).is_err());
    assert!(decode_handshake_answer(&vec![0; MAX_HANDSHAKE_ANSWER_BYTES + 1]).is_err());
    assert!(decode_anonymous_auth_token(&vec![0; MAX_ANONYMOUS_AUTH_TOKEN_BYTES]).is_err());
    assert!(decode_anonymous_auth_token(&vec![0; MAX_ANONYMOUS_AUTH_TOKEN_BYTES + 1]).is_err());

    let mut hydra = fresh("target/hydra-msg-test-limit-boundary-packet-size");
    assert!(hydra.set_packet_size(LITE_ENVELOPE_SIZE).is_ok());
    assert!(hydra.set_packet_size(LITE_ENVELOPE_SIZE - 1).is_err());
}
