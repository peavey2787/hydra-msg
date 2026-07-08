use super::{
    ContactId, HydraAttachment, HydraAttachmentSource, HydraContact, HydraLobby, HydraLobbyPolicy,
    HydraMessage, HydraMsgError, HydraResult, IdentityId, IdentityRecord, LobbyId, MessageId,
    ReceivedHydraMessage, StoredMessage, ANSWER_MAGIC, BACKUP_MAGIC, CONTACT_CARD_MAGIC,
    ID_EXPORT_MAGIC, LOBBY_INVITE_MAGIC, LOBBY_PAYLOAD_MAGIC, OFFER_MAGIC, PAYLOAD_MAGIC,
};

use getrandom::SysRng;
use hydra_core::{HASH_SIZE, ML_DSA_65_VK_SIZE, TRANSCRIPT_HASH_SIZE};
use hydra_crypto::{CryptoBackend, MlDsaKeyPair, RustCryptoBackend, SecretBytes};
use hydra_group::GroupMode;
use rand_core::TryRng;

pub(super) fn identity_record_from_seed(
    label: String,
    seed: [u8; 32],
    password: &str,
    unlocked: bool,
) -> HydraResult<IdentityRecord> {
    let keypair = MlDsaKeyPair::from_seed(seed)?;
    let public_key = keypair.verification_key.to_bytes();
    let id = IdentityId(RustCryptoBackend::sha3_256(&public_key));
    let seed_nonce = random_array::<12>()?;
    let encrypted_seed = encrypt_seed(id, &seed, password, seed_nonce)?;
    Ok(IdentityRecord {
        id,
        label,
        seed: unlocked.then_some(seed),
        public_key,
        password_tag: password_tag(password),
        seed_nonce,
        encrypted_seed,
        unlocked,
    })
}

pub(super) fn seed_key(id: IdentityId, password: &str) -> SecretBytes<32> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade/identity-seed-key");
    input.extend_from_slice(&id.0);
    input.extend_from_slice(password.as_bytes());
    RustCryptoBackend::hkdf_extract(b"HYDRA-MSG/v1/facade/identity-seed", &input)
}

pub(super) fn encrypt_seed(
    id: IdentityId,
    seed: &[u8; 32],
    password: &str,
    nonce: [u8; 12],
) -> HydraResult<Vec<u8>> {
    let key = seed_key(id, password);
    RustCryptoBackend::aead_seal(&key, &nonce, b"HYDRA-MSG/v1/facade/encrypted-seed", seed)
        .map_err(Into::into)
}

pub(super) fn decrypt_seed(record: &IdentityRecord, password: &str) -> HydraResult<[u8; 32]> {
    verify_password(record, password)?;
    let key = seed_key(record.id, password);
    let plaintext = RustCryptoBackend::aead_open(
        &key,
        &record.seed_nonce,
        b"HYDRA-MSG/v1/facade/encrypted-seed",
        &record.encrypted_seed,
    )?;
    exact_array_from_vec((*plaintext).clone())
}

pub(super) fn verify_password(record: &IdentityRecord, password: &str) -> HydraResult<()> {
    if record.password_tag == password_tag(password) {
        Ok(())
    } else {
        Err(HydraMsgError::InvalidPassword)
    }
}

pub(super) fn password_tag(password: &str) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade/password-tag");
    input.extend_from_slice(password.as_bytes());
    RustCryptoBackend::sha3_256(&input)
}

pub(super) fn encode_identity_line(record: &IdentityRecord) -> String {
    [
        "identity".to_string(),
        record.id.hex(),
        hex_encode(record.label.as_bytes()),
        hex_encode(&record.public_key),
        hex_encode(&record.password_tag),
        hex_encode(&record.seed_nonce),
        hex_encode(&record.encrypted_seed),
    ]
    .join("	")
}

pub(super) fn decode_identity_line(line: &str) -> HydraResult<IdentityRecord> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() != 7 || parts[0] != "identity" {
        return Err(HydraMsgError::InvalidEncoding("identity state record"));
    }
    let id = IdentityId(exact_array_from_vec(hex_decode(parts[1])?)?);
    let label = String::from_utf8(hex_decode(parts[2])?)
        .map_err(|_| HydraMsgError::InvalidEncoding("identity label"))?;
    let public_key = exact_array_from_vec(hex_decode(parts[3])?)?;
    let expected_id = IdentityId(RustCryptoBackend::sha3_256(&public_key));
    if id != expected_id {
        return Err(HydraMsgError::InvalidEncoding(
            "identity fingerprint mismatch",
        ));
    }
    Ok(IdentityRecord {
        id,
        label,
        seed: None,
        public_key,
        password_tag: exact_array_from_vec(hex_decode(parts[4])?)?,
        seed_nonce: exact_array_from_vec(hex_decode(parts[5])?)?,
        encrypted_seed: hex_decode(parts[6])?,
        unlocked: false,
    })
}

pub(super) fn encode_contact_line(contact: &HydraContact) -> String {
    [
        "contact".to_string(),
        contact.id.hex(),
        hex_encode(contact.label.as_bytes()),
        hex_encode(&contact.public_key),
        if contact.verified { "1" } else { "0" }.to_string(),
        if contact.blocked { "1" } else { "0" }.to_string(),
    ]
    .join("	")
}

pub(super) fn decode_contact_line(line: &str) -> HydraResult<HydraContact> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() != 6 || parts[0] != "contact" {
        return Err(HydraMsgError::InvalidEncoding("contact state record"));
    }
    let id = ContactId(exact_array_from_vec(hex_decode(parts[1])?)?);
    let label = String::from_utf8(hex_decode(parts[2])?)
        .map_err(|_| HydraMsgError::InvalidEncoding("contact label"))?;
    let public_key = exact_array_from_vec(hex_decode(parts[3])?)?;
    let expected_id = ContactId(RustCryptoBackend::sha3_256(&public_key));
    if id != expected_id {
        return Err(HydraMsgError::InvalidEncoding(
            "contact fingerprint mismatch",
        ));
    }
    Ok(HydraContact {
        id,
        label,
        public_key,
        verified: parts[4] == "1",
        blocked: parts[5] == "1",
    })
}

pub(super) fn encode_message_line(message: &StoredMessage) -> String {
    let mut parts = vec![
        "message".to_string(),
        message.id.0.to_string(),
        message.contact_id.hex(),
        if message.inbound { "in" } else { "out" }.to_string(),
        hex_encode(&message.plaintext),
        message.attachments.len().to_string(),
    ];
    for attachment in &message.attachments {
        let source = match attachment.source {
            HydraAttachmentSource::File => "file",
            HydraAttachmentSource::Bytes => "bytes",
        };
        parts.push(source.to_string());
        parts.push(hex_encode(attachment.filename.as_bytes()));
        parts.push(hex_encode(&attachment.bytes));
    }
    parts.join("	")
}

pub(super) fn decode_message_line(line: &str) -> HydraResult<StoredMessage> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() < 6 || parts[0] != "message" {
        return Err(HydraMsgError::InvalidEncoding("message state record"));
    }
    let id = MessageId(
        parts[1]
            .parse()
            .map_err(|_| HydraMsgError::InvalidEncoding("message id"))?,
    );
    let contact_id = ContactId(exact_array_from_vec(hex_decode(parts[2])?)?);
    let inbound = match parts[3] {
        "in" => true,
        "out" => false,
        _ => return Err(HydraMsgError::InvalidEncoding("message direction")),
    };
    let plaintext = hex_decode(parts[4])?;
    let attachment_count: usize = parts[5]
        .parse()
        .map_err(|_| HydraMsgError::InvalidEncoding("attachment count"))?;
    if parts.len() != 6 + attachment_count * 3 {
        return Err(HydraMsgError::InvalidEncoding("attachment record length"));
    }
    let mut attachments = Vec::with_capacity(attachment_count);
    let mut offset = 6;
    for _ in 0..attachment_count {
        let source = match parts[offset] {
            "file" => HydraAttachmentSource::File,
            "bytes" => HydraAttachmentSource::Bytes,
            _ => return Err(HydraMsgError::InvalidEncoding("attachment source")),
        };
        let filename = String::from_utf8(hex_decode(parts[offset + 1])?)
            .map_err(|_| HydraMsgError::InvalidEncoding("attachment filename"))?;
        let bytes = hex_decode(parts[offset + 2])?;
        attachments.push(HydraAttachment {
            filename,
            bytes,
            source,
        });
        offset += 3;
    }
    Ok(StoredMessage {
        id,
        contact_id,
        inbound,
        plaintext,
        attachments,
    })
}

pub(super) fn validate_lobby_policy(policy: &HydraLobbyPolicy) -> HydraResult<()> {
    if policy.label.trim().is_empty() {
        return Err(HydraMsgError::InvalidInput("lobby label is empty"));
    }
    if policy.max_members == 0 {
        return Err(HydraMsgError::InvalidInput(
            "lobby max_members must be greater than zero",
        ));
    }
    if policy.max_members > GroupMode::Interactive.max_roster_entries() {
        return Err(HydraMsgError::InvalidInput(
            "lobby max_members exceeds HYDRA group limit",
        ));
    }
    Ok(())
}

pub(super) fn encode_lobby_line(lobby: &HydraLobby) -> String {
    let members = lobby
        .members
        .iter()
        .map(|member| member.hex())
        .collect::<Vec<_>>()
        .join(",");
    [
        "lobby".to_string(),
        hex_encode(&lobby.id.0),
        hex_encode(lobby.policy.label.as_bytes()),
        lobby.policy.max_members.to_string(),
        members,
    ]
    .join("	")
}

pub(super) fn decode_lobby_line(line: &str) -> HydraResult<HydraLobby> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "lobby" {
        return Err(HydraMsgError::InvalidEncoding("lobby state record"));
    }
    let id = LobbyId(exact_array_from_vec(hex_decode(parts[1])?)?);
    let label = String::from_utf8(hex_decode(parts[2])?)
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby label"))?;
    let max_members = parts[3]
        .parse()
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby max_members"))?;
    let members = if parts[4].is_empty() {
        Vec::new()
    } else {
        parts[4]
            .split(',')
            .map(|member| Ok(ContactId(exact_array_from_vec(hex_decode(member)?)?)))
            .collect::<HydraResult<Vec<_>>>()?
    };
    Ok(HydraLobby {
        id,
        policy: HydraLobbyPolicy::new(label, max_members),
        members,
    })
}

pub(super) fn encode_lobby_invite(lobby: &HydraLobby, members: &[ContactId]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(LOBBY_INVITE_MAGIC.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"id:");
    out.extend_from_slice(lobby.id.hex().as_bytes());
    out.extend_from_slice(b"\nlabel:");
    out.extend_from_slice(hex_encode(lobby.policy.label.as_bytes()).as_bytes());
    out.extend_from_slice(b"\nmax_members:");
    out.extend_from_slice(lobby.policy.max_members.to_string().as_bytes());
    out.extend_from_slice(b"\nmembers:");
    out.extend_from_slice(
        members
            .iter()
            .map(|member| member.hex())
            .collect::<Vec<_>>()
            .join(",")
            .as_bytes(),
    );
    out.push(b'\n');
    out
}

pub(super) fn decode_lobby_invite(bytes: &[u8]) -> HydraResult<HydraLobby> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite is not utf-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(LOBBY_INVITE_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("lobby invite magic"));
    }

    // Backward-compatible decode for the older three-line placeholder invite.
    if let Some(first) = lines.next() {
        if !first.contains(':') {
            let id = LobbyId(exact_array_from_vec(hex_decode(first)?)?);
            let label = lines.next().unwrap_or("HYDRA lobby").to_string();
            return Ok(HydraLobby {
                id,
                policy: HydraLobbyPolicy::new(label, 64),
                members: Vec::new(),
            });
        }

        let mut id = None;
        let mut label = None;
        let mut max_members = None;
        let mut members = Vec::new();
        for line in std::iter::once(first).chain(lines) {
            if let Some(value) = line.strip_prefix("id:") {
                id = Some(LobbyId(exact_array_from_vec(hex_decode(value)?)?));
            } else if let Some(value) = line.strip_prefix("label:") {
                label = Some(
                    String::from_utf8(hex_decode(value)?)
                        .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite label"))?,
                );
            } else if let Some(value) = line.strip_prefix("max_members:") {
                max_members = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite max_members"))?,
                );
            } else if let Some(value) = line.strip_prefix("members:") {
                if !value.trim().is_empty() {
                    members = value
                        .split(',')
                        .map(|member| Ok(ContactId(exact_array_from_vec(hex_decode(member)?)?)))
                        .collect::<HydraResult<Vec<_>>>()?;
                }
            }
        }
        let policy = HydraLobbyPolicy::new(
            label.unwrap_or_else(|| "HYDRA lobby".to_string()),
            max_members.unwrap_or(64),
        );
        return Ok(HydraLobby {
            id: id.ok_or(HydraMsgError::InvalidEncoding("lobby invite id"))?,
            policy,
            members,
        });
    }
    Err(HydraMsgError::InvalidEncoding("lobby invite id"))
}

pub(super) fn pack_lobby_payload(lobby_id: LobbyId, packed_message: &[u8]) -> HydraResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(LOBBY_PAYLOAD_MAGIC);
    out.extend_from_slice(&lobby_id.0);
    write_u64(&mut out, packed_message.len() as u64);
    out.extend_from_slice(packed_message);
    Ok(out)
}

pub(super) fn unpack_lobby_payload(bytes: &[u8]) -> HydraResult<(LobbyId, Vec<u8>)> {
    let mut reader = BytesReader::new(bytes);
    reader.expect(LOBBY_PAYLOAD_MAGIC)?;
    let lobby_id = LobbyId(exact_array_from_vec(reader.read(HASH_SIZE)?.to_vec())?);
    let message_len = reader.read_u64()? as usize;
    let packed_message = reader.read_vec(message_len)?;
    Ok((lobby_id, packed_message))
}

pub(super) fn backup_key(password: &str) -> SecretBytes<32> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade/backup-key");
    input.extend_from_slice(password.as_bytes());
    RustCryptoBackend::hkdf_extract(b"HYDRA-MSG/v1/facade/backup", &input)
}

pub(super) fn parse_backup_outer(bytes: &[u8]) -> HydraResult<([u8; 12], Vec<u8>)> {
    if !bytes.starts_with(BACKUP_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("backup magic"));
    }
    let text = std::str::from_utf8(&bytes[BACKUP_MAGIC.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("backup utf-8"))?;
    let mut lines = text.lines();
    let nonce = exact_array_from_vec(hex_decode(
        lines
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("backup nonce"))?,
    )?)?;
    let ciphertext = hex_decode(
        lines
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("backup ciphertext"))?,
    )?;
    Ok((nonce, ciphertext))
}

pub(super) fn decode_backup(bytes: &[u8], password: &str) -> HydraResult<Vec<u8>> {
    let (nonce, ciphertext) = parse_backup_outer(bytes)?;
    let key = backup_key(password);
    let plaintext = RustCryptoBackend::aead_open(&key, &nonce, BACKUP_MAGIC, &ciphertext)?;
    Ok((*plaintext).clone())
}

pub(super) fn encode_identity_export(seed: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ID_EXPORT_MAGIC);
    out.extend_from_slice(&hex_encode(seed).into_bytes());
    out.push(b'\n');
    out
}

pub(super) fn decode_identity_export(bytes: &[u8]) -> HydraResult<[u8; 32]> {
    if !bytes.starts_with(ID_EXPORT_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("identity export magic"));
    }
    let text = std::str::from_utf8(&bytes[ID_EXPORT_MAGIC.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("identity export utf-8"))?;
    exact_array_from_vec(hex_decode(text.trim())?)
}

pub(super) fn encode_contact_card(label: &str, public_key: &[u8; ML_DSA_65_VK_SIZE]) -> Vec<u8> {
    let id = RustCryptoBackend::sha3_256(public_key);
    format!(
        "{CONTACT_CARD_MAGIC}\nlabel:{}\nid:{}\npublic_key:{}\nsafety:{}\n",
        escape_line(label),
        hex_encode(&id),
        hex_encode(public_key),
        safety_code_for_contact(ContactId(id))
    )
    .into_bytes()
}

pub(super) fn decode_contact_card(bytes: &[u8]) -> HydraResult<HydraContact> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("contact card utf-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(CONTACT_CARD_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("contact card magic"));
    }
    let mut label = None;
    let mut id = None;
    let mut public_key = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("label:") {
            label = Some(unescape_line(value));
        } else if let Some(value) = line.strip_prefix("id:") {
            id = Some(ContactId(exact_array_from_vec(hex_decode(value)?)?));
        } else if let Some(value) = line.strip_prefix("public_key:") {
            public_key = Some(exact_array_from_vec(hex_decode(value)?)?);
        }
    }
    let public_key = public_key.ok_or(HydraMsgError::InvalidEncoding("contact public key"))?;
    let expected_id = ContactId(RustCryptoBackend::sha3_256(&public_key));
    let id = id.unwrap_or(expected_id);
    if id != expected_id {
        return Err(HydraMsgError::InvalidEncoding(
            "contact fingerprint mismatch",
        ));
    }
    Ok(HydraContact {
        id,
        label: label.unwrap_or_else(|| format!("contact-{}", id.hex())),
        public_key,
        verified: false,
        blocked: false,
    })
}

pub(super) fn safety_code_for_contact(contact_id: ContactId) -> String {
    let hex = contact_id.hex();
    hex.as_bytes()
        .chunks(4)
        .take(6)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

#[derive(Clone, Copy)]
pub(super) struct ParsedHandshake {
    pub(super) peer_id: IdentityId,
    pub(super) public_key: [u8; ML_DSA_65_VK_SIZE],
    pub(super) nonce: [u8; 32],
}

pub(super) fn encode_handshake_offer(
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
) -> Vec<u8> {
    encode_handshake(OFFER_MAGIC, id, public_key, nonce)
}

pub(super) fn encode_handshake_answer(
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
) -> Vec<u8> {
    encode_handshake(ANSWER_MAGIC, id, public_key, nonce)
}

pub(super) fn encode_handshake(
    magic: &[u8],
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(magic);
    out.extend_from_slice(b"id:");
    out.extend_from_slice(id.hex().as_bytes());
    out.extend_from_slice(b"\npublic_key:");
    out.extend_from_slice(hex_encode(public_key).as_bytes());
    out.extend_from_slice(b"\nnonce:");
    out.extend_from_slice(hex_encode(&nonce).as_bytes());
    out.push(b'\n');
    out
}

pub(super) fn decode_handshake_offer(bytes: &[u8]) -> HydraResult<ParsedHandshake> {
    decode_handshake(bytes, OFFER_MAGIC)
}

pub(super) fn decode_handshake_answer(bytes: &[u8]) -> HydraResult<ParsedHandshake> {
    decode_handshake(bytes, ANSWER_MAGIC)
}

pub(super) fn decode_handshake(bytes: &[u8], magic: &[u8]) -> HydraResult<ParsedHandshake> {
    if !bytes.starts_with(magic) {
        return Err(HydraMsgError::InvalidEncoding("handshake magic"));
    }
    let text = std::str::from_utf8(&bytes[magic.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("handshake utf-8"))?;
    let mut id = None;
    let mut public_key = None;
    let mut nonce = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("id:") {
            id = Some(IdentityId(exact_array_from_vec(hex_decode(value)?)?));
        } else if let Some(value) = line.strip_prefix("public_key:") {
            public_key = Some(exact_array_from_vec(hex_decode(value)?)?);
        } else if let Some(value) = line.strip_prefix("nonce:") {
            nonce = Some(exact_array_from_vec(hex_decode(value)?)?);
        }
    }
    let public_key = public_key.ok_or(HydraMsgError::InvalidEncoding("handshake public key"))?;
    let expected_id = IdentityId(RustCryptoBackend::sha3_256(&public_key));
    let id = id.ok_or(HydraMsgError::InvalidEncoding("handshake id"))?;
    if id != expected_id {
        return Err(HydraMsgError::InvalidEncoding(
            "handshake identity mismatch",
        ));
    }
    Ok(ParsedHandshake {
        peer_id: id,
        public_key,
        nonce: nonce.ok_or(HydraMsgError::InvalidEncoding("handshake nonce"))?,
    })
}

pub(super) fn derive_facade_handshake_material(
    nonce: [u8; 32],
    left: IdentityId,
    right: IdentityId,
) -> (SecretBytes<32>, [u8; TRANSCRIPT_HASH_SIZE]) {
    let (a, b) = if left <= right {
        (left.0, right.0)
    } else {
        (right.0, left.0)
    };
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"HYDRA-MSG/v1/facade-handshake");
    transcript.extend_from_slice(&nonce);
    transcript.extend_from_slice(&a);
    transcript.extend_from_slice(&b);
    let transcript_hash = RustCryptoBackend::sha3_512(&transcript);
    let secret =
        RustCryptoBackend::hkdf_extract(b"HYDRA-MSG/v1/facade-handshake-secret", &transcript_hash);
    (secret, transcript_hash)
}

pub(super) fn pack_message(message: &HydraMessage) -> HydraResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(PAYLOAD_MAGIC);
    write_u64(&mut out, message.plaintext.len() as u64);
    out.extend_from_slice(&message.plaintext);
    write_u32(&mut out, message.attachments.len() as u32);
    for attachment in &message.attachments {
        out.push(match attachment.source {
            HydraAttachmentSource::File => 1,
            HydraAttachmentSource::Bytes => 2,
        });
        let name = attachment.filename.as_bytes();
        write_u32(&mut out, name.len() as u32);
        out.extend_from_slice(name);
        write_u64(&mut out, attachment.bytes.len() as u64);
        out.extend_from_slice(&attachment.bytes);
    }
    Ok(out)
}

pub(super) fn unpack_message(
    bytes: &[u8],
    from: ContactId,
    message_id: MessageId,
    lobby_id: Option<LobbyId>,
) -> HydraResult<ReceivedHydraMessage> {
    let mut reader = BytesReader::new(bytes);
    reader.expect(PAYLOAD_MAGIC)?;
    let plaintext_len = reader.read_u64()? as usize;
    let plaintext = reader.read_vec(plaintext_len)?;
    let attachment_count = reader.read_u32()? as usize;
    let mut attachments = Vec::with_capacity(attachment_count);
    for _ in 0..attachment_count {
        let source = match reader.read_u8()? {
            1 => HydraAttachmentSource::File,
            2 => HydraAttachmentSource::Bytes,
            _ => return Err(HydraMsgError::InvalidEncoding("attachment source")),
        };
        let name_len = reader.read_u32()? as usize;
        let filename = String::from_utf8(reader.read_vec(name_len)?)
            .map_err(|_| HydraMsgError::InvalidEncoding("attachment filename"))?;
        let bytes_len = reader.read_u64()? as usize;
        let content = reader.read_vec(bytes_len)?;
        attachments.push(HydraAttachment {
            filename,
            bytes: content,
            source,
        });
    }
    Ok(ReceivedHydraMessage {
        from,
        message_id,
        lobby_id,
        plaintext,
        attachments,
    })
}

struct BytesReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BytesReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> HydraResult<()> {
        let got = self.read(expected.len())?;
        if got == expected {
            Ok(())
        } else {
            Err(HydraMsgError::InvalidEncoding("payload magic"))
        }
    }

    fn read(&mut self, len: usize) -> HydraResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(HydraMsgError::InvalidEncoding("length overflow"))?;
        if end > self.bytes.len() {
            return Err(HydraMsgError::InvalidEncoding("truncated payload"));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn read_vec(&mut self, len: usize) -> HydraResult<Vec<u8>> {
        Ok(self.read(len)?.to_vec())
    }

    fn read_u8(&mut self) -> HydraResult<u8> {
        Ok(*self
            .read(1)?
            .first()
            .ok_or(HydraMsgError::InvalidEncoding("u8"))?)
    }

    fn read_u32(&mut self) -> HydraResult<u32> {
        Ok(u32::from_be_bytes(exact_array_from_vec(
            self.read(4)?.to_vec(),
        )?))
    }

    fn read_u64(&mut self) -> HydraResult<u64> {
        Ok(u64::from_be_bytes(exact_array_from_vec(
            self.read(8)?.to_vec(),
        )?))
    }
}

pub(super) fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn random_array<const N: usize>() -> HydraResult<[u8; N]> {
    let mut out = [0_u8; N];
    SysRng
        .try_fill_bytes(&mut out)
        .map_err(|_| HydraMsgError::EntropyUnavailable)?;
    Ok(out)
}

pub(super) fn exact_array_from_vec<const N: usize>(bytes: Vec<u8>) -> HydraResult<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| HydraMsgError::InvalidEncoding("array length"))
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn hex_decode(input: &str) -> HydraResult<Vec<u8>> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
        return Err(HydraMsgError::InvalidEncoding("hex length"));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_nibble(bytes[index])?;
        let low = hex_nibble(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Ok(out)
}

pub(super) fn hex_nibble(byte: u8) -> HydraResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HydraMsgError::InvalidEncoding("hex character")),
    }
}

pub(super) fn escape_line(input: &str) -> String {
    input
        .replace('%', "%25")
        .replace('\n', "%0a")
        .replace('\r', "%0d")
}

pub(super) fn unescape_line(input: &str) -> String {
    input
        .replace("%0d", "\r")
        .replace("%0a", "\n")
        .replace("%25", "%")
}
