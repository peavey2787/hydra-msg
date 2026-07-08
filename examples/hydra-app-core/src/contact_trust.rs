use std::path::{Path, PathBuf};

use hydra_core::{types::IdentityPublicKey, ML_DSA_65_VK_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};
use zeroize::Zeroize;

use crate::{
    random::random_array,
    secret_handling::{
        crash_safe_atomic_write, derive_storage_key, read_crash_safe, StorageKdfPolicy,
    },
    AppError, AppIdentity, AppResult, PublicIdentity,
};

const STORE_MAGIC: &[u8; 8] = b"HYDRACT1";
const STORE_VERSION: u8 = 1;
const STORE_SALT_SIZE: usize = 32;
const STORE_NONCE_SIZE: usize = 12;
const STORE_HEADER_SIZE: usize = 8 + 1 + 1 + 4 + STORE_SALT_SIZE + STORE_NONCE_SIZE;
const PLAINTEXT_MAGIC: &[u8; 16] = b"HYDRACT-PLAIN-1\n";
const CONTACT_KDF_LABEL: &[u8] = b"HYDRA-MSG/v1/app/contact-store";
const SAFETY_LABEL: &[u8] = b"HYDRA-MSG/v1/app/contact/safety-number";
const MAILBOX_LABEL: &[u8] = b"HYDRA-MSG/v1/app/contact/mailbox-binding";
const QR_PREFIX: &str = "hydra-msg-contact-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedContact {
    pub alias: String,
    pub fingerprint_hex: String,
    pub public_key_hex: String,
    pub mailbox_hint: String,
    pub mailbox_binding_hex: String,
    pub safety_number: String,
    pub qr_payload: String,
    pub added_at_ms: u64,
    pub updated_at_ms: u64,
    pub key_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicContactCard {
    pub label: String,
    pub fingerprint_hex: String,
    pub public_key_hex: String,
    pub mailbox_hint: String,
    pub mailbox_binding_hex: String,
    pub safety_number: String,
    pub qr_payload: String,
    pub join_code: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactKeyChangeWarning {
    pub alias: String,
    pub old_fingerprint_hex: String,
    pub new_fingerprint_hex: String,
    pub old_safety_number: String,
    pub new_safety_number: String,
    pub message: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactAddOutcome {
    Added(TrustedContact),
    AlreadyTrusted(TrustedContact),
    KeyChangeWarning(ContactKeyChangeWarning),
}

#[derive(Clone, Debug)]
pub struct ContactTrustStore {
    path: PathBuf,
    contacts: Vec<TrustedContact>,
}

impl ContactTrustStore {
    pub fn create_or_load(path: impl AsRef<Path>, storage_secret: &[u8]) -> AppResult<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            Self::load(path, storage_secret)
        } else {
            Ok(Self {
                path,
                contacts: Vec::new(),
            })
        }
    }

    pub fn load(path: impl AsRef<Path>, storage_secret: &[u8]) -> AppResult<Self> {
        let path = path.as_ref().to_path_buf();
        let file = read_crash_safe(&path, "contact trust store cannot be read")?;
        if file.len() <= STORE_HEADER_SIZE {
            return Err(AppError::InvalidInput("contact trust store is truncated"));
        }
        let (header, ciphertext) = file.split_at(STORE_HEADER_SIZE);
        let (kdf_policy, salt, nonce) = decode_header(header)?;
        let key = derive_contact_key(storage_secret, salt, kdf_policy)?;
        let plaintext = RustCryptoBackend::aead_open(&key, nonce, header, ciphertext)?;
        let contacts = decode_contacts(&plaintext)?;
        Ok(Self { path, contacts })
    }

    pub fn save(&self, storage_secret: &[u8]) -> AppResult<()> {
        let mut salt = random_array::<STORE_SALT_SIZE>()?;
        let nonce = random_array::<STORE_NONCE_SIZE>()?;
        let kdf_policy = StorageKdfPolicy::scrypt_interactive();
        let key = derive_contact_key(storage_secret, &salt, kdf_policy)?;
        let plaintext = encode_contacts(&self.contacts);
        let header = encode_header(kdf_policy, &salt, &nonce);
        let ciphertext = RustCryptoBackend::aead_seal(&key, &nonce, &header, plaintext.as_bytes())?;
        salt.zeroize();
        let mut file = Vec::with_capacity(header.len() + ciphertext.len());
        file.extend_from_slice(&header);
        file.extend_from_slice(&ciphertext);
        crash_safe_atomic_write(&self.path, &file, "contact trust store cannot be committed")
    }

    #[must_use]
    pub fn contacts(&self) -> &[TrustedContact] {
        &self.contacts
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    pub fn add_generated(&mut self, alias: &str) -> AppResult<ContactAddOutcome> {
        let identity = AppIdentity::generate()?;
        self.add_public_identity(alias, &identity.public_identity(), current_time_ms())
    }

    pub fn add_public_key_hex(
        &mut self,
        alias: &str,
        public_key_hex: &str,
    ) -> AppResult<ContactAddOutcome> {
        let public_identity = public_identity_from_hex(public_key_hex)?;
        self.add_public_identity(alias, &public_identity, current_time_ms())
    }

    pub fn accept_key_change_public_key_hex(
        &mut self,
        alias: &str,
        public_key_hex: &str,
    ) -> AppResult<ContactAddOutcome> {
        let public_identity = public_identity_from_hex(public_key_hex)?;
        let now = current_time_ms();
        let new_record = build_contact(alias, &public_identity, now, now, 0)?;
        match self
            .contacts
            .iter_mut()
            .find(|contact| contact.alias == alias)
        {
            Some(existing) => {
                if existing.public_key_hex == new_record.public_key_hex {
                    return Ok(ContactAddOutcome::AlreadyTrusted(existing.clone()));
                }
                new_record.validate()?;
                let next_version = existing
                    .key_version
                    .checked_add(1)
                    .ok_or(AppError::InvalidState("contact key version exhausted"))?;
                *existing = TrustedContact {
                    key_version: next_version,
                    added_at_ms: existing.added_at_ms,
                    ..new_record
                };
                Ok(ContactAddOutcome::Added(existing.clone()))
            }
            None => self.add_public_identity(alias, &public_identity, now),
        }
    }

    pub fn add_qr_payload(&mut self, alias: &str, payload: &str) -> AppResult<ContactAddOutcome> {
        let parsed = ParsedQrContact::parse(payload)?;
        let public_identity = public_identity_from_hex(&parsed.public_key_hex)?;
        let expected = build_contact(alias, &public_identity, 0, 0, 0)?;
        if parsed.fingerprint_hex != expected.fingerprint_hex
            || parsed.mailbox_hint != expected.mailbox_hint
            || parsed.safety_number != expected.safety_number
        {
            return Err(AppError::InvalidInput(
                "contact QR payload failed safety checks",
            ));
        }
        self.add_public_identity(alias, &public_identity, current_time_ms())
    }

    pub fn accept_key_change_qr_payload(
        &mut self,
        alias: &str,
        payload: &str,
    ) -> AppResult<ContactAddOutcome> {
        let parsed = ParsedQrContact::parse(payload)?;
        let public_identity = public_identity_from_hex(&parsed.public_key_hex)?;
        let expected = build_contact(alias, &public_identity, 0, 0, 0)?;
        if parsed.fingerprint_hex != expected.fingerprint_hex
            || parsed.mailbox_hint != expected.mailbox_hint
            || parsed.safety_number != expected.safety_number
        {
            return Err(AppError::InvalidInput(
                "contact QR payload failed safety checks",
            ));
        }
        self.accept_key_change_public_key_hex(alias, &parsed.public_key_hex)
    }

    pub fn verify_qr_payload(&self, alias: &str, payload: &str) -> AppResult<bool> {
        let parsed = ParsedQrContact::parse(payload)?;
        let Some(contact) = self.contacts.iter().find(|contact| contact.alias == alias) else {
            return Ok(false);
        };
        Ok(parsed.public_key_hex == contact.public_key_hex
            && parsed.fingerprint_hex == contact.fingerprint_hex
            && parsed.mailbox_hint == contact.mailbox_hint
            && parsed.safety_number == contact.safety_number)
    }

    fn add_public_identity(
        &mut self,
        alias: &str,
        public_identity: &PublicIdentity,
        now: u64,
    ) -> AppResult<ContactAddOutcome> {
        validate_alias(alias)?;
        let record = build_contact(alias, public_identity, now, now, 0)?;
        record.validate()?;
        if let Some(existing) = self.contacts.iter().find(|contact| contact.alias == alias) {
            if existing.public_key_hex == record.public_key_hex
                && existing.mailbox_hint == record.mailbox_hint
                && existing.safety_number == record.safety_number
            {
                return Ok(ContactAddOutcome::AlreadyTrusted(existing.clone()));
            }
            return Ok(ContactAddOutcome::KeyChangeWarning(
                ContactKeyChangeWarning {
                    alias: alias.to_owned(),
                    old_fingerprint_hex: existing.fingerprint_hex.clone(),
                    new_fingerprint_hex: record.fingerprint_hex,
                    old_safety_number: existing.safety_number.clone(),
                    new_safety_number: record.safety_number,
                    message:
                        "contact key changed; verify safety number or QR before trusting the update",
                },
            ));
        }
        if self
            .contacts
            .iter()
            .any(|contact| contact.public_key_hex == record.public_key_hex)
        {
            return Err(AppError::InvalidInput(
                "contact public key is already trusted under another alias",
            ));
        }
        self.contacts.push(record.clone());
        self.contacts.sort_by_key(|contact| contact.alias.clone());
        Ok(ContactAddOutcome::Added(record))
    }
}

impl PublicContactCard {
    pub fn create(label: &str, public_key_hex: &str) -> AppResult<Self> {
        let public_identity = public_identity_from_hex(public_key_hex)?;
        let contact = build_contact(label, &public_identity, 0, 0, 0)?;
        Ok(Self {
            label: label.to_owned(),
            fingerprint_hex: contact.fingerprint_hex,
            public_key_hex: contact.public_key_hex,
            mailbox_hint: contact.mailbox_hint,
            mailbox_binding_hex: contact.mailbox_binding_hex,
            safety_number: contact.safety_number,
            join_code: contact.qr_payload.clone(),
            qr_payload: contact.qr_payload,
        })
    }
}

impl TrustedContact {
    pub fn validate(&self) -> AppResult<()> {
        validate_alias(&self.alias)?;
        let public_identity = public_identity_from_hex(&self.public_key_hex)?;
        let expected = build_contact(
            &self.alias,
            &public_identity,
            self.added_at_ms,
            self.updated_at_ms,
            self.key_version,
        )?;
        if self.fingerprint_hex != expected.fingerprint_hex {
            return Err(AppError::InvalidInput(
                "contact fingerprint does not match public key",
            ));
        }
        if self.mailbox_hint != expected.mailbox_hint {
            return Err(AppError::InvalidInput(
                "contact mailbox is not bound to the public key",
            ));
        }
        if self.mailbox_binding_hex != expected.mailbox_binding_hex {
            return Err(AppError::InvalidInput("contact mailbox binding is invalid"));
        }
        if self.safety_number != expected.safety_number {
            return Err(AppError::InvalidInput("contact safety number is invalid"));
        }
        if self.qr_payload != expected.qr_payload {
            return Err(AppError::InvalidInput("contact QR payload is invalid"));
        }
        Ok(())
    }
}

fn build_contact(
    alias: &str,
    public_identity: &PublicIdentity,
    added_at_ms: u64,
    updated_at_ms: u64,
    key_version: u64,
) -> AppResult<TrustedContact> {
    validate_alias(alias)?;
    let public_key_hex = hex_encode(&public_identity.public_key().0);
    let fingerprint_hex = hex_encode(&public_identity.fingerprint().0);
    let mailbox_hint = derive_mailbox_hint(&fingerprint_hex);
    let mailbox_binding_hex = mailbox_binding_hex(&public_key_hex, &fingerprint_hex, &mailbox_hint);
    let safety_number = safety_number(&public_key_hex, &fingerprint_hex, &mailbox_hint);
    let qr_payload = qr_payload(
        &public_key_hex,
        &fingerprint_hex,
        &mailbox_hint,
        &safety_number,
    );
    Ok(TrustedContact {
        alias: alias.to_owned(),
        fingerprint_hex,
        public_key_hex,
        mailbox_hint,
        mailbox_binding_hex,
        safety_number,
        qr_payload,
        added_at_ms,
        updated_at_ms,
        key_version,
    })
}

fn derive_contact_key(
    storage_secret: &[u8],
    salt: &[u8; 32],
    policy: StorageKdfPolicy,
) -> AppResult<hydra_crypto::SecretBytes<32>> {
    derive_storage_key(
        CONTACT_KDF_LABEL,
        storage_secret,
        salt,
        policy.kdf_id,
        policy.parameter_code,
    )
}

fn encode_header(
    policy: StorageKdfPolicy,
    salt: &[u8; 32],
    nonce: &[u8; 12],
) -> [u8; STORE_HEADER_SIZE] {
    let mut header = [0_u8; STORE_HEADER_SIZE];
    header[..8].copy_from_slice(STORE_MAGIC);
    header[8] = STORE_VERSION;
    header[9] = policy.kdf_id;
    header[10..14].copy_from_slice(&policy.parameter_code.to_be_bytes());
    header[14..46].copy_from_slice(salt);
    header[46..58].copy_from_slice(nonce);
    header
}

fn decode_header(header: &[u8]) -> AppResult<(StorageKdfPolicy, &[u8; 32], &[u8; 12])> {
    if header.len() != STORE_HEADER_SIZE || &header[..8] != STORE_MAGIC {
        return Err(AppError::InvalidInput(
            "contact trust store header is invalid",
        ));
    }
    if header[8] != STORE_VERSION {
        return Err(AppError::InvalidInput(
            "contact trust store version is unsupported",
        ));
    }
    let parameter_code = u32::from_be_bytes(
        header[10..14]
            .try_into()
            .map_err(|_| AppError::InvalidInput("contact trust KDF parameters are invalid"))?,
    );
    let salt = header[14..46]
        .try_into()
        .map_err(|_| AppError::InvalidInput("contact trust salt is invalid"))?;
    let nonce = header[46..58]
        .try_into()
        .map_err(|_| AppError::InvalidInput("contact trust nonce is invalid"))?;
    Ok((
        StorageKdfPolicy {
            kdf_id: header[9],
            parameter_code,
        },
        salt,
        nonce,
    ))
}

fn encode_contacts(contacts: &[TrustedContact]) -> String {
    let mut out = String::from("HYDRACT-PLAIN-1\n");
    out.push_str("schema_version=1\n");
    out.push_str(&format!("contact_count={}\n", contacts.len()));
    for contact in contacts {
        out.push_str("contact\n");
        out.push_str(&format!("alias={}\n", encode_field(&contact.alias)));
        out.push_str(&format!("fingerprint={}\n", contact.fingerprint_hex));
        out.push_str(&format!("public_key={}\n", contact.public_key_hex));
        out.push_str(&format!("mailbox={}\n", contact.mailbox_hint));
        out.push_str(&format!(
            "mailbox_binding={}\n",
            contact.mailbox_binding_hex
        ));
        out.push_str(&format!("safety={}\n", contact.safety_number));
        out.push_str(&format!("qr={}\n", encode_field(&contact.qr_payload)));
        out.push_str(&format!("added_at_ms={}\n", contact.added_at_ms));
        out.push_str(&format!("updated_at_ms={}\n", contact.updated_at_ms));
        out.push_str(&format!("key_version={}\n", contact.key_version));
        out.push_str("end\n");
    }
    out
}

fn decode_contacts(bytes: &[u8]) -> AppResult<Vec<TrustedContact>> {
    if !bytes.starts_with(PLAINTEXT_MAGIC) {
        return Err(AppError::InvalidInput(
            "contact trust plaintext marker is invalid",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AppError::InvalidInput("contact trust plaintext is not UTF-8"))?;
    let mut contacts = Vec::new();
    let mut lines = text.lines();
    let _magic = lines.next();
    let Some(schema) = lines.next() else {
        return Err(AppError::InvalidInput("contact trust schema is missing"));
    };
    if schema != "schema_version=1" {
        return Err(AppError::InvalidInput(
            "contact trust schema is unsupported",
        ));
    }
    let Some(count_line) = lines.next() else {
        return Err(AppError::InvalidInput("contact trust count is missing"));
    };
    let expected_count = count_line
        .strip_prefix("contact_count=")
        .ok_or(AppError::InvalidInput("contact trust count is invalid"))?
        .parse::<usize>()
        .map_err(|_| AppError::InvalidInput("contact trust count is invalid"))?;
    while let Some(line) = lines.next() {
        if line.is_empty() {
            continue;
        }
        if line != "contact" {
            return Err(AppError::InvalidInput(
                "contact trust record marker is invalid",
            ));
        }
        let mut alias = None;
        let mut fingerprint_hex = None;
        let mut public_key_hex = None;
        let mut mailbox_hint = None;
        let mut mailbox_binding_hex = None;
        let mut safety_number = None;
        let mut qr_payload = None;
        let mut added_at_ms = None;
        let mut updated_at_ms = None;
        let mut key_version = None;
        for field in lines.by_ref() {
            if field == "end" {
                break;
            }
            let (key, value) = field
                .split_once('=')
                .ok_or(AppError::InvalidInput("contact trust field is invalid"))?;
            match key {
                "alias" => alias = Some(decode_field(value)?),
                "fingerprint" => fingerprint_hex = Some(value.to_owned()),
                "public_key" => public_key_hex = Some(value.to_owned()),
                "mailbox" => mailbox_hint = Some(value.to_owned()),
                "mailbox_binding" => mailbox_binding_hex = Some(value.to_owned()),
                "safety" => safety_number = Some(value.to_owned()),
                "qr" => qr_payload = Some(decode_field(value)?),
                "added_at_ms" => {
                    added_at_ms = Some(value.parse::<u64>().map_err(|_| {
                        AppError::InvalidInput("contact trust added timestamp is invalid")
                    })?)
                }
                "updated_at_ms" => {
                    updated_at_ms = Some(value.parse::<u64>().map_err(|_| {
                        AppError::InvalidInput("contact trust updated timestamp is invalid")
                    })?)
                }
                "key_version" => {
                    key_version = Some(value.parse::<u64>().map_err(|_| {
                        AppError::InvalidInput("contact trust key version is invalid")
                    })?)
                }
                _ => return Err(AppError::InvalidInput("contact trust field is unknown")),
            }
        }
        let contact = TrustedContact {
            alias: alias.ok_or(AppError::InvalidInput("contact alias is missing"))?,
            fingerprint_hex: fingerprint_hex
                .ok_or(AppError::InvalidInput("contact fingerprint is missing"))?,
            public_key_hex: public_key_hex
                .ok_or(AppError::InvalidInput("contact public key is missing"))?,
            mailbox_hint: mailbox_hint
                .ok_or(AppError::InvalidInput("contact mailbox is missing"))?,
            mailbox_binding_hex: mailbox_binding_hex
                .ok_or(AppError::InvalidInput("contact mailbox binding is missing"))?,
            safety_number: safety_number
                .ok_or(AppError::InvalidInput("contact safety number is missing"))?,
            qr_payload: qr_payload
                .ok_or(AppError::InvalidInput("contact QR payload is missing"))?,
            added_at_ms: added_at_ms
                .ok_or(AppError::InvalidInput("contact added timestamp is missing"))?,
            updated_at_ms: updated_at_ms.ok_or(AppError::InvalidInput(
                "contact updated timestamp is missing",
            ))?,
            key_version: key_version
                .ok_or(AppError::InvalidInput("contact key version is missing"))?,
        };
        contact.validate()?;
        contacts.push(contact);
    }
    if contacts.len() != expected_count {
        return Err(AppError::InvalidInput("contact trust count mismatch"));
    }
    contacts.sort_by_key(|contact| contact.alias.clone());
    for pair in contacts.windows(2) {
        if pair[0].alias == pair[1].alias {
            return Err(AppError::InvalidInput("contact aliases must be unique"));
        }
        if pair[0].public_key_hex == pair[1].public_key_hex {
            return Err(AppError::InvalidInput("contact public keys must be unique"));
        }
    }
    Ok(contacts)
}

struct ParsedQrContact {
    fingerprint_hex: String,
    public_key_hex: String,
    mailbox_hint: String,
    safety_number: String,
}

impl ParsedQrContact {
    fn parse(payload: &str) -> AppResult<Self> {
        let parts = payload.split('|').collect::<Vec<_>>();
        if parts.len() != 5 || parts[0] != QR_PREFIX {
            return Err(AppError::InvalidInput("contact QR payload is invalid"));
        }
        Ok(Self {
            fingerprint_hex: parts[1].to_owned(),
            mailbox_hint: parts[2].to_owned(),
            public_key_hex: parts[3].to_owned(),
            safety_number: parts[4].to_owned(),
        })
    }
}

fn public_identity_from_hex(hex: &str) -> AppResult<PublicIdentity> {
    let bytes = hex_decode(hex)?;
    let array: [u8; ML_DSA_65_VK_SIZE] = bytes
        .try_into()
        .map_err(|_| AppError::InvalidInput("contact public key length is invalid"))?;
    PublicIdentity::from_public_key(IdentityPublicKey(array))
}

fn derive_mailbox_hint(fingerprint_hex: &str) -> String {
    fingerprint_hex[..16].to_owned()
}

fn mailbox_binding_hex(public_key_hex: &str, fingerprint_hex: &str, mailbox_hint: &str) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(MAILBOX_LABEL);
    input.extend_from_slice(public_key_hex.as_bytes());
    input.push(0);
    input.extend_from_slice(fingerprint_hex.as_bytes());
    input.push(0);
    input.extend_from_slice(mailbox_hint.as_bytes());
    hex_encode(&RustCryptoBackend::sha3_256(&input))
}

fn safety_number(public_key_hex: &str, fingerprint_hex: &str, mailbox_hint: &str) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(SAFETY_LABEL);
    input.extend_from_slice(public_key_hex.as_bytes());
    input.push(0);
    input.extend_from_slice(fingerprint_hex.as_bytes());
    input.push(0);
    input.extend_from_slice(mailbox_hint.as_bytes());
    let digest = RustCryptoBackend::sha3_256(&input);
    let mut groups = Vec::with_capacity(8);
    for chunk in digest[..20].chunks_exact(5) {
        let value = u64::from_be_bytes([0, 0, 0, chunk[0], chunk[1], chunk[2], chunk[3], chunk[4]])
            % 100_000;
        groups.push(format!("{value:05}"));
    }
    groups.join("-")
}

fn qr_payload(
    public_key_hex: &str,
    fingerprint_hex: &str,
    mailbox_hint: &str,
    safety_number: &str,
) -> String {
    format!("{QR_PREFIX}|{fingerprint_hex}|{mailbox_hint}|{public_key_hex}|{safety_number}")
}

fn validate_alias(alias: &str) -> AppResult<()> {
    if alias.is_empty() {
        return Err(AppError::InvalidInput("contact alias must not be empty"));
    }
    if alias.len() > 96 {
        return Err(AppError::InvalidInput("contact alias is too long"));
    }
    if alias.contains('|') || alias.contains('\n') || alias.contains('\r') || alias.contains('=') {
        return Err(AppError::InvalidInput(
            "contact alias contains a reserved character",
        ));
    }
    Ok(())
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn encode_field(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_field(value: &str) -> AppResult<String> {
    let bytes = hex_decode(value)?;
    String::from_utf8(bytes).map_err(|_| AppError::InvalidInput("contact text field is not UTF-8"))
}

pub fn contact_hex_encode(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

pub fn contact_hex_decode(hex: &str) -> AppResult<Vec<u8>> {
    hex_decode(hex)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(hex: &str) -> AppResult<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(AppError::InvalidInput("hex input must have an even length"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> AppResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AppError::InvalidInput(
            "hex input contains a non-hex character",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let unique = current_time_ms();
        std::env::temp_dir().join(format!("hydra-contact-trust-{name}-{unique}"))
    }

    #[test]
    fn encrypted_contact_store_hides_plaintext_and_round_trips() {
        let path = temp_path("roundtrip");
        let password = b"contact-test-password";
        let mut store = ContactTrustStore::create_or_load(&path, password).unwrap();
        let added = match store.add_generated("bob").unwrap() {
            ContactAddOutcome::Added(contact) => contact,
            other => panic!("unexpected add outcome: {other:?}"),
        };
        store.save(password).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(b"bob".len()).any(|window| window == b"bob"));
        assert!(!bytes
            .windows(added.public_key_hex.len())
            .any(|window| window == added.public_key_hex.as_bytes()));
        let loaded = ContactTrustStore::load(&path, password).unwrap();
        assert_eq!(loaded.contacts(), &[added]);
    }

    #[test]
    fn key_change_warns_before_mutation() {
        let path = temp_path("key-change");
        let password = b"contact-test-password";
        let mut store = ContactTrustStore::create_or_load(&path, password).unwrap();
        let first = AppIdentity::generate().unwrap();
        let second = AppIdentity::generate().unwrap();
        let first_key = hex_encode(&first.public_identity().public_key().0);
        let second_key = hex_encode(&second.public_identity().public_key().0);
        let original = match store.add_public_key_hex("bob", &first_key).unwrap() {
            ContactAddOutcome::Added(contact) => contact,
            other => panic!("unexpected add outcome: {other:?}"),
        };
        let warning = match store.add_public_key_hex("bob", &second_key).unwrap() {
            ContactAddOutcome::KeyChangeWarning(warning) => warning,
            other => panic!("unexpected key-change outcome: {other:?}"),
        };
        assert_eq!(store.contacts()[0], original);
        assert_eq!(warning.old_fingerprint_hex, original.fingerprint_hex);
        let updated = match store
            .accept_key_change_public_key_hex("bob", &second_key)
            .unwrap()
        {
            ContactAddOutcome::Added(contact) => contact,
            other => panic!("unexpected accept outcome: {other:?}"),
        };
        assert_ne!(updated.fingerprint_hex, original.fingerprint_hex);
        assert_eq!(updated.key_version, 1);
    }

    #[test]
    fn qr_payload_verifies_against_pinned_contact() {
        let path = temp_path("qr");
        let password = b"contact-test-password";
        let mut store = ContactTrustStore::create_or_load(&path, password).unwrap();
        let contact = match store.add_generated("bob").unwrap() {
            ContactAddOutcome::Added(contact) => contact,
            other => panic!("unexpected add outcome: {other:?}"),
        };
        assert!(store.verify_qr_payload("bob", &contact.qr_payload).unwrap());
        assert!(!store
            .verify_qr_payload("alice", &contact.qr_payload)
            .unwrap());
    }

    #[test]
    fn public_contact_card_imports_as_trusted_qr_payload() {
        let path = temp_path("public-card");
        let password = b"contact-test-password";
        let identity = AppIdentity::generate().unwrap();
        let public_key_hex = hex_encode(&identity.public_identity().public_key().0);
        let card = PublicContactCard::create("alice", &public_key_hex).unwrap();
        assert_eq!(card.join_code, card.qr_payload);
        assert!(card.qr_payload.starts_with(QR_PREFIX));
        let mut store = ContactTrustStore::create_or_load(&path, password).unwrap();
        let contact = match store.add_qr_payload("alice", &card.join_code).unwrap() {
            ContactAddOutcome::Added(contact) => contact,
            other => panic!("unexpected contact-card outcome: {other:?}"),
        };
        assert_eq!(contact.fingerprint_hex, card.fingerprint_hex);
        assert_eq!(contact.safety_number, card.safety_number);
    }

    #[test]
    fn qr_key_change_requires_explicit_acceptance() {
        let path = temp_path("qr-key-change");
        let password = b"contact-test-password";
        let mut store = ContactTrustStore::create_or_load(&path, password).unwrap();
        let original = match store.add_generated("bob").unwrap() {
            ContactAddOutcome::Added(contact) => contact,
            other => panic!("unexpected add outcome: {other:?}"),
        };
        let replacement = AppIdentity::generate().unwrap();
        let replacement_contact =
            build_contact("bob", &replacement.public_identity(), 0, 0, 0).unwrap();
        let warning = match store
            .add_qr_payload("bob", &replacement_contact.qr_payload)
            .unwrap()
        {
            ContactAddOutcome::KeyChangeWarning(warning) => warning,
            other => panic!("unexpected QR change outcome: {other:?}"),
        };
        assert_eq!(store.contacts()[0], original);
        assert_eq!(warning.old_fingerprint_hex, original.fingerprint_hex);
        let updated = match store
            .accept_key_change_qr_payload("bob", &replacement_contact.qr_payload)
            .unwrap()
        {
            ContactAddOutcome::Added(contact) => contact,
            other => panic!("unexpected QR accept outcome: {other:?}"),
        };
        assert_ne!(updated.fingerprint_hex, original.fingerprint_hex);
        assert_eq!(updated.key_version, 1);
    }
}
