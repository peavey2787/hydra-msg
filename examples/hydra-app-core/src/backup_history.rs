use std::{
    fs,
    path::{Path, PathBuf},
};

use hydra_core::{
    types::{IdentityFingerprint, IdentityPublicKey},
    ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

use crate::{
    secret_handling::crash_safe_atomic_write, AppError, AppIdentity, AppResult, LiveStateStore,
    PublicIdentity,
};

const CHECKPOINT_TEXT_MAGIC: &str = "HYDRA-MSG SIGNED BACKUP CHECKPOINT v1";
const CHECKPOINT_FILE_PREFIX: &str = "hydra-checkpoint-";
const CHECKPOINT_FILE_SUFFIX: &str = ".hcpt";

/// Warning shown when a local state database is older than a signed checkpoint
/// the user previously created/imported/synced.
pub const POSSIBLE_ROLLBACK_WARNING: &str = concat!(
    "Possible rollback detected.\n\n",
    "This device is trying to use state older than a signed checkpoint you previously created.\n",
    "Continuing may allow replayed messages, revoked devices, or old session keys to be reused."
);

/// User-visible signed metadata for one encrypted live-state commit.
///
/// This is intentionally portable: the checkpoint is a text file that can be
/// copied to USB storage, cloud sync, another device, or any app-chosen storage.
/// It does not contain plaintext messages, live protocol secrets, or storage
/// keys. It only signs the monotonic backup sequence and encrypted state hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBackupCheckpoint {
    pub backup_sequence: u64,
    pub local_rollback_counter: u64,
    pub encrypted_state_hash: [u8; 32],
    pub identity_fingerprint: IdentityFingerprint,
    pub identity_public_key: IdentityPublicKey,
    pub signature: [u8; ML_DSA_65_SIG_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupHistoryStatus {
    pub local_backup_sequence: u64,
    pub newest_known_sequence: Option<u64>,
    pub possible_rollback: bool,
}

impl SignedBackupCheckpoint {
    pub fn for_live_state(
        live_state_path: impl AsRef<Path>,
        local_rollback_counter: u64,
        signer: &AppIdentity,
    ) -> AppResult<Self> {
        let encrypted_state_hash =
            encrypted_live_state_hash(live_state_path, local_rollback_counter)?;
        let identity = signer.public_identity();
        let mut checkpoint = Self {
            backup_sequence: local_rollback_counter,
            local_rollback_counter,
            encrypted_state_hash,
            identity_fingerprint: identity.fingerprint(),
            identity_public_key: identity.public_key().clone(),
            signature: [0_u8; ML_DSA_65_SIG_SIZE],
        };
        let digest = checkpoint.signing_digest();
        checkpoint.signature = signer.sign_backup_checkpoint_digest(&digest)?;
        Ok(checkpoint)
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        if identity_fingerprint_for_public_key(self.identity_public_key.clone())
            != Some(self.identity_fingerprint)
        {
            return false;
        }
        let Ok(identity) = PublicIdentity::from_public_key(self.identity_public_key.clone()) else {
            return false;
        };
        identity
            .verify_backup_checkpoint_digest(&self.signing_digest(), &self.signature)
            .is_ok()
    }

    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "{}\nbackup_sequence={}\nlocal_rollback_counter={}\nencrypted_state_hash={}\nidentity_fingerprint={}\nidentity_public_key={}\nsignature={}\n",
            CHECKPOINT_TEXT_MAGIC,
            self.backup_sequence,
            self.local_rollback_counter,
            encode_hex(&self.encrypted_state_hash),
            encode_hex(&self.identity_fingerprint.0),
            encode_hex(&self.identity_public_key.0),
            encode_hex(&self.signature),
        )
    }

    pub fn from_text(text: &str) -> AppResult<Self> {
        let mut lines = text.lines();
        if lines.next() != Some(CHECKPOINT_TEXT_MAGIC) {
            return Err(AppError::InvalidInput(
                "signed backup checkpoint magic is invalid",
            ));
        }
        let mut backup_sequence = None;
        let mut local_rollback_counter = None;
        let mut encrypted_state_hash = None;
        let mut identity_fingerprint = None;
        let mut identity_public_key = None;
        let mut signature = None;
        for line in lines {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "backup_sequence" => backup_sequence = Some(parse_u64(value)?),
                "local_rollback_counter" => local_rollback_counter = Some(parse_u64(value)?),
                "encrypted_state_hash" => {
                    encrypted_state_hash = Some(decode_hex_array::<32>(value)?)
                }
                "identity_fingerprint" => {
                    identity_fingerprint = Some(IdentityFingerprint(decode_hex_array::<32>(value)?))
                }
                "identity_public_key" => {
                    identity_public_key = Some(IdentityPublicKey(decode_hex_array::<
                        ML_DSA_65_VK_SIZE,
                    >(value)?))
                }
                "signature" => signature = Some(decode_hex_array::<ML_DSA_65_SIG_SIZE>(value)?),
                _ => {}
            }
        }
        let checkpoint = Self {
            backup_sequence: backup_sequence.ok_or(AppError::InvalidInput(
                "signed backup checkpoint sequence is missing",
            ))?,
            local_rollback_counter: local_rollback_counter.ok_or(AppError::InvalidInput(
                "signed backup checkpoint rollback counter is missing",
            ))?,
            encrypted_state_hash: encrypted_state_hash.ok_or(AppError::InvalidInput(
                "signed backup checkpoint state hash is missing",
            ))?,
            identity_fingerprint: identity_fingerprint.ok_or(AppError::InvalidInput(
                "signed backup checkpoint identity fingerprint is missing",
            ))?,
            identity_public_key: identity_public_key.ok_or(AppError::InvalidInput(
                "signed backup checkpoint identity public key is missing",
            ))?,
            signature: signature.ok_or(AppError::InvalidInput(
                "signed backup checkpoint signature is missing",
            ))?,
        };
        if !checkpoint.verify() {
            return Err(AppError::InvalidState(
                "signed backup checkpoint signature is invalid",
            ));
        }
        Ok(checkpoint)
    }

    fn signing_digest(&self) -> [u8; 64] {
        let mut body = Vec::with_capacity(64 + 8 + 8 + 32 + 32 + ML_DSA_65_VK_SIZE);
        body.extend_from_slice(b"HYDRA-MSG/v1/signed-backup-checkpoint");
        body.extend_from_slice(&self.backup_sequence.to_be_bytes());
        body.extend_from_slice(&self.local_rollback_counter.to_be_bytes());
        body.extend_from_slice(&self.encrypted_state_hash);
        body.extend_from_slice(&self.identity_fingerprint.0);
        body.extend_from_slice(&self.identity_public_key.0);
        RustCryptoBackend::sha3_512(&body)
    }
}

pub fn write_signed_checkpoint_history(
    history_path: impl AsRef<Path>,
    checkpoint: &SignedBackupCheckpoint,
) -> AppResult<()> {
    if !checkpoint.verify() {
        return Err(AppError::InvalidState(
            "signed backup checkpoint signature is invalid",
        ));
    }
    let history_path = history_path.as_ref();
    let mut checkpoints = read_signed_checkpoint_history(history_path)?;
    if checkpoints
        .iter()
        .any(|existing| existing.backup_sequence == checkpoint.backup_sequence)
    {
        return Ok(());
    }
    checkpoints.push(checkpoint.clone());
    checkpoints.sort_by_key(|entry| entry.backup_sequence);
    let mut text = String::new();
    for checkpoint in checkpoints {
        text.push_str(&checkpoint.to_text());
        text.push('\n');
    }
    crash_safe_atomic_write(
        history_path,
        text.as_bytes(),
        "signed backup history cannot be written",
    )
}

pub fn read_signed_checkpoint_history(
    history_path: impl AsRef<Path>,
) -> AppResult<Vec<SignedBackupCheckpoint>> {
    let history_path = history_path.as_ref();
    if !history_path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(history_path)
        .map_err(|_| AppError::InvalidInput("signed backup history cannot be read"))?;
    parse_checkpoint_stream(&text)
}

pub fn export_signed_checkpoint(
    export_dir: impl AsRef<Path>,
    checkpoint: &SignedBackupCheckpoint,
) -> AppResult<PathBuf> {
    let export_dir = export_dir.as_ref();
    fs::create_dir_all(export_dir).map_err(|_| {
        AppError::InvalidInput("signed backup checkpoint export directory cannot be created")
    })?;
    let path = export_dir.join(format!(
        "{CHECKPOINT_FILE_PREFIX}{:020}{CHECKPOINT_FILE_SUFFIX}",
        checkpoint.backup_sequence,
    ));
    crash_safe_atomic_write(
        &path,
        checkpoint.to_text().as_bytes(),
        "signed backup checkpoint cannot be exported",
    )?;
    Ok(path)
}

pub fn load_exported_signed_checkpoints(
    path: impl AsRef<Path>,
) -> AppResult<Vec<SignedBackupCheckpoint>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    if path.is_file() {
        let text = fs::read_to_string(path).map_err(|_| {
            AppError::InvalidInput("exported signed backup checkpoint cannot be read")
        })?;
        return parse_checkpoint_stream(&text);
    }
    let mut checkpoints = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| {
        AppError::InvalidInput("signed backup checkpoint export directory cannot be read")
    })? {
        let entry = entry.map_err(|_| {
            AppError::InvalidInput("signed backup checkpoint export entry cannot be read")
        })?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with(CHECKPOINT_FILE_PREFIX)
            || !file_name.ends_with(CHECKPOINT_FILE_SUFFIX)
        {
            continue;
        }
        let text = fs::read_to_string(entry.path()).map_err(|_| {
            AppError::InvalidInput("exported signed backup checkpoint cannot be read")
        })?;
        checkpoints.push(SignedBackupCheckpoint::from_text(&text)?);
    }
    Ok(checkpoints)
}

pub fn check_live_state_against_signed_history(
    live_state_path: impl AsRef<Path>,
    local_backup_sequence: u64,
    local_history_path: impl AsRef<Path>,
    exported_checkpoint_paths: &[PathBuf],
) -> AppResult<BackupHistoryStatus> {
    let mut checkpoints = read_signed_checkpoint_history(local_history_path)?;
    for path in exported_checkpoint_paths {
        checkpoints.extend(load_exported_signed_checkpoints(path)?);
    }
    let newest = checkpoints
        .iter()
        .map(|checkpoint| checkpoint.backup_sequence)
        .max();
    if newest.is_some_and(|sequence| sequence > local_backup_sequence) {
        return Err(AppError::InvalidState(POSSIBLE_ROLLBACK_WARNING));
    }
    if let Some(local_match) = checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.backup_sequence == local_backup_sequence)
        .max_by_key(|checkpoint| checkpoint.local_rollback_counter)
    {
        let hash = encrypted_live_state_hash(live_state_path, local_backup_sequence)?;
        if local_match.encrypted_state_hash != hash {
            return Err(AppError::InvalidState(POSSIBLE_ROLLBACK_WARNING));
        }
    }
    Ok(BackupHistoryStatus {
        local_backup_sequence,
        newest_known_sequence: newest,
        possible_rollback: false,
    })
}

impl LiveStateStore {
    pub fn save_with_signed_backup_history(
        &mut self,
        password: &[u8],
        signer: &AppIdentity,
        local_history_path: impl AsRef<Path>,
        export_dir: Option<&Path>,
    ) -> AppResult<SignedBackupCheckpoint> {
        self.save(password)?;
        let checkpoint =
            SignedBackupCheckpoint::for_live_state(self.path(), self.rollback_counter(), signer)?;
        write_signed_checkpoint_history(local_history_path, &checkpoint)?;
        if let Some(export_dir) = export_dir {
            export_signed_checkpoint(export_dir, &checkpoint)?;
        }
        Ok(checkpoint)
    }

    pub fn load_with_signed_backup_history(
        path: impl AsRef<Path>,
        password: &[u8],
        local_history_path: impl AsRef<Path>,
        exported_checkpoint_paths: &[PathBuf],
    ) -> AppResult<Self> {
        let store = Self::load(&path, password)?;
        check_live_state_against_signed_history(
            path,
            store.rollback_counter(),
            local_history_path,
            exported_checkpoint_paths,
        )?;
        Ok(store)
    }
}

fn encrypted_live_state_hash(path: impl AsRef<Path>, sequence: u64) -> AppResult<[u8; 32]> {
    let file = fs::read(path.as_ref()).map_err(|_| {
        AppError::InvalidInput("live state database cannot be read for signed checkpoint")
    })?;
    let mut body = Vec::with_capacity(64 + 8 + file.len());
    body.extend_from_slice(b"HYDRA-MSG/v1/signed-backup-state-hash");
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(&file);
    Ok(RustCryptoBackend::sha3_256(&body))
}

fn parse_checkpoint_stream(text: &str) -> AppResult<Vec<SignedBackupCheckpoint>> {
    let mut out = Vec::new();
    for chunk in text.split(CHECKPOINT_TEXT_MAGIC).skip(1) {
        let checkpoint_text = format!("{CHECKPOINT_TEXT_MAGIC}{chunk}");
        let trimmed = checkpoint_text.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(SignedBackupCheckpoint::from_text(trimmed)?);
    }
    Ok(out)
}

fn identity_fingerprint_for_public_key(
    public_key: IdentityPublicKey,
) -> Option<IdentityFingerprint> {
    PublicIdentity::from_public_key(public_key)
        .ok()
        .map(|identity| identity.fingerprint())
}

fn parse_u64(input: &str) -> AppResult<u64> {
    input
        .parse::<u64>()
        .map_err(|_| AppError::InvalidInput("signed backup checkpoint sequence is invalid"))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_array<const N: usize>(input: &str) -> AppResult<[u8; N]> {
    let bytes = decode_hex(input)?;
    if bytes.len() != N {
        return Err(AppError::InvalidInput(
            "signed backup checkpoint hex field has invalid length",
        ));
    }
    bytes.try_into().map_err(|_| {
        AppError::InvalidInput("signed backup checkpoint hex field has invalid length")
    })
}

fn decode_hex(input: &str) -> AppResult<Vec<u8>> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
        return Err(AppError::InvalidInput(
            "signed backup checkpoint hex field has odd length",
        ));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> AppResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AppError::InvalidInput(
            "signed backup checkpoint hex field is invalid",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{AppSession, AppSessionRole, SessionHandshakeExport};
    use hydra_crypto::SecretBytes;

    fn temp_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("hydra-signed-history-{label}-{unique}.db"))
    }

    #[test]
    fn signed_checkpoint_round_trips_and_verifies() {
        let password = b"signed checkpoint password";
        let path = temp_path("roundtrip");
        let history = path.with_extension("history");
        let alice = AppIdentity::generate().unwrap();
        let mut store = LiveStateStore::create(&path, password).unwrap();
        let checkpoint = store
            .save_with_signed_backup_history(password, &alice, &history, None)
            .unwrap();
        assert_eq!(checkpoint.backup_sequence, 1);
        assert!(checkpoint.verify());
        let text = checkpoint.to_text();
        let decoded = SignedBackupCheckpoint::from_text(&text).unwrap();
        assert_eq!(decoded, checkpoint);
        let loaded = read_signed_checkpoint_history(&history).unwrap();
        assert_eq!(loaded, vec![checkpoint]);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(history);
    }

    #[test]
    fn newer_exported_checkpoint_rejects_older_local_state() {
        let password = b"signed checkpoint rollback password";
        let path = temp_path("rollback");
        let history = path.with_extension("history");
        let export_dir = std::env::temp_dir().join(format!(
            "hydra-signed-history-export-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let transcript = [0x91; 64];
        let secret = [0x92; 32];
        let mut session = AppSession::start(
            AppSessionRole::Initiator,
            &alice,
            bob.public_identity(),
            SessionHandshakeExport::from_handshake_layer(
                SecretBytes::from_array(secret),
                transcript,
            ),
        )
        .unwrap();
        let conversation = crate::ConversationId([0x93; 32]);
        let mut store = LiveStateStore::create(&path, password).unwrap();
        store.upsert_session(conversation, &session);
        store
            .save_with_signed_backup_history(password, &alice, &history, Some(export_dir.as_path()))
            .unwrap();
        let _ = session.send(b"advance state").unwrap();
        store.upsert_session(conversation, &session);
        store
            .save_with_signed_backup_history(password, &alice, &history, Some(export_dir.as_path()))
            .unwrap();

        let error = check_live_state_against_signed_history(
            &path,
            1,
            &history,
            std::slice::from_ref(&export_dir),
        )
        .unwrap_err();
        assert_eq!(error, AppError::InvalidState(POSSIBLE_ROLLBACK_WARNING));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(history);
        let _ = fs::remove_dir_all(export_dir);
    }
}
