use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use hydra_crypto::SecretBytes;
use scrypt::{scrypt, Params as ScryptParams};
use zeroize::Zeroize;

use crate::{AppError, AppResult};

pub(crate) const KDF_ID_SCRYPT: u8 = 2;

const DEFAULT_SCRYPT_LOG_N: u8 = 14;
const DEFAULT_SCRYPT_R: u8 = 8;
const DEFAULT_SCRYPT_P: u16 = 1;

pub(crate) const DEFAULT_SCRYPT_PARAM_CODE: u32 =
    encode_scrypt_params(DEFAULT_SCRYPT_LOG_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P);

pub(crate) const fn encode_scrypt_params(log_n: u8, r: u8, p: u16) -> u32 {
    ((log_n as u32) << 24) | ((r as u32) << 16) | p as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageKdfPolicy {
    pub kdf_id: u8,
    pub parameter_code: u32,
}

impl StorageKdfPolicy {
    #[must_use]
    pub const fn scrypt_interactive() -> Self {
        Self {
            kdf_id: KDF_ID_SCRYPT,
            parameter_code: DEFAULT_SCRYPT_PARAM_CODE,
        }
    }
}

/// OS-keychain integration hook for app frontends.
///
/// `hydra-app-core` does not directly depend on platform keychain crates so the
/// core library stays portable and deterministic in CI. GUI/native shells can
/// implement this trait with Windows Credential Manager, macOS Keychain, Linux
/// Secret Service, or a hardware-token backed provider and then pass the loaded
/// secret bytes into the encrypted stores.
pub trait OsKeychainSecretProvider {
    fn load_secret(&self, service: &str, account: &str) -> AppResult<SecretBytes<32>>;
    fn store_secret(&self, service: &str, account: &str, secret: &SecretBytes<32>)
        -> AppResult<()>;
}

/// Explicit unavailable provider used when an app is compiled without a native
/// keychain backend. This keeps the OS-keychain path visible without silently
/// falling back to a weaker source.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedOsKeychain;

impl OsKeychainSecretProvider for UnsupportedOsKeychain {
    fn load_secret(&self, _service: &str, _account: &str) -> AppResult<SecretBytes<32>> {
        Err(AppError::InvalidState(
            "OS keychain provider is not configured",
        ))
    }

    fn store_secret(
        &self,
        _service: &str,
        _account: &str,
        _secret: &SecretBytes<32>,
    ) -> AppResult<()> {
        Err(AppError::InvalidState(
            "OS keychain provider is not configured",
        ))
    }
}

pub(crate) fn derive_storage_key(
    label: &'static [u8],
    password: &[u8],
    salt: &[u8; 32],
    kdf_id: u8,
    parameter_code: u32,
) -> AppResult<SecretBytes<32>> {
    if password.is_empty() {
        return Err(AppError::InvalidInput("storage secret must not be empty"));
    }
    match kdf_id {
        KDF_ID_SCRYPT => derive_scrypt_key(label, password, salt, parameter_code),
        _ => Err(AppError::InvalidInput("storage KDF is unsupported")),
    }
}

fn derive_scrypt_key(
    label: &'static [u8],
    password: &[u8],
    salt: &[u8; 32],
    parameter_code: u32,
) -> AppResult<SecretBytes<32>> {
    let log_n = (parameter_code >> 24) as u8;
    let r = (parameter_code >> 16) & 0xff;
    let p = parameter_code & 0xffff;
    if log_n < 14 || r == 0 || p == 0 {
        return Err(AppError::InvalidInput(
            "scrypt storage KDF parameters are too weak or invalid",
        ));
    }
    let params = ScryptParams::new(log_n, r, p, 32)
        .map_err(|_| AppError::InvalidInput("scrypt storage KDF parameters are invalid"))?;
    let mut labelled_password = Vec::with_capacity(label.len() + 1 + password.len());
    labelled_password.extend_from_slice(label);
    labelled_password.push(0);
    labelled_password.extend_from_slice(password);
    let mut out = [0_u8; 32];
    scrypt(&labelled_password, salt, &params, &mut out)
        .map_err(|_| AppError::InvalidInput("scrypt storage KDF failed"))?;
    labelled_password.zeroize();
    Ok(SecretBytes::from_array(out))
}

pub(crate) fn read_crash_safe(path: &Path, label: &'static str) -> AppResult<Vec<u8>> {
    recover_backup_if_needed(path, label)?;
    fs::read(path).map_err(|_| AppError::InvalidInput(label))
}

pub(crate) fn crash_safe_atomic_write(
    path: &Path,
    bytes: &[u8],
    label: &'static str,
) -> AppResult<()> {
    recover_backup_if_needed(path, label)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|_| AppError::InvalidInput(label))?;
        }
    }

    let temp = temp_path(path);
    let backup = backup_path(path);
    if temp.exists() {
        fs::remove_file(&temp).map_err(|_| AppError::InvalidInput(label))?;
    }

    {
        let mut file = File::create(&temp).map_err(|_| AppError::InvalidInput(label))?;
        file.write_all(bytes)
            .map_err(|_| AppError::InvalidInput(label))?;
        file.sync_all().map_err(|_| AppError::InvalidInput(label))?;
    }

    if backup.exists() {
        fs::remove_file(&backup).map_err(|_| AppError::InvalidInput(label))?;
    }
    if path.exists() {
        fs::rename(path, &backup).map_err(|_| AppError::InvalidInput(label))?;
    }
    fs::rename(&temp, path).map_err(|_| AppError::InvalidInput(label))?;
    sync_parent_dir(path);
    if backup.exists() {
        fs::remove_file(&backup).map_err(|_| AppError::InvalidInput(label))?;
    }
    Ok(())
}

fn recover_backup_if_needed(path: &Path, label: &'static str) -> AppResult<()> {
    if path.exists() {
        return Ok(());
    }
    let backup = backup_path(path);
    if backup.exists() {
        fs::rename(&backup, path).map_err(|_| AppError::InvalidInput(label))?;
    }
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}bak",
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    ))
}

fn temp_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    ))
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
}
