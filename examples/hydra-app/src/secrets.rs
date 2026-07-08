use std::{env, fs, path::Path};

use getrandom::SysRng;
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use rand_core::TryRng;

const ENV_PASSWORD: &str = "HYDRA_APP_PASSWORD";
const ENV_SECRET_SOURCE: &str = "HYDRA_APP_SECRET_SOURCE";
const LOCAL_SECRET_FILE: &str = ".hydra-local-secret";

pub struct AppStorageSecret {
    bytes: SecretBytes<32>,
    source: AppStorageSecretSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppStorageSecretSource {
    EnvironmentPassword,
    LocalKeyFile,
}

impl AppStorageSecret {
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.bytes.expose_secret()
    }

    #[must_use]
    pub const fn source_label(&self) -> &'static str {
        match self.source {
            AppStorageSecretSource::EnvironmentPassword => "environment-password",
            AppStorageSecretSource::LocalKeyFile => "local-key-file",
        }
    }
}

pub fn load_storage_secret(data_dir: &Path) -> Result<AppStorageSecret, String> {
    match env::var(ENV_SECRET_SOURCE).unwrap_or_default().trim() {
        "" | "auto" => load_auto_secret(data_dir),
        "env" | "environment" => load_env_password(),
        "local-key-file" => load_local_key_file(data_dir),
        "os-keychain" => Err(
            "HYDRA_APP_SECRET_SOURCE=os-keychain requested, but no native OS keychain backend is linked yet".to_owned(),
        ),
        other => Err(format!(
            "unknown {ENV_SECRET_SOURCE} value '{other}' (use auto, env, local-key-file, or os-keychain)"
        )),
    }
}

fn load_auto_secret(data_dir: &Path) -> Result<AppStorageSecret, String> {
    if env::var_os(ENV_PASSWORD).is_some() {
        load_env_password()
    } else {
        load_local_key_file(data_dir)
    }
}

fn load_env_password() -> Result<AppStorageSecret, String> {
    let password = env::var(ENV_PASSWORD).map_err(|_| format!("{ENV_PASSWORD} is not set"))?;
    if password.is_empty() {
        return Err(format!("{ENV_PASSWORD} must not be empty"));
    }
    Ok(AppStorageSecret {
        bytes: SecretBytes::from_array(derive_app_secret(password.as_bytes())),
        source: AppStorageSecretSource::EnvironmentPassword,
    })
}

fn load_local_key_file(data_dir: &Path) -> Result<AppStorageSecret, String> {
    fs::create_dir_all(data_dir)
        .map_err(|error| format!("cannot create data dir {}: {error}", data_dir.display()))?;
    let path = data_dir.join(LOCAL_SECRET_FILE);
    if path.exists() {
        let text = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read local app secret {}: {error}", path.display()))?;
        let bytes = decode_hex_32(text.trim())?;
        return Ok(AppStorageSecret {
            bytes: SecretBytes::from_array(bytes),
            source: AppStorageSecretSource::LocalKeyFile,
        });
    }

    let mut bytes = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| format!("cannot generate local app secret: {error}"))?;
    let encoded = encode_hex(&bytes);
    fs::write(&path, encoded)
        .map_err(|error| format!("cannot write local app secret {}: {error}", path.display()))?;
    Ok(AppStorageSecret {
        bytes: SecretBytes::from_array(bytes),
        source: AppStorageSecretSource::LocalKeyFile,
    })
}

fn derive_app_secret(password: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(b"HYDRA-MSG/app/storage-secret/v1".len() + password.len());
    input.extend_from_slice(b"HYDRA-MSG/app/storage-secret/v1");
    input.extend_from_slice(password);
    RustCryptoBackend::sha3_256(&input)
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

fn decode_hex_32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("local app secret has invalid length".to_owned());
    }
    let mut out = [0_u8; 32];
    let bytes = text.as_bytes();
    for index in 0..32 {
        let hi = hex_nibble(bytes[index * 2])?;
        let lo = hex_nibble(bytes[index * 2 + 1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("local app secret is not valid hex".to_owned()),
    }
}
