use super::{exact_array_from_vec, hex_decode, hex_encode, random_array};
use crate::{limits::MAX_PASSWORD_BYTES, HydraMsgError, HydraResult};
use hydra_crypto::SecretBytes;
use scrypt::{scrypt, Params as ScryptParams};
use zeroize::Zeroize;

pub(crate) const KDF_ALGORITHM_SCRYPT: &str = "scrypt";
pub(crate) const KDF_PROFILE_MOBILE: &str = "mobile";
pub(crate) const KDF_PROFILE_INTERACTIVE: &str = "interactive";
pub(crate) const KDF_PROFILE_HIGH_SECURITY: &str = "high-security";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PasswordKdfRecord {
    pub(crate) profile: String,
    pub(crate) log_n: u8,
    pub(crate) r: u32,
    pub(crate) p: u32,
    pub(crate) salt: [u8; 32],
}

impl PasswordKdfRecord {
    pub(crate) fn new_interactive() -> HydraResult<Self> {
        Self::with_salt(KDF_PROFILE_INTERACTIVE, random_array::<32>()?)
    }

    pub(crate) fn with_salt(profile: &str, salt: [u8; 32]) -> HydraResult<Self> {
        let (log_n, r, p) = params_for_profile(profile)?;
        Ok(Self {
            profile: profile.to_owned(),
            log_n,
            r,
            p,
            salt,
        })
    }

    pub(crate) fn validate(&self) -> HydraResult<()> {
        let (log_n, r, p) = params_for_profile(&self.profile)?;
        if self.log_n != log_n || self.r != r || self.p != p {
            return Err(HydraMsgError::InvalidEncoding("kdf parameters"));
        }
        if self.salt == [0_u8; 32] {
            return Err(HydraMsgError::InvalidEncoding("kdf salt"));
        }
        Ok(())
    }
}

pub(crate) fn derive_password_key(
    label: &'static [u8],
    password: &str,
    kdf: &PasswordKdfRecord,
) -> HydraResult<SecretBytes<32>> {
    if password.is_empty() {
        return Err(HydraMsgError::InvalidPassword);
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(HydraMsgError::InvalidInput("password size"));
    }
    kdf.validate()?;
    let params = ScryptParams::new(kdf.log_n, kdf.r, kdf.p, 32)
        .map_err(|_| HydraMsgError::InvalidEncoding("kdf parameters"))?;
    let mut labelled_password = Vec::with_capacity(label.len() + 1 + password.len());
    labelled_password.extend_from_slice(label);
    labelled_password.push(0);
    labelled_password.extend_from_slice(password.as_bytes());
    let mut out = [0_u8; 32];
    scrypt(&labelled_password, &kdf.salt, &params, &mut out)
        .map_err(|_| HydraMsgError::Crypto("scrypt KDF failed".to_owned()))?;
    labelled_password.zeroize();
    Ok(SecretBytes::from_array(out))
}

pub(crate) fn encode_kdf_fields(kdf: &PasswordKdfRecord) -> String {
    format!(
        "kdf\t{}\nkdf_profile\t{}\nkdf_log_n\t{}\nkdf_r\t{}\nkdf_p\t{}\nkdf_salt\t{}\n",
        KDF_ALGORITHM_SCRYPT,
        kdf.profile,
        kdf.log_n,
        kdf.r,
        kdf.p,
        hex_encode(&kdf.salt)
    )
}

pub(crate) fn decode_kdf_fields<'a, I>(lines: &mut I) -> HydraResult<PasswordKdfRecord>
where
    I: Iterator<Item = &'a str>,
{
    let algorithm = required_field(lines, "kdf", "kdf algorithm")?;
    if algorithm != KDF_ALGORITHM_SCRYPT {
        return Err(HydraMsgError::Unsupported("kdf algorithm"));
    }
    let profile_value = required_field(lines, "kdf_profile", "kdf profile")?;
    if profile_value.len() > 32 {
        return Err(HydraMsgError::InvalidEncoding("kdf profile"));
    }
    let profile = profile_value.to_owned();
    let log_n = required_field(lines, "kdf_log_n", "kdf log_n")?
        .parse::<u8>()
        .map_err(|_| HydraMsgError::InvalidEncoding("kdf log_n"))?;
    let r = required_field(lines, "kdf_r", "kdf r")?
        .parse::<u32>()
        .map_err(|_| HydraMsgError::InvalidEncoding("kdf r"))?;
    let p = required_field(lines, "kdf_p", "kdf p")?
        .parse::<u32>()
        .map_err(|_| HydraMsgError::InvalidEncoding("kdf p"))?;
    let salt = decode_kdf_salt(required_field(lines, "kdf_salt", "kdf salt")?)?;
    let record = PasswordKdfRecord {
        profile,
        log_n,
        r,
        p,
        salt,
    };
    record.validate()?;
    Ok(record)
}

pub(crate) fn parse_kdf_columns(parts: &[&str]) -> HydraResult<PasswordKdfRecord> {
    if parts.len() != 6 || parts[0] != KDF_ALGORITHM_SCRYPT || parts[1].len() > 32 {
        return Err(HydraMsgError::InvalidEncoding("kdf columns"));
    }
    let record = PasswordKdfRecord {
        profile: parts[1].to_owned(),
        log_n: parts[2]
            .parse::<u8>()
            .map_err(|_| HydraMsgError::InvalidEncoding("kdf log_n"))?,
        r: parts[3]
            .parse::<u32>()
            .map_err(|_| HydraMsgError::InvalidEncoding("kdf r"))?,
        p: parts[4]
            .parse::<u32>()
            .map_err(|_| HydraMsgError::InvalidEncoding("kdf p"))?,
        salt: decode_kdf_salt(parts[5])?,
    };
    record.validate()?;
    Ok(record)
}

pub(crate) fn encode_kdf_columns(kdf: &PasswordKdfRecord) -> [String; 6] {
    [
        KDF_ALGORITHM_SCRYPT.to_owned(),
        kdf.profile.clone(),
        kdf.log_n.to_string(),
        kdf.r.to_string(),
        kdf.p.to_string(),
        hex_encode(&kdf.salt),
    ]
}

pub(crate) fn required_field<'a, I>(
    lines: &mut I,
    name: &str,
    description: &'static str,
) -> HydraResult<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    let line = lines
        .next()
        .ok_or(HydraMsgError::InvalidEncoding(description))?;
    let (got, value) = line
        .split_once('\t')
        .ok_or(HydraMsgError::InvalidEncoding("kdf field"))?;
    if got == name {
        Ok(value)
    } else {
        Err(HydraMsgError::InvalidEncoding("kdf field name"))
    }
}

fn decode_kdf_salt(value: &str) -> HydraResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(HydraMsgError::InvalidEncoding("kdf salt"));
    }
    exact_array_from_vec(hex_decode(value)?)
}

fn params_for_profile(profile: &str) -> HydraResult<(u8, u32, u32)> {
    match profile {
        KDF_PROFILE_MOBILE => Ok((13, 8, 1)),
        KDF_PROFILE_INTERACTIVE => Ok((14, 8, 1)),
        KDF_PROFILE_HIGH_SECURITY => Ok((15, 8, 1)),
        _ => Err(HydraMsgError::Unsupported("kdf profile")),
    }
}
