use std::{error::Error, fmt};

/// Errors produced while creating or recovering a steganographic text carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StegoError {
    InvalidConfig(&'static str),
    PayloadTooLarge { actual: usize, maximum: usize },
    CoverTooLarge { actual: usize, maximum: usize },
    ModelRequired,
    NotCoverText,
    MalformedCoverText(&'static str),
    Model(String),
    IntegrityMismatch,
}

impl fmt::Display for StegoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid stego config: {reason}"),
            Self::PayloadTooLarge { actual, maximum } => write!(
                formatter,
                "stego payload contains {actual} bytes; configured maximum is {maximum}"
            ),
            Self::CoverTooLarge { actual, maximum } => write!(
                formatter,
                "stego carrier contains {actual} bytes; configured maximum is {maximum}"
            ),
            Self::ModelRequired => formatter.write_str(
                "selected stego profile requires a configured deterministic local model",
            ),
            Self::NotCoverText => formatter.write_str("text is not a HYDRA stego carrier"),
            Self::MalformedCoverText(reason) => {
                write!(formatter, "malformed HYDRA stego carrier: {reason}")
            }
            Self::Model(reason) => write!(formatter, "cover-text model failed: {reason}"),
            Self::IntegrityMismatch => {
                formatter.write_str("HYDRA stego carrier integrity check failed")
            }
        }
    }
}

impl Error for StegoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stego_error_variant_has_stable_display_text() {
        let cases = [
            (
                StegoError::InvalidConfig("bad"),
                "invalid stego config: bad".to_owned(),
            ),
            (
                StegoError::PayloadTooLarge {
                    actual: 2,
                    maximum: 1,
                },
                "stego payload contains 2 bytes; configured maximum is 1".to_owned(),
            ),
            (
                StegoError::CoverTooLarge {
                    actual: 4,
                    maximum: 3,
                },
                "stego carrier contains 4 bytes; configured maximum is 3".to_owned(),
            ),
            (
                StegoError::ModelRequired,
                "selected stego profile requires a configured deterministic local model".to_owned(),
            ),
            (
                StegoError::NotCoverText,
                "text is not a HYDRA stego carrier".to_owned(),
            ),
            (
                StegoError::MalformedCoverText("bad"),
                "malformed HYDRA stego carrier: bad".to_owned(),
            ),
            (
                StegoError::Model("bad".to_owned()),
                "cover-text model failed: bad".to_owned(),
            ),
            (
                StegoError::IntegrityMismatch,
                "HYDRA stego carrier integrity check failed".to_owned(),
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }
}
