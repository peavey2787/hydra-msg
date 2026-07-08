//! Closed v1 envelope discriminants.

use core::fmt;

/// A byte is not assigned by the closed v1 wire enum being decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownDiscriminant {
    pub type_name: &'static str,
    pub value: u8,
}

impl fmt::Display for UnknownDiscriminant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown {} discriminant 0x{:02x}",
            self.type_name, self.value
        )
    }
}

impl std::error::Error for UnknownDiscriminant {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeClass {
    Lite = 0x01,
    Standard = 0x02,
    Full = 0x03,
}

impl EnvelopeClass {
    #[must_use]
    pub const fn envelope_size(self) -> usize {
        match self {
            Self::Lite => crate::LITE_ENVELOPE_SIZE,
            Self::Standard => crate::STANDARD_ENVELOPE_SIZE,
            Self::Full => crate::FULL_ENVELOPE_SIZE,
        }
    }

    #[must_use]
    pub const fn body_size(self) -> usize {
        self.envelope_size() - crate::OUTER_HEADER_SIZE
    }

    #[must_use]
    pub const fn protected_record_size(self) -> usize {
        self.body_size() - crate::AEAD_TAG_SIZE
    }

    #[must_use]
    pub const fn max_content_size(self) -> usize {
        self.protected_record_size() - crate::INNER_HEADER_SIZE
    }
}

impl TryFrom<u8> for EnvelopeClass {
    type Error = UnknownDiscriminant;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Lite),
            0x02 => Ok(Self::Standard),
            0x03 => Ok(Self::Full),
            _ => Err(UnknownDiscriminant {
                type_name: "EnvelopeClass",
                value,
            }),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OuterMode {
    BootstrapInit = 0x01,
    BootstrapResp = 0x02,
    Protected = 0x03,
}

impl TryFrom<u8> for OuterMode {
    type Error = UnknownDiscriminant;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::BootstrapInit),
            0x02 => Ok(Self::BootstrapResp),
            0x03 => Ok(Self::Protected),
            _ => Err(UnknownDiscriminant {
                type_name: "OuterMode",
                value,
            }),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentKind {
    HandshakeFinish = 0x01,
    Data = 0x02,
    RefreshInit = 0x03,
    RefreshResp = 0x04,
    RefreshFinish = 0x05,
    Close = 0x06,
    GroupCommit = 0x10,
    GroupWelcome = 0x11,
    GroupData = 0x12,
    IdentityRotation = 0x20,
    DeviceRevocation = 0x21,
}

impl TryFrom<u8> for ContentKind {
    type Error = UnknownDiscriminant;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::HandshakeFinish),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::RefreshInit),
            0x04 => Ok(Self::RefreshResp),
            0x05 => Ok(Self::RefreshFinish),
            0x06 => Ok(Self::Close),
            0x10 => Ok(Self::GroupCommit),
            0x11 => Ok(Self::GroupWelcome),
            0x12 => Ok(Self::GroupData),
            0x20 => Ok(Self::IdentityRotation),
            0x21 => Ok(Self::DeviceRevocation),
            _ => Err(UnknownDiscriminant {
                type_name: "ContentKind",
                value,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_class_arithmetic_matches_the_specification() {
        let expected = [
            (EnvelopeClass::Lite, 4_096, 4_032, 4_016, 3_920),
            (EnvelopeClass::Standard, 32_768, 32_704, 32_688, 32_592),
            (EnvelopeClass::Full, 147_456, 147_392, 147_376, 147_280),
        ];

        for (class, envelope, body, record, content) in expected {
            assert_eq!(class.envelope_size(), envelope);
            assert_eq!(class.body_size(), body);
            assert_eq!(class.protected_record_size(), record);
            assert_eq!(class.max_content_size(), content);
            assert_eq!(EnvelopeClass::try_from(class as u8), Ok(class));
        }
    }

    #[test]
    fn closed_enums_reject_unassigned_values() {
        for value in [0x00, 0x04, 0xff] {
            assert!(EnvelopeClass::try_from(value).is_err());
            assert!(OuterMode::try_from(value).is_err());
        }

        for value in [0x00, 0x07, 0x0f, 0x13, 0x1f, 0x22, 0xff] {
            assert!(ContentKind::try_from(value).is_err());
        }
    }

    #[test]
    fn every_assigned_content_kind_round_trips() {
        let kinds = [
            ContentKind::HandshakeFinish,
            ContentKind::Data,
            ContentKind::RefreshInit,
            ContentKind::RefreshResp,
            ContentKind::RefreshFinish,
            ContentKind::Close,
            ContentKind::GroupCommit,
            ContentKind::GroupWelcome,
            ContentKind::GroupData,
            ContentKind::IdentityRotation,
            ContentKind::DeviceRevocation,
        ];

        for kind in kinds {
            assert_eq!(ContentKind::try_from(kind as u8), Ok(kind));
        }
    }

    #[test]
    fn every_assigned_outer_mode_round_trips() {
        let modes = [
            OuterMode::BootstrapInit,
            OuterMode::BootstrapResp,
            OuterMode::Protected,
        ];

        for mode in modes {
            assert_eq!(OuterMode::try_from(mode as u8), Ok(mode));
        }
    }
}
