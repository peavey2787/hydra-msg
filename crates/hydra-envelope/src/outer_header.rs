use core::fmt;

use hydra_core::{
    constants::{MAGIC, OUTER_HEADER_SIZE, PROTOCOL_VERSION, ROUTE_TAG_SIZE, SUITE_ID},
    types::{EnvelopeClass, OuterMode},
};

const MAGIC_RANGE: core::ops::Range<usize> = 0..4;
const VERSION_OFFSET: usize = 4;
const MODE_OFFSET: usize = 5;
const CLASS_OFFSET: usize = 6;
const FLAGS_OFFSET: usize = 7;
const SUITE_RANGE: core::ops::Range<usize> = 8..24;
const ROUTE_TAG_RANGE: core::ops::Range<usize> = 24..40;
const COUNTER_RANGE: core::ops::Range<usize> = 40..48;
const RESERVED_RANGE: core::ops::Range<usize> = 48..64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OuterHeader {
    pub mode: OuterMode,
    pub envelope_class: EnvelopeClass,
    pub suite_id: [u8; 16],
    pub route_tag: [u8; ROUTE_TAG_SIZE],
    pub counter: u64,
}

impl OuterHeader {
    #[must_use]
    pub const fn new(
        mode: OuterMode,
        envelope_class: EnvelopeClass,
        route_tag: [u8; ROUTE_TAG_SIZE],
        counter: u64,
    ) -> Self {
        Self {
            mode,
            envelope_class,
            suite_id: SUITE_ID,
            route_tag,
            counter,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    InvalidEnvelopeSize { expected: usize, actual: usize },
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidMode(u8),
    InvalidEnvelopeClass(u8),
    UnsupportedSuite([u8; 16]),
    NonZeroReserved,
    InvalidProtectedRecord,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelopeSize { expected, actual } => {
                write!(
                    f,
                    "invalid envelope size: expected {expected}, got {actual}"
                )
            }
            Self::InvalidMagic => f.write_str("invalid HYDRA-MSG magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported protocol version 0x{version:02x}")
            }
            Self::InvalidMode(mode) => write!(f, "invalid outer mode 0x{mode:02x}"),
            Self::InvalidEnvelopeClass(class) => {
                write!(f, "invalid envelope class 0x{class:02x}")
            }
            Self::UnsupportedSuite(_) => f.write_str("unsupported suite identifier"),
            Self::NonZeroReserved => {
                f.write_str("outer flags and reserved header bytes must be zero")
            }
            Self::InvalidProtectedRecord => f.write_str("invalid protected record"),
        }
    }
}

impl std::error::Error for WireError {}

/// Encodes one canonical 64-byte outer header.
///
/// The single v1 suite is checked even though callers should normally use
/// [`OuterHeader::new`], preventing an encoder from emitting negotiation data.
pub fn encode_outer_header(header: &OuterHeader) -> Result<[u8; OUTER_HEADER_SIZE], WireError> {
    if header.suite_id != SUITE_ID {
        return Err(WireError::UnsupportedSuite(header.suite_id));
    }

    let mut encoded = [0_u8; OUTER_HEADER_SIZE];
    encoded[MAGIC_RANGE].copy_from_slice(&MAGIC);
    encoded[VERSION_OFFSET] = PROTOCOL_VERSION;
    encoded[MODE_OFFSET] = header.mode as u8;
    encoded[CLASS_OFFSET] = header.envelope_class as u8;
    encoded[FLAGS_OFFSET] = 0;
    encoded[SUITE_RANGE].copy_from_slice(&header.suite_id);
    encoded[ROUTE_TAG_RANGE].copy_from_slice(&header.route_tag);
    encoded[COUNTER_RANGE].copy_from_slice(&header.counter.to_be_bytes());
    // RESERVED_RANGE remains zero.
    Ok(encoded)
}

/// Decodes a header from a complete fixed-class envelope.
///
/// No body byte is interpreted. The complete input length must exactly match
/// the authenticated class selected by byte 6.
pub fn decode_outer_header(envelope: &[u8]) -> Result<OuterHeader, WireError> {
    if envelope.len() < OUTER_HEADER_SIZE {
        return Err(WireError::InvalidEnvelopeSize {
            expected: OUTER_HEADER_SIZE,
            actual: envelope.len(),
        });
    }

    if envelope[MAGIC_RANGE] != MAGIC {
        return Err(WireError::InvalidMagic);
    }

    let version = envelope[VERSION_OFFSET];
    if version != PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }

    let mode_byte = envelope[MODE_OFFSET];
    let mode = OuterMode::try_from(mode_byte).map_err(|_| WireError::InvalidMode(mode_byte))?;

    let class_byte = envelope[CLASS_OFFSET];
    let envelope_class = EnvelopeClass::try_from(class_byte)
        .map_err(|_| WireError::InvalidEnvelopeClass(class_byte))?;

    let flags = envelope[FLAGS_OFFSET];
    if flags != 0 {
        return Err(WireError::NonZeroReserved);
    }

    let mut suite_id = [0_u8; 16];
    suite_id.copy_from_slice(&envelope[SUITE_RANGE]);
    if suite_id != SUITE_ID {
        return Err(WireError::UnsupportedSuite(suite_id));
    }

    if envelope[RESERVED_RANGE].iter().any(|&byte| byte != 0) {
        return Err(WireError::NonZeroReserved);
    }

    validate_envelope_length(envelope_class, envelope.len())?;

    let mut route_tag = [0_u8; ROUTE_TAG_SIZE];
    route_tag.copy_from_slice(&envelope[ROUTE_TAG_RANGE]);

    let mut counter_bytes = [0_u8; 8];
    counter_bytes.copy_from_slice(&envelope[COUNTER_RANGE]);

    Ok(OuterHeader {
        mode,
        envelope_class,
        suite_id,
        route_tag,
        counter: u64::from_be_bytes(counter_bytes),
    })
}

pub fn validate_envelope_length(
    envelope_class: EnvelopeClass,
    actual: usize,
) -> Result<(), WireError> {
    let expected = envelope_class.envelope_size();
    if actual != expected {
        return Err(WireError::InvalidEnvelopeSize { expected, actual });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_test_header() -> OuterHeader {
        OuterHeader::new(
            OuterMode::Protected,
            EnvelopeClass::Full,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            0x0102_0304_0506_0708,
        )
    }

    fn envelope_for(header: &OuterHeader) -> Vec<u8> {
        let mut envelope = vec![0_u8; header.envelope_class.envelope_size()];
        envelope[..OUTER_HEADER_SIZE]
            .copy_from_slice(&encode_outer_header(header).expect("the test header is supported"));
        envelope
    }

    #[test]
    fn canonical_header_matches_tv_hdr_000() {
        let encoded = encode_outer_header(&full_test_header()).unwrap();
        let expected = [
            0x48, 0x59, 0x44, 0x31, 0x01, 0x03, 0x03, 0x00, 0x48, 0x59, 0x44, 0x52, 0x41, 0x31,
            0x2d, 0x4d, 0x4b, 0x37, 0x36, 0x38, 0x2d, 0x4d, 0x36, 0x35, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(encoded, expected);

        let envelope = envelope_for(&full_test_header());
        assert_eq!(decode_outer_header(&envelope), Ok(full_test_header()));
    }

    #[test]
    fn rejects_every_invalid_fixed_header_field() {
        let original = envelope_for(&full_test_header());
        let cases = [
            (0, 0x49, WireError::InvalidMagic),
            (4, 0x02, WireError::UnsupportedVersion(0x02)),
            (5, 0xff, WireError::InvalidMode(0xff)),
            (6, 0x00, WireError::InvalidEnvelopeClass(0x00)),
            (6, 0xff, WireError::InvalidEnvelopeClass(0xff)),
            (7, 0x01, WireError::NonZeroReserved),
            (
                8,
                0x49,
                WireError::UnsupportedSuite([
                    0x49, 0x59, 0x44, 0x52, 0x41, 0x31, 0x2d, 0x4d, 0x4b, 0x37, 0x36, 0x38, 0x2d,
                    0x4d, 0x36, 0x35,
                ]),
            ),
            (48, 0x01, WireError::NonZeroReserved),
            (63, 0x01, WireError::NonZeroReserved),
        ];

        for (offset, value, expected) in cases {
            let mut mutated = original.clone();
            mutated[offset] = value;
            assert_eq!(decode_outer_header(&mutated), Err(expected));
        }
    }

    #[test]
    fn rejects_wrong_total_length_for_every_class() {
        for class in [
            EnvelopeClass::Lite,
            EnvelopeClass::Standard,
            EnvelopeClass::Full,
        ] {
            let header = OuterHeader::new(OuterMode::Protected, class, [0_u8; 16], 0);
            let exact = envelope_for(&header);
            assert_eq!(decode_outer_header(&exact), Ok(header.clone()));

            for actual in [class.envelope_size() - 1, class.envelope_size() + 1] {
                let mut wrong = exact.clone();
                wrong.resize(actual, 0);
                assert_eq!(
                    decode_outer_header(&wrong),
                    Err(WireError::InvalidEnvelopeSize {
                        expected: class.envelope_size(),
                        actual,
                    })
                );
            }
        }
    }

    #[test]
    fn rejects_a_truncated_header_without_indexing_it() {
        assert_eq!(
            decode_outer_header(&[0_u8; OUTER_HEADER_SIZE - 1]),
            Err(WireError::InvalidEnvelopeSize {
                expected: OUTER_HEADER_SIZE,
                actual: OUTER_HEADER_SIZE - 1,
            })
        );
    }

    #[test]
    fn encoder_rejects_an_unsupported_suite() {
        let mut header = full_test_header();
        header.suite_id[0] ^= 1;
        assert!(matches!(
            encode_outer_header(&header),
            Err(WireError::UnsupportedSuite(_))
        ));
    }
}
