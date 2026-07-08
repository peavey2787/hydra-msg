use hydra_core::{
    types::{ContentKind, EnvelopeClass},
    INNER_HEADER_SIZE,
};

use crate::WireError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedRecord {
    pub content_kind: ContentKind,
    pub session_or_group_id: [u8; 32],
    pub sender_id: [u8; 32],
    pub epoch: u64,
    pub state_version: u64,
    pub message_index: u64,
    pub content: Vec<u8>,
}

pub fn encode_protected_record(
    class: EnvelopeClass,
    record: &ProtectedRecord,
) -> Result<Vec<u8>, WireError> {
    if record.content.len() > class.max_content_size() {
        return Err(WireError::InvalidProtectedRecord);
    }

    let mut encoded = vec![0_u8; class.protected_record_size()];
    encoded[0] = record.content_kind as u8;
    encoded[4..36].copy_from_slice(&record.session_or_group_id);
    encoded[36..68].copy_from_slice(&record.sender_id);
    encoded[68..76].copy_from_slice(&record.epoch.to_be_bytes());
    encoded[76..84].copy_from_slice(&record.state_version.to_be_bytes());
    encoded[84..92].copy_from_slice(&record.message_index.to_be_bytes());
    encoded[92..96].copy_from_slice(
        &u32::try_from(record.content.len())
            .map_err(|_| WireError::InvalidProtectedRecord)?
            .to_be_bytes(),
    );
    encoded[INNER_HEADER_SIZE..INNER_HEADER_SIZE + record.content.len()]
        .copy_from_slice(&record.content);
    Ok(encoded)
}

pub fn decode_protected_record(
    class: EnvelopeClass,
    encoded: &[u8],
) -> Result<ProtectedRecord, WireError> {
    if encoded.len() != class.protected_record_size() {
        return Err(WireError::InvalidEnvelopeSize {
            expected: class.protected_record_size(),
            actual: encoded.len(),
        });
    }

    let content_kind =
        ContentKind::try_from(encoded[0]).map_err(|_| WireError::InvalidProtectedRecord)?;
    if encoded[1..4].iter().any(|byte| *byte != 0) {
        return Err(WireError::InvalidProtectedRecord);
    }

    let content_len = u32::from_be_bytes(
        encoded[92..96]
            .try_into()
            .map_err(|_| WireError::InvalidProtectedRecord)?,
    ) as usize;
    let content_end = INNER_HEADER_SIZE
        .checked_add(content_len)
        .ok_or(WireError::InvalidProtectedRecord)?;
    if content_len > class.max_content_size()
        || content_end > encoded.len()
        || encoded[content_end..].iter().any(|byte| *byte != 0)
    {
        return Err(WireError::InvalidProtectedRecord);
    }

    Ok(ProtectedRecord {
        content_kind,
        session_or_group_id: encoded[4..36]
            .try_into()
            .map_err(|_| WireError::InvalidProtectedRecord)?,
        sender_id: encoded[36..68]
            .try_into()
            .map_err(|_| WireError::InvalidProtectedRecord)?,
        epoch: u64::from_be_bytes(
            encoded[68..76]
                .try_into()
                .map_err(|_| WireError::InvalidProtectedRecord)?,
        ),
        state_version: u64::from_be_bytes(
            encoded[76..84]
                .try_into()
                .map_err(|_| WireError::InvalidProtectedRecord)?,
        ),
        message_index: u64::from_be_bytes(
            encoded[84..92]
                .try_into()
                .map_err(|_| WireError::InvalidProtectedRecord)?,
        ),
        content: encoded[INNER_HEADER_SIZE..content_end].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> ProtectedRecord {
        ProtectedRecord {
            content_kind: ContentKind::Data,
            session_or_group_id: [0x11; 32],
            sender_id: [0; 32],
            epoch: 0,
            state_version: 0,
            message_index: 7,
            content: b"hello".to_vec(),
        }
    }

    #[test]
    fn protected_record_round_trips_in_every_class() {
        for class in [
            EnvelopeClass::Lite,
            EnvelopeClass::Standard,
            EnvelopeClass::Full,
        ] {
            let encoded = encode_protected_record(class, &record()).unwrap();
            assert_eq!(encoded.len(), class.protected_record_size());
            assert_eq!(decode_protected_record(class, &encoded), Ok(record()));
        }
    }

    #[test]
    fn rejects_wrong_length_unknown_kind_reserved_bytes_and_padding() {
        let class = EnvelopeClass::Lite;
        let encoded = encode_protected_record(class, &record()).unwrap();

        assert!(matches!(
            decode_protected_record(class, &encoded[..encoded.len() - 1]),
            Err(WireError::InvalidEnvelopeSize { .. })
        ));
        for (offset, value) in [(0, 0xff), (1, 1), (2, 1), (3, 1)] {
            let mut malformed = encoded.clone();
            malformed[offset] = value;
            assert_eq!(
                decode_protected_record(class, &malformed),
                Err(WireError::InvalidProtectedRecord)
            );
        }
        let mut malformed = encoded;
        *malformed.last_mut().unwrap() = 1;
        assert_eq!(
            decode_protected_record(class, &malformed),
            Err(WireError::InvalidProtectedRecord)
        );
    }

    #[test]
    fn rejects_content_beyond_class_capacity() {
        let mut oversized = record();
        oversized.content = vec![0; EnvelopeClass::Lite.max_content_size() + 1];
        assert_eq!(
            encode_protected_record(EnvelopeClass::Lite, &oversized),
            Err(WireError::InvalidProtectedRecord)
        );
    }

    #[test]
    fn every_class_capacity_is_inclusive_at_its_boundary() {
        for class in [
            EnvelopeClass::Lite,
            EnvelopeClass::Standard,
            EnvelopeClass::Full,
        ] {
            let maximum = class.max_content_size();
            for length in [maximum - 1, maximum] {
                let mut candidate = record();
                candidate.content = vec![0xa5; length];
                let encoded = encode_protected_record(class, &candidate).unwrap();
                assert_eq!(
                    decode_protected_record(class, &encoded)
                        .unwrap()
                        .content
                        .len(),
                    length
                );
            }
            let mut rejected = record();
            rejected.content = vec![0xa5; maximum + 1];
            assert_eq!(
                encode_protected_record(class, &rejected),
                Err(WireError::InvalidProtectedRecord)
            );
        }
    }
}
