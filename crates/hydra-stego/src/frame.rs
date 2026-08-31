use crate::StegoError;

const MAGIC: [u8; 4] = *b"HSTG";
const VERSION: u8 = 1;
const HEADER_LEN: usize = MAGIC.len() + 1 + 4 + 4;
const SEED_LEN: usize = 4;

pub(crate) const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
pub(crate) const ENCODED_OVERHEAD_BYTES: usize = SEED_LEN + HEADER_LEN;

pub(crate) const fn minimum_encoded_len() -> usize {
    SEED_LEN + HEADER_LEN
}

pub(crate) fn encode(payload: &[u8]) -> Result<Vec<u8>, StegoError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(StegoError::PayloadTooLarge {
            actual: payload.len(),
            maximum: MAX_PAYLOAD_BYTES,
        });
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| StegoError::PayloadTooLarge {
        actual: payload.len(),
        maximum: MAX_PAYLOAD_BYTES,
    })?;
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&MAGIC);
    frame.push(VERSION);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&checksum(payload).to_be_bytes());
    frame.extend_from_slice(payload);

    // This public mask keeps the version/header from producing the same cover
    // prefix on every packet. It is format diversification, not encryption.
    let seed = mask_seed(payload, payload_len);
    let mut framed = Vec::with_capacity(SEED_LEN + frame.len());
    framed.extend_from_slice(&seed.to_be_bytes());
    framed.extend(mask(&frame, seed));
    Ok(framed)
}

pub(crate) fn expected_len(
    bytes: &[u8],
    maximum_payload_bytes: usize,
) -> Result<Option<usize>, StegoError> {
    if bytes.len() < SEED_LEN + HEADER_LEN {
        return Ok(None);
    }
    let seed = u32::from_be_bytes(
        bytes[..SEED_LEN]
            .try_into()
            .expect("fixed masking seed slice"),
    );
    let header = mask(&bytes[SEED_LEN..SEED_LEN + HEADER_LEN], seed);
    if header[..MAGIC.len()] != MAGIC {
        return Err(StegoError::NotCoverText);
    }
    if header[MAGIC.len()] != VERSION {
        return Err(StegoError::MalformedCoverText(
            "unsupported carrier version",
        ));
    }

    let length_offset = MAGIC.len() + 1;
    let length = u32::from_be_bytes(
        header[length_offset..length_offset + 4]
            .try_into()
            .expect("fixed frame length slice"),
    ) as usize;
    if length > maximum_payload_bytes {
        return Err(StegoError::PayloadTooLarge {
            actual: length,
            maximum: maximum_payload_bytes,
        });
    }
    Ok(Some(SEED_LEN + HEADER_LEN + length))
}

pub(crate) fn decode(bytes: &[u8], maximum_payload_bytes: usize) -> Result<Vec<u8>, StegoError> {
    let expected = expected_len(bytes, maximum_payload_bytes)?.ok_or(
        StegoError::MalformedCoverText("carrier ended before its frame header"),
    )?;
    if bytes.len() != expected {
        return Err(StegoError::MalformedCoverText(
            "carrier frame length does not match its contents",
        ));
    }

    let seed = u32::from_be_bytes(
        bytes[..SEED_LEN]
            .try_into()
            .expect("fixed masking seed slice"),
    );
    let frame = mask(&bytes[SEED_LEN..], seed);
    let checksum_offset = MAGIC.len() + 1 + 4;
    let expected_checksum = u32::from_be_bytes(
        frame[checksum_offset..checksum_offset + 4]
            .try_into()
            .expect("fixed checksum slice"),
    );
    let payload = &frame[HEADER_LEN..];
    if checksum(payload) != expected_checksum {
        return Err(StegoError::IntegrityMismatch);
    }
    Ok(payload.to_vec())
}

fn mask(bytes: &[u8], seed: u32) -> Vec<u8> {
    let mut state = seed;
    bytes
        .iter()
        .map(|byte| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            byte ^ state as u8
        })
        .collect()
}

fn mask_seed(payload: &[u8], payload_len: u32) -> u32 {
    let seed = checksum(payload) ^ payload_len.rotate_left(13) ^ 0x9e37_79b9;
    if seed == 0 {
        0xa341_316c
    } else {
        seed
    }
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_and_integrity_check() {
        let mut framed = encode(b"opaque packet").unwrap();
        assert_eq!(decode(&framed, 1024).unwrap(), b"opaque packet");

        *framed.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode(&framed, 1024).unwrap_err(),
            StegoError::IntegrityMismatch
        );
    }
}
