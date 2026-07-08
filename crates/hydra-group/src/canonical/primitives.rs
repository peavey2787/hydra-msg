use crate::{GroupError, GroupResult, MemberId};

#[must_use]
pub fn u16_be(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

#[must_use]
pub fn u32_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

#[must_use]
pub fn u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn checked_u16_be(value: usize) -> GroupResult<[u8; 2]> {
    let value = u16::try_from(value).map_err(|_| GroupError::InvalidLength {
        field: "u16",
        actual: value,
        maximum: u16::MAX as usize,
    })?;
    Ok(value.to_be_bytes())
}

pub fn checked_u32_be(value: usize) -> GroupResult<[u8; 4]> {
    let value = u32::try_from(value).map_err(|_| GroupError::InvalidLength {
        field: "u32",
        actual: value,
        maximum: u32::MAX as usize,
    })?;
    Ok(value.to_be_bytes())
}

pub fn lp(value: &[u8]) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::with_capacity(4 + value.len());
    encoded.extend_from_slice(&checked_u32_be(value.len())?);
    encoded.extend_from_slice(value);
    Ok(encoded)
}

pub(super) fn is_strictly_ordered_member_ids(ids: &[MemberId]) -> bool {
    ids.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefixed_and_integer_encoders_are_big_endian_and_checked() {
        assert_eq!(u16_be(0x0102), [0x01, 0x02]);
        assert_eq!(u32_be(0x0102_0304), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            u64_be(0x0102_0304_0506_0708),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(lp(b"abc").unwrap(), b"\0\0\0\x03abc".to_vec());
        assert_eq!(checked_u16_be(u16::MAX as usize).unwrap(), [0xff, 0xff]);
        assert!(checked_u16_be(u16::MAX as usize + 1).is_err());
    }
}
