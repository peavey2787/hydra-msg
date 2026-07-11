use crate::{HydraMsgError, HydraResult};
use getrandom::SysRng;
use rand_core::TryRng;

pub(crate) struct BytesReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BytesReader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn expect(&mut self, expected: &[u8]) -> HydraResult<()> {
        let got = self.read(expected.len())?;
        if got == expected {
            Ok(())
        } else {
            Err(HydraMsgError::InvalidEncoding("payload magic"))
        }
    }

    pub(crate) fn read(&mut self, len: usize) -> HydraResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(HydraMsgError::InvalidEncoding("length overflow"))?;
        if end > self.bytes.len() {
            return Err(HydraMsgError::InvalidEncoding("truncated payload"));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    pub(crate) fn read_vec(&mut self, len: usize) -> HydraResult<Vec<u8>> {
        Ok(self.read(len)?.to_vec())
    }

    pub(crate) fn read_u8(&mut self) -> HydraResult<u8> {
        Ok(*self
            .read(1)?
            .first()
            .ok_or(HydraMsgError::InvalidEncoding("u8"))?)
    }

    pub(crate) fn read_u32(&mut self) -> HydraResult<u32> {
        Ok(u32::from_be_bytes(exact_array_from_vec(
            self.read(4)?.to_vec(),
        )?))
    }

    pub(crate) fn read_u64(&mut self) -> HydraResult<u64> {
        Ok(u64::from_be_bytes(exact_array_from_vec(
            self.read(8)?.to_vec(),
        )?))
    }

    pub(crate) const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

pub(crate) fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn random_array<const N: usize>() -> HydraResult<[u8; N]> {
    let mut out = [0_u8; N];
    SysRng
        .try_fill_bytes(&mut out)
        .map_err(|_| HydraMsgError::EntropyUnavailable)?;
    Ok(out)
}

pub(crate) fn exact_array_from_vec<const N: usize>(bytes: Vec<u8>) -> HydraResult<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| HydraMsgError::InvalidEncoding("array length"))
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn hex_decode(input: &str) -> HydraResult<Vec<u8>> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
        return Err(HydraMsgError::InvalidEncoding("hex length"));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_nibble(bytes[index])?;
        let low = hex_nibble(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Ok(out)
}

pub(crate) fn hex_nibble(byte: u8) -> HydraResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HydraMsgError::InvalidEncoding("hex character")),
    }
}
