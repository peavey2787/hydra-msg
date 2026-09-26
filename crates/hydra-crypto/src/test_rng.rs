//! Test-only entropy source that always fails, for RNG-failure paths.

use core::fmt;
use rand_core::{TryCryptoRng, TryRng};

#[derive(Debug)]
pub(crate) struct EntropyDown;

impl fmt::Display for EntropyDown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("test entropy source unavailable")
    }
}

impl core::error::Error for EntropyDown {}

pub(crate) struct FailingRng;

impl TryRng for FailingRng {
    type Error = EntropyDown;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(EntropyDown)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(EntropyDown)
    }

    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
        Err(EntropyDown)
    }
}

impl TryCryptoRng for FailingRng {}
