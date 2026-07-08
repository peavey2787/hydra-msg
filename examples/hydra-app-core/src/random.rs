use getrandom::SysRng;
use rand_core::TryRng;

use crate::{AppError, AppResult};

pub(crate) fn random_array<const N: usize>() -> AppResult<[u8; N]> {
    let mut bytes = [0_u8; N];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AppError::EntropyUnavailable)?;
    Ok(bytes)
}
