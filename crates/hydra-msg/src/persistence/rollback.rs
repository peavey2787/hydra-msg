use crate::{persistence::native_store::NativeStateStore, HydraMsgError, HydraResult};

/// Reject a locally replayed encrypted state file when the rollback guard has
/// observed a newer state generation on this device.
pub(crate) fn reject_state_rollback(
    store: &NativeStateStore,
    state_generation: u64,
) -> HydraResult<()> {
    let Some(text) = store.read_rollback_guard()? else {
        return Ok(());
    };
    let newest = text
        .trim()
        .parse::<u64>()
        .map_err(|_| HydraMsgError::InvalidEncoding("state rollback guard"))?;
    if state_generation < newest {
        return Err(HydraMsgError::InvalidEncoding("state rollback detected"));
    }
    Ok(())
}

pub(crate) fn write_rollback_guard(
    store: &NativeStateStore,
    state_generation: u64,
) -> HydraResult<()> {
    store.write_rollback_guard(state_generation)
}
