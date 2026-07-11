use super::records::{self, FragmentScope};
use crate::{
    codec::random_array,
    limits::{MAX_FRAGMENTED_PAYLOAD_BYTES, MAX_FRAGMENTS_PER_MESSAGE},
    HydraMsgError, HydraResult,
};

pub(super) fn split_payload_for_packets(
    scope: FragmentScope,
    payload: &[u8],
    max_payload_size: usize,
) -> HydraResult<Vec<Vec<u8>>> {
    if payload.len() > MAX_FRAGMENTED_PAYLOAD_BYTES {
        return Err(HydraMsgError::InvalidInput("fragmented payload size"));
    }
    if !records::payload_needs_fragment_record(payload, max_payload_size) {
        return Ok(vec![payload.to_vec()]);
    }
    let part_size = fragment_payload_size(scope, max_payload_size)?;
    let total = payload.len().div_ceil(part_size).max(1);
    if total > MAX_FRAGMENTS_PER_MESSAGE || total > u32::MAX as usize {
        return Err(HydraMsgError::InvalidInput(
            "message requires too many packet fragments",
        ));
    }
    let fragment_id = random_array::<32>()?;
    let mut records_out = Vec::with_capacity(total);
    for index in 0..total {
        let start = index * part_size;
        let end = payload.len().min(start + part_size);
        records_out.push(records::encode_fragment_record(
            scope,
            fragment_id,
            total as u32,
            index as u32,
            &payload[start..end],
        ));
    }
    Ok(records_out)
}

fn fragment_payload_size(scope: FragmentScope, max_payload_size: usize) -> HydraResult<usize> {
    max_payload_size
        .checked_sub(records::fragment_header_bytes(scope))
        .filter(|size| *size > 0)
        .ok_or(HydraMsgError::InvalidInput(
            "configured envelope size cannot carry HYDRA fragment records",
        ))
}
