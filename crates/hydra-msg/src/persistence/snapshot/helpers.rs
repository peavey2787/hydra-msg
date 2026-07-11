use crate::{limits::MAX_STATE_SNAPSHOT_BYTES, HydraMsgError, HydraResult, STATE_SNAPSHOT_MAGIC};

const MAX_STATE_SNAPSHOT_LINE_BYTES: usize = MAX_STATE_SNAPSHOT_BYTES;

pub(super) fn append_snapshot_line(out: &mut Vec<u8>, line: &str) -> HydraResult<()> {
    if line.len() > MAX_STATE_SNAPSHOT_LINE_BYTES {
        return Err(HydraMsgError::InvalidInput("state snapshot line length"));
    }
    append_snapshot_bytes(out, line.as_bytes())?;
    append_snapshot_bytes(out, b"\n")
}

pub(super) fn append_snapshot_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> HydraResult<()> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|total| total > MAX_STATE_SNAPSHOT_BYTES)
    {
        return Err(HydraMsgError::InvalidInput("state snapshot size"));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn state_snapshot_text(bytes: &[u8]) -> HydraResult<&str> {
    if bytes.len() > MAX_STATE_SNAPSHOT_BYTES {
        return Err(HydraMsgError::InvalidEncoding("state snapshot size"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("state snapshot utf-8"))?;
    if !text.starts_with(std::str::from_utf8(STATE_SNAPSHOT_MAGIC).unwrap_or_default()) {
        return Err(HydraMsgError::InvalidEncoding("state snapshot magic"));
    }
    for line in text.lines() {
        if line.len() > MAX_STATE_SNAPSHOT_LINE_BYTES {
            return Err(HydraMsgError::InvalidEncoding("state snapshot line length"));
        }
    }
    Ok(text)
}

pub(super) fn required_snapshot_value<'a>(
    value: Option<&'a str>,
    description: &'static str,
) -> HydraResult<&'a str> {
    value.ok_or(HydraMsgError::InvalidEncoding(description))
}

pub(super) fn reject_extra_snapshot_fields(
    value: Option<&str>,
    description: &'static str,
) -> HydraResult<()> {
    if value.is_some() {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(super) fn reject_duplicate_scalar(
    saw_record: bool,
    description: &'static str,
) -> HydraResult<()> {
    if saw_record {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(super) fn reject_collection_limit(
    current_count: usize,
    max_count: usize,
    description: &'static str,
) -> HydraResult<()> {
    if current_count >= max_count {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(super) fn reject_runtime_collection_size(
    current_count: usize,
    max_count: usize,
    description: &'static str,
) -> HydraResult<()> {
    if current_count > max_count {
        return Err(HydraMsgError::InvalidInput(description));
    }
    Ok(())
}

pub(super) fn reject_duplicate_collection_record(
    inserted: bool,
    description: &'static str,
) -> HydraResult<()> {
    if !inserted {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}
