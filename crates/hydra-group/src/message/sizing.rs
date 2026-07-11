use hydra_core::{types::EnvelopeClass, ML_DSA_65_SIG_SIZE};

use crate::{GroupError, GroupMode, GroupResult};

pub(super) fn group_data_record_class_allowed(
    mode: GroupMode,
    record_content_len: usize,
    class: EnvelopeClass,
) -> bool {
    match mode {
        GroupMode::Interactive => {
            if record_content_len <= EnvelopeClass::Standard.max_content_size() {
                class == EnvelopeClass::Standard
            } else if record_content_len <= EnvelopeClass::Full.max_content_size() {
                class == EnvelopeClass::Full
            } else {
                false
            }
        }
        GroupMode::Broadcast => smallest_class(record_content_len) == Some(class),
        GroupMode::Lite => {
            class == EnvelopeClass::Lite
                && record_content_len <= EnvelopeClass::Lite.max_content_size()
        }
    }
}

pub(super) fn signed_group_data_content_len(application_content_len: usize) -> GroupResult<usize> {
    4_usize
        .checked_add(application_content_len)
        .and_then(|len| len.checked_add(ML_DSA_65_SIG_SIZE))
        .ok_or(GroupError::InvalidEnvelope)
}

pub(super) fn signed_group_data_class(
    mode: GroupMode,
    application_content_len: usize,
) -> Option<EnvelopeClass> {
    let signed_len = signed_group_data_content_len(application_content_len).ok()?;
    match mode {
        GroupMode::Lite => {
            if application_content_len <= 607
                && signed_len <= EnvelopeClass::Lite.max_content_size()
            {
                Some(EnvelopeClass::Lite)
            } else {
                None
            }
        }
        GroupMode::Interactive => {
            if signed_len <= EnvelopeClass::Standard.max_content_size() {
                Some(EnvelopeClass::Standard)
            } else if signed_len <= EnvelopeClass::Full.max_content_size() {
                Some(EnvelopeClass::Full)
            } else {
                None
            }
        }
        GroupMode::Broadcast => smallest_class(signed_len),
    }
}

pub(super) fn group_skip_bound(mode: GroupMode) -> u64 {
    match mode {
        GroupMode::Lite => 32,
        GroupMode::Interactive => 64,
        GroupMode::Broadcast => 256,
    }
}

pub(super) fn smallest_class(content_length: usize) -> Option<EnvelopeClass> {
    [
        EnvelopeClass::Lite,
        EnvelopeClass::Standard,
        EnvelopeClass::Full,
    ]
    .into_iter()
    .find(|class| content_length <= class.max_content_size())
}
