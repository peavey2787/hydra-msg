use hydra_core::types::EnvelopeClass;

pub(super) fn smallest_class(content_length: usize) -> Option<EnvelopeClass> {
    [
        EnvelopeClass::Lite,
        EnvelopeClass::Standard,
        EnvelopeClass::Full,
    ]
    .into_iter()
    .find(|class| content_length <= class.max_content_size())
}

pub(super) fn smallest_standard_or_full(content_length: usize) -> Option<EnvelopeClass> {
    [EnvelopeClass::Standard, EnvelopeClass::Full]
        .into_iter()
        .find(|class| content_length <= class.max_content_size())
}

pub(super) fn bounded_data_class(
    content_length: usize,
    min_envelope_size: usize,
    max_envelope_size: usize,
) -> Option<EnvelopeClass> {
    [
        EnvelopeClass::Lite,
        EnvelopeClass::Standard,
        EnvelopeClass::Full,
    ]
    .into_iter()
    .find(|class| {
        content_length <= class.max_content_size()
            && class.envelope_size() >= min_envelope_size
            && class.envelope_size() <= max_envelope_size
    })
}
