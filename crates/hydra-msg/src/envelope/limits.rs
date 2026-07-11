use crate::{Hydra, HydraMsgError, HydraResult};
use hydra_core::types::EnvelopeClass;
#[cfg(test)]
use hydra_core::{
    FULL_ENVELOPE_SIZE, FULL_MAX_CONTENT_SIZE, LITE_ENVELOPE_SIZE, LITE_MAX_CONTENT_SIZE,
    STANDARD_ENVELOPE_SIZE, STANDARD_MAX_CONTENT_SIZE,
};

/// Default app-visible transport packet ceiling.
///
/// HYDRA v1 uses fixed padded envelope classes. A 56 KiB app packet cap maps
/// to Standard envelopes internally because Standard is the largest HYDRA v1
/// envelope class that fits under this ceiling.
pub(crate) const DEFAULT_PACKET_SIZE: usize = 56 * 1024;

impl Hydra {
    /// Sets the maximum app-visible HYDRA packet size for future sends and
    /// receive-side packet validation.
    ///
    /// Apps transport each opaque packet returned by `send()` independently.
    /// HYDRA chooses the largest fixed v1 envelope class that fits under this
    /// cap and internally splits larger messages across multiple packets.
    pub fn set_packet_size(&mut self, bytes: usize) -> HydraResult<()> {
        validate_packet_size(bytes)?;
        self.packet_size = bytes;
        Ok(())
    }

    #[must_use]
    pub const fn packet_size(&self) -> usize {
        self.packet_size
    }

    pub(crate) fn envelope_size_bounds(&self) -> HydraResult<(usize, usize)> {
        let class = selected_packet_class(self.packet_size)?;
        let envelope_size = class.envelope_size();
        Ok((envelope_size, envelope_size))
    }

    pub(crate) fn max_payload_content_size(&self) -> HydraResult<usize> {
        Ok(selected_packet_class(self.packet_size)?.max_content_size())
    }

    pub(crate) fn validate_inbound_envelope_size(&self, len: usize) -> HydraResult<()> {
        let valid_fixed_size = [
            EnvelopeClass::Lite,
            EnvelopeClass::Standard,
            EnvelopeClass::Full,
        ]
        .into_iter()
        .any(|class| class.envelope_size() == len && len <= self.packet_size);
        if !valid_fixed_size {
            return Err(HydraMsgError::InvalidInput(
                "inbound packet is not an allowed fixed HYDRA envelope size",
            ));
        }
        Ok(())
    }
}

fn validate_packet_size(bytes: usize) -> HydraResult<()> {
    selected_packet_class(bytes).map(|_| ())
}

fn selected_packet_class(packet_size: usize) -> HydraResult<EnvelopeClass> {
    largest_class_at_or_below(packet_size).ok_or(HydraMsgError::InvalidInput(
        "packet size is smaller than the HYDRA Lite envelope",
    ))
}

fn largest_class_at_or_below(packet_size: usize) -> Option<EnvelopeClass> {
    [
        EnvelopeClass::Full,
        EnvelopeClass::Standard,
        EnvelopeClass::Lite,
    ]
    .into_iter()
    .find(|class| class.envelope_size() <= packet_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_size_56k_maps_to_standard_capacity() {
        assert_eq!(
            selected_packet_class(56 * 1024).unwrap(),
            EnvelopeClass::Standard
        );
        assert_eq!(
            selected_packet_class(56 * 1024).unwrap().max_content_size(),
            STANDARD_MAX_CONTENT_SIZE
        );
    }

    #[test]
    fn packet_size_selects_fixed_padded_class() {
        assert_eq!(
            selected_packet_class(LITE_ENVELOPE_SIZE).unwrap(),
            EnvelopeClass::Lite
        );
        assert_eq!(
            selected_packet_class(STANDARD_ENVELOPE_SIZE).unwrap(),
            EnvelopeClass::Standard
        );
        assert_eq!(
            selected_packet_class(FULL_ENVELOPE_SIZE).unwrap(),
            EnvelopeClass::Full
        );
        assert_eq!(
            LITE_MAX_CONTENT_SIZE,
            EnvelopeClass::Lite.max_content_size()
        );
        assert_eq!(
            FULL_MAX_CONTENT_SIZE,
            EnvelopeClass::Full.max_content_size()
        );
    }

    #[test]
    fn packet_size_rejects_values_below_lite() {
        assert!(selected_packet_class(LITE_ENVELOPE_SIZE - 1).is_err());
    }
}
