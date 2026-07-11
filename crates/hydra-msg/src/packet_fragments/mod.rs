use crate::{ContactId, Hydra, HydraResult, LobbyId};

mod outbound;
mod reassembly;
mod records;
#[cfg(test)]
mod tests;

pub(crate) use reassembly::{PendingFragmentKey, PendingInboundFragments};
pub(crate) use records::{FragmentKind, FragmentScope};

impl Hydra {
    pub(crate) fn payloads_for_packets(
        &self,
        scope: FragmentScope,
        payload: &[u8],
    ) -> HydraResult<Vec<Vec<u8>>> {
        outbound::split_payload_for_packets(scope, payload, self.max_payload_content_size()?)
    }

    pub(crate) fn receive_fragmented_payload(
        &mut self,
        from: ContactId,
        kind: FragmentKind,
        payload: &[u8],
    ) -> HydraResult<Option<(Vec<u8>, Option<LobbyId>)>> {
        let Some(part) = records::decode_fragment_record(payload)? else {
            return Ok(Some((payload.to_vec(), None)));
        };
        Ok(
            reassembly::apply_fragment_record(&mut self.pending_fragments, from, kind, part)?
                .map(|completed| (completed.bytes, completed.lobby_id)),
        )
    }
}

pub(crate) fn is_packet_fragment_for_kind(kind: FragmentKind, payload: &[u8]) -> bool {
    matches!(records::decode_fragment_record(payload), Ok(Some(part)) if part.kind == kind)
}
