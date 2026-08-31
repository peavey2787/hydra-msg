use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::json;

const PEER_TTL: Duration = Duration::from_secs(45);
const MAX_PEERS: usize = 64;
const MAX_CONTACT_CARD_BYTES: usize = 32 * 1024;
const MAX_SIGNAL_BYTES: usize = 512 * 1024;

type BrokerResult<T> = Result<T, String>;

pub(crate) struct PeerBroker {
    state: Mutex<BrokerState>,
}

#[derive(Default)]
struct BrokerState {
    peers: HashMap<String, Peer>,
    next_order: u64,
}

struct Peer {
    contact_card: String,
    last_seen: Instant,
    order: u64,
    partner: Option<String>,
    role: Option<Role>,
    offer: Option<String>,
    answer: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Offer,
    Answer,
}

impl PeerBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(BrokerState::default()),
        }
    }

    pub(crate) fn join(&self, id: &str, contact_card: &[u8]) -> BrokerResult<String> {
        validate_id(id)?;
        if contact_card.is_empty() || contact_card.len() > MAX_CONTACT_CARD_BYTES {
            return Err("contact card has an invalid size".to_owned());
        }
        let contact_card = std::str::from_utf8(contact_card)
            .map_err(|_| "contact card is not UTF-8".to_owned())?;
        if !contact_card
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err("contact card is not canonical base64".to_owned());
        }

        {
            let mut state = self.lock()?;
            state.remove_stale();
            if !state.peers.contains_key(id) && state.peers.len() >= MAX_PEERS {
                return Err("LAN rendezvous is full".to_owned());
            }
            if let Some(previous) = state.peers.remove(id) {
                state.release_partner(previous.partner.as_deref());
            }
            let order = state.next_order;
            state.next_order = state.next_order.wrapping_add(1);
            state.peers.insert(
                id.to_owned(),
                Peer {
                    contact_card: contact_card.to_owned(),
                    last_seen: Instant::now(),
                    order,
                    partner: None,
                    role: None,
                    offer: None,
                    answer: None,
                },
            );
            state.pair_waiters();
        }
        self.status(id)
    }

    pub(crate) fn status(&self, id: &str) -> BrokerResult<String> {
        validate_id(id)?;
        let mut state = self.lock()?;
        state.remove_stale();
        state.pair_waiters();
        let peer_count = state.peers.len();
        let (partner_id, role, contact_card) = {
            let peer = state
                .peers
                .get_mut(id)
                .ok_or_else(|| "LAN rendezvous registration expired".to_owned())?;
            peer.last_seen = Instant::now();
            (peer.partner.clone(), peer.role, peer.contact_card.clone())
        };
        let Some(partner_id) = partner_id else {
            return Ok(format!(
                "{{\"state\":\"waiting\",\"peersSeen\":{},\"targetPeers\":1}}",
                peer_count.saturating_sub(1),
            ));
        };
        let partner = state
            .peers
            .get(&partner_id)
            .ok_or_else(|| "paired LAN peer disappeared".to_owned())?;
        let role = role.ok_or_else(|| "paired LAN peer has no role".to_owned())?;
        let offer = optional_json("offer", partner.offer.as_deref());
        let answer = optional_json("answer", partner.answer.as_deref());
        Ok(format!(
            "{{\"state\":\"paired\",\"peersSeen\":{},\"targetPeers\":1,\"role\":\"{}\",\"peerCard\":{}{}{},\"localCardBytes\":{}}}",
            peer_count.saturating_sub(1),
            match role {
                Role::Offer => "offer",
                Role::Answer => "answer",
            },
            json::string(&partner.contact_card),
            offer,
            answer,
            contact_card.len(),
        ))
    }

    pub(crate) fn signal(&self, id: &str, kind: &str, body: &[u8]) -> BrokerResult<String> {
        validate_id(id)?;
        if body.is_empty() || body.len() > MAX_SIGNAL_BYTES {
            return Err("WebRTC signal has an invalid size".to_owned());
        }
        let signal =
            std::str::from_utf8(body).map_err(|_| "WebRTC signal is not UTF-8".to_owned())?;
        if !signal
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err("WebRTC signal is not canonical base64".to_owned());
        }

        let mut state = self.lock()?;
        state.remove_stale();
        let peer = state
            .peers
            .get_mut(id)
            .ok_or_else(|| "LAN rendezvous registration expired".to_owned())?;
        if peer.partner.is_none() {
            return Err("LAN peer is not paired yet".to_owned());
        }
        match (kind, peer.role) {
            ("offer", Some(Role::Offer)) => peer.offer = Some(signal.to_owned()),
            ("answer", Some(Role::Answer)) => peer.answer = Some(signal.to_owned()),
            ("offer" | "answer", _) => {
                return Err("WebRTC signal does not match the assigned peer role".to_owned())
            }
            _ => return Err("unknown WebRTC signal kind".to_owned()),
        }
        peer.last_seen = Instant::now();
        Ok("{\"accepted\":true}".to_owned())
    }

    pub(crate) fn leave(&self, id: &str) -> BrokerResult<String> {
        validate_id(id)?;
        let mut state = self.lock()?;
        if let Some(peer) = state.peers.remove(id) {
            state.release_partner(peer.partner.as_deref());
        }
        state.pair_waiters();
        Ok("{\"removed\":true}".to_owned())
    }

    fn lock(&self) -> BrokerResult<std::sync::MutexGuard<'_, BrokerState>> {
        self.state
            .lock()
            .map_err(|_| "LAN rendezvous lock is poisoned".to_owned())
    }
}

impl BrokerState {
    fn remove_stale(&mut self) {
        let now = Instant::now();
        let stale = self
            .peers
            .iter()
            .filter(|(_, peer)| now.duration_since(peer.last_seen) > PEER_TTL)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in stale {
            if let Some(peer) = self.peers.remove(&id) {
                self.release_partner(peer.partner.as_deref());
            }
        }
    }

    fn release_partner(&mut self, partner_id: Option<&str>) {
        if let Some(partner) = partner_id.and_then(|id| self.peers.get_mut(id)) {
            partner.partner = None;
            partner.role = None;
            partner.offer = None;
            partner.answer = None;
        }
    }

    fn pair_waiters(&mut self) {
        let mut waiting = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.partner.is_none())
            .map(|(id, peer)| (peer.order, id.clone()))
            .collect::<Vec<_>>();
        waiting.sort_by_key(|(order, _)| *order);
        for pair in waiting.chunks_exact(2) {
            let offer_id = &pair[0].1;
            let answer_id = &pair[1].1;
            if let Some(offer) = self.peers.get_mut(offer_id) {
                offer.partner = Some(answer_id.clone());
                offer.role = Some(Role::Offer);
                offer.offer = None;
                offer.answer = None;
            }
            if let Some(answer) = self.peers.get_mut(answer_id) {
                answer.partner = Some(offer_id.clone());
                answer.role = Some(Role::Answer);
                answer.offer = None;
                answer.answer = None;
            }
        }
    }
}

fn validate_id(id: &str) -> BrokerResult<()> {
    if id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("LAN peer id must contain 32 hexadecimal characters".to_owned())
    }
}

fn optional_json(name: &str, value: Option<&str>) -> String {
    value.map_or_else(String::new, |value| {
        format!(",\"{name}\":{}", json::string(value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "00000000000000000000000000000001";
    const BOB: &str = "00000000000000000000000000000002";

    #[test]
    fn pairs_two_peers_and_relays_role_bound_signals() {
        let broker = PeerBroker::new();
        assert!(broker.join(ALICE, b"YWxpY2U=").unwrap().contains("waiting"));
        let bob = broker.join(BOB, b"Ym9i").unwrap();
        assert!(bob.contains("\"role\":\"answer\""));
        assert!(bob.contains("YWxpY2U="));

        broker.signal(ALICE, "offer", b"b2ZmZXI=").unwrap();
        assert!(broker.status(BOB).unwrap().contains("b2ZmZXI="));
        assert!(broker.signal(ALICE, "answer", b"YmFk").is_err());

        broker.leave(ALICE).unwrap();
        assert!(broker.status(BOB).unwrap().contains("waiting"));
    }
}
