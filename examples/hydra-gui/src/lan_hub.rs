use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::json;

const PEER_TTL: Duration = Duration::from_secs(45);
const MAX_PEERS: usize = 32;
const MAX_CARD_BYTES: usize = 32 * 1024;
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_INBOX_MESSAGES: usize = 512;

type HubResult<T> = Result<T, String>;

pub(crate) struct LanHub {
    state: Mutex<HubState>,
}

#[derive(Default)]
struct HubState {
    peers: HashMap<String, Peer>,
    next_order: u64,
}

struct Peer {
    card: String,
    last_seen: Instant,
    order: u64,
    inbox: VecDeque<HubMessage>,
}

struct HubMessage {
    from: String,
    kind: String,
    tag: Option<String>,
    payload: String,
}

impl LanHub {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(HubState::default()),
        }
    }

    pub(crate) fn register(&self, id: &str, card: &[u8]) -> HubResult<String> {
        validate_id(id)?;
        let card = validate_base64(card, MAX_CARD_BYTES, "contact card")?;
        let mut state = self.lock()?;
        state.remove_stale();
        if !state.peers.contains_key(id) && state.peers.len() >= MAX_PEERS {
            return Err("LAN demo hub is full".to_owned());
        }
        if let Some(peer) = state.peers.get_mut(id) {
            peer.card = card.to_owned();
            peer.last_seen = Instant::now();
        } else {
            let order = state.next_order;
            state.next_order = state.next_order.wrapping_add(1);
            state.peers.insert(
                id.to_owned(),
                Peer {
                    card: card.to_owned(),
                    last_seen: Instant::now(),
                    order,
                    inbox: VecDeque::new(),
                },
            );
        }
        Ok(peer_list_json(&state, id))
    }

    pub(crate) fn peers(&self, id: &str) -> HubResult<String> {
        validate_id(id)?;
        let mut state = self.lock()?;
        state.remove_stale();
        state
            .peers
            .get_mut(id)
            .ok_or_else(|| "LAN registration expired".to_owned())?
            .last_seen = Instant::now();
        Ok(peer_list_json(&state, id))
    }

    pub(crate) fn send(
        &self,
        from: &str,
        to: &str,
        kind: &str,
        tag: Option<&str>,
        payload: &[u8],
    ) -> HubResult<String> {
        validate_id(from)?;
        validate_id(to)?;
        validate_kind(kind)?;
        let tag = tag.map(validate_tag).transpose()?;
        let payload = validate_base64(payload, MAX_MESSAGE_BYTES, "LAN payload")?;
        let mut state = self.lock()?;
        state.remove_stale();
        if !state.peers.contains_key(from) {
            return Err("sender LAN registration expired".to_owned());
        }
        let target = state
            .peers
            .get_mut(to)
            .ok_or_else(|| "target peer is no longer available".to_owned())?;
        if target.inbox.len() >= MAX_INBOX_MESSAGES {
            let _ = target.inbox.pop_front();
        }
        target.inbox.push_back(HubMessage {
            from: from.to_owned(),
            kind: kind.to_owned(),
            tag,
            payload: payload.to_owned(),
        });
        Ok("{\"accepted\":true}".to_owned())
    }

    pub(crate) fn receive(&self, id: &str) -> HubResult<String> {
        validate_id(id)?;
        let mut state = self.lock()?;
        state.remove_stale();
        let peer = state
            .peers
            .get_mut(id)
            .ok_or_else(|| "LAN registration expired".to_owned())?;
        peer.last_seen = Instant::now();
        let Some(message) = peer.inbox.pop_front() else {
            return Ok("{\"available\":false}".to_owned());
        };
        let tag = message
            .tag
            .as_deref()
            .map(json::string)
            .unwrap_or_else(|| "null".to_owned());
        Ok(format!(
            "{{\"available\":true,\"from\":{},\"kind\":{},\"tag\":{},\"payload\":{}}}",
            json::string(&message.from),
            json::string(&message.kind),
            tag,
            json::string(&message.payload),
        ))
    }

    pub(crate) fn leave(&self, id: &str) -> HubResult<String> {
        validate_id(id)?;
        let mut state = self.lock()?;
        state.peers.remove(id);
        Ok("{\"removed\":true}".to_owned())
    }

    fn lock(&self) -> HubResult<std::sync::MutexGuard<'_, HubState>> {
        self.state
            .lock()
            .map_err(|_| "LAN hub lock is poisoned".to_owned())
    }
}

impl HubState {
    fn remove_stale(&mut self) {
        let now = Instant::now();
        self.peers
            .retain(|_, peer| now.duration_since(peer.last_seen) <= PEER_TTL);
    }
}

fn peer_list_json(state: &HubState, local_id: &str) -> String {
    let mut peers = state
        .peers
        .iter()
        .filter(|(id, _)| id.as_str() != local_id)
        .map(|(id, peer)| (peer.order, id, &peer.card))
        .collect::<Vec<_>>();
    peers.sort_by_key(|(order, _, _)| *order);
    let values = peers
        .into_iter()
        .map(|(_, id, card)| {
            format!(
                "{{\"id\":{},\"card\":{}}}",
                json::string(id),
                json::string(card),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"peers\":[{values}]}}")
}

fn validate_id(id: &str) -> HubResult<()> {
    if id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("LAN peer id must contain 32 hexadecimal characters".to_owned())
    }
}

fn validate_kind(kind: &str) -> HubResult<()> {
    if !kind.is_empty()
        && kind.len() <= 40
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        Ok(())
    } else {
        Err("LAN message kind is invalid".to_owned())
    }
}

fn validate_tag(tag: &str) -> HubResult<String> {
    if (3..=64).contains(&tag.len())
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(tag.to_owned())
    } else {
        Err("LAN message tag is invalid".to_owned())
    }
}

fn validate_base64<'a>(bytes: &'a [u8], maximum: usize, name: &str) -> HubResult<&'a str> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(format!("{name} has an invalid size"));
    }
    let value = std::str::from_utf8(bytes).map_err(|_| format!("{name} is not UTF-8"))?;
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        Ok(value)
    } else {
        Err(format!("{name} is not canonical base64"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "00000000000000000000000000000001";
    const BOB: &str = "00000000000000000000000000000002";

    #[test]
    fn peers_discover_and_exchange_opaque_messages() {
        let hub = LanHub::new();
        assert_eq!(hub.register(ALICE, b"YWxpY2U=").unwrap(), "{\"peers\":[]}");
        assert!(hub.register(BOB, b"Ym9i").unwrap().contains(ALICE));
        assert!(hub.peers(ALICE).unwrap().contains(BOB));
        hub.send(
            ALICE,
            BOB,
            "handshake-offer",
            Some("m-demo123"),
            b"b2ZmZXI=",
        )
        .unwrap();
        let received = hub.receive(BOB).unwrap();
        assert!(received.contains("handshake-offer"));
        assert!(received.contains("m-demo123"));
        assert!(received.contains("b2ZmZXI="));
        assert_eq!(hub.receive(BOB).unwrap(), "{\"available\":false}");
    }
}
