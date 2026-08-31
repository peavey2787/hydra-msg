use super::{HandshakeAnswer, HandshakeFinish, HandshakeOffer, HandshakePurpose};
use crate::{ContactId, Hydra, HydraResult};

impl Hydra {
    pub fn init_handshake(&mut self, contact_id: ContactId) -> HydraResult<HandshakeOffer> {
        self.init_handshake_for(contact_id, HandshakePurpose::Standard)
    }

    pub fn reply_handshake(&mut self, offer: impl AsRef<[u8]>) -> HydraResult<HandshakeAnswer> {
        self.reply_handshake_for(offer, HandshakePurpose::Standard)
    }

    pub fn finish_handshake(&mut self, answer: impl AsRef<[u8]>) -> HydraResult<HandshakeFinish> {
        self.finish_handshake_for(answer, HandshakePurpose::Standard)
    }

    pub fn accept_handshake_finish(&mut self, finish: impl AsRef<[u8]>) -> HydraResult<()> {
        self.accept_handshake_finish_for(finish, HandshakePurpose::Standard)
    }
}
