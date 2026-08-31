use super::{
    helpers::{
        expire_handshakes, identity_signing_key, pending_retry, prepare_inbound_responder_attempt,
        prepare_local_initiator_attempt, reject_other_pending_attempt,
        supersede_inbound_candidates, supersede_outbound_attempts,
    },
    AcceptedInit, AcceptedInitKey, HandshakeAnswer, HandshakeOffer, HandshakePurpose, PendingOffer,
    ResponderCandidate,
};
use crate::{
    codec::{
        decode_handshake_offer, encode_handshake_answer, encode_handshake_offer, finish_route_tag,
        identity_fingerprint, random_array, HandshakeAnswerParts,
    },
    limits::{reject_collection_growth, MAX_CONTACTS, MAX_PENDING_HANDSHAKES},
    ContactId, Hydra, HydraContact, HydraMsgError, HydraResult,
};
use hydra_crypto::{CryptoBackend, MlKemEncapsulationKey, RustCryptoBackend};

impl Hydra {
    pub(crate) fn init_handshake_for(
        &mut self,
        contact_id: ContactId,
        purpose: HandshakePurpose,
    ) -> HydraResult<HandshakeOffer> {
        let contact = self.require_contact(contact_id)?.clone();
        expire_handshakes(self);
        let record = self.active_unlocked_record()?.clone();
        if let Some(offer) = pending_retry(self, contact_id, record.id, purpose) {
            return Ok(HandshakeOffer(offer));
        }
        reject_other_pending_attempt(self, contact_id, record.id, purpose)?;
        let supersede_inbound = prepare_local_initiator_attempt(
            self,
            contact_id,
            &record.public_key,
            &contact.public_key,
            purpose,
        )?;
        reject_collection_growth(
            self.pending_offers.len(),
            1,
            MAX_PENDING_HANDSHAKES,
            "pending handshake limit",
        )?;
        let signing_key = identity_signing_key(&record)?;
        let nonce = random_array::<32>()?;
        let x25519_secret = RustCryptoBackend::x25519_generate()?;
        let x25519_public = x25519_secret.public_key();
        let kem_keypair = RustCryptoBackend::mlkem768_generate()?;
        let kem_public_key = kem_keypair.encapsulation_key.to_bytes();
        let route_tag = random_array::<16>()?;
        let expected_responder_fingerprint = identity_fingerprint(&contact.public_key);
        let offer = encode_handshake_offer(
            &record.public_key,
            nonce,
            expected_responder_fingerprint,
            x25519_public,
            &kem_public_key,
            &signing_key,
            route_tag,
        )?;
        let parsed_offer = decode_handshake_offer(&offer)?;
        if supersede_inbound {
            supersede_inbound_candidates(self, contact_id, purpose);
        }
        self.pending_offers.insert(
            parsed_offer.init_hash,
            PendingOffer {
                contact_id,
                offer_bytes: offer.clone(),
                local_identity_id: record.id,
                offer: parsed_offer,
                x25519_secret,
                kem_decapsulation_key: kem_keypair.decapsulation_key,
                created_at: crate::time::HydraInstant::now(),
                purpose,
            },
        );
        Ok(HandshakeOffer(offer))
    }

    pub(crate) fn reply_handshake_for(
        &mut self,
        offer: impl AsRef<[u8]>,
        purpose: HandshakePurpose,
    ) -> HydraResult<HandshakeAnswer> {
        let parsed_offer = decode_handshake_offer(offer.as_ref())?;
        let active = self.active_unlocked_record()?.clone();
        if parsed_offer.expected_responder_fingerprint != identity_fingerprint(&active.public_key) {
            return Err(HydraMsgError::InvalidInput(
                "INIT expected responder fingerprint mismatch",
            ));
        }
        expire_handshakes(self);
        let contact_id = ContactId(parsed_offer.peer_id.0);
        if self
            .contacts
            .get(&contact_id)
            .is_some_and(|contact| contact.blocked)
        {
            return Err(HydraMsgError::InvalidInput("contact is blocked"));
        }
        let cache_key = AcceptedInitKey {
            initiator_fingerprint: parsed_offer.initiator_fingerprint,
            init_nonce: parsed_offer.nonce,
            init_hash: parsed_offer.init_hash,
        };
        if let Some(cached) = self.accepted_inits.get(&cache_key) {
            if cached.purpose != purpose {
                return Err(HydraMsgError::InvalidInput(
                    "duplicate INIT has the wrong local purpose",
                ));
            }
            return Ok(HandshakeAnswer(cached.response.clone()));
        }
        let supersede_outbound = prepare_inbound_responder_attempt(
            self,
            contact_id,
            &active.public_key,
            parsed_offer.initiator_fingerprint,
            purpose,
        )?;
        reject_collection_growth(
            self.accepted_inits.len(),
            1,
            MAX_PENDING_HANDSHAKES,
            "accepted INIT cache limit",
        )?;
        let new_contact = if self.contacts.contains_key(&contact_id) {
            None
        } else {
            reject_collection_growth(self.contacts.len(), 1, MAX_CONTACTS, "contact limit")?;
            Some(HydraContact {
                id: contact_id,
                label: format!("contact-{}", contact_id.hex()),
                public_key: parsed_offer.public_key,
                verified: false,
                blocked: false,
            })
        };

        let signing_key = identity_signing_key(&active)?;
        let x25519_secret = RustCryptoBackend::x25519_generate()?;
        let x25519_public = x25519_secret.public_key();
        let x25519_shared =
            RustCryptoBackend::x25519_diffie_hellman(&x25519_secret, &parsed_offer.x25519_public)?;
        let kem_public_key = MlKemEncapsulationKey::from_bytes(&parsed_offer.kem_public_key)?;
        let (kem_ciphertext, kem_shared) =
            RustCryptoBackend::mlkem768_encapsulate(&kem_public_key)?;
        let nonce = random_array::<32>()?;
        let route_tag = random_array::<16>()?;
        let (answer, material) = encode_handshake_answer(
            HandshakeAnswerParts {
                public_key: &active.public_key,
                nonce,
                x25519_public,
                kem_ciphertext: &kem_ciphertext,
                offer: &parsed_offer,
                signing_key: &signing_key,
                x25519_secret: &x25519_shared,
                kem_secret: &kem_shared,
            },
            route_tag,
        )?;
        let finish_route_tag = finish_route_tag(&material);
        if supersede_outbound {
            supersede_outbound_attempts(self, contact_id, purpose);
        }
        if let Some(contact) = new_contact {
            self.contacts.insert(contact_id, contact);
        }
        self.accepted_inits.insert(
            cache_key,
            AcceptedInit {
                contact_id,
                local_identity_id: active.id,
                response: answer.clone(),
                finish_route_tag,
                purpose,
                candidate: Some(ResponderCandidate { material }),
                accepted_finish_hash: None,
                created_at: crate::time::HydraInstant::now(),
            },
        );
        self.persist()?;
        Ok(HandshakeAnswer(answer))
    }
}
