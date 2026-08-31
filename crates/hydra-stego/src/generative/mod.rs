use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
};

use crate::{frame, StegoError};

mod arithmetic;
mod config;
mod fast;
mod hybrid;
mod model;

use arithmetic::{Decoder, Encoder, Frequencies};
pub use config::ModelConfig;
pub use model::{LanguageModel, TokenCandidate, TokenId};

/// Probability-weighted arithmetic steganography over a deterministic model.
///
/// The model, tokenizer, prompt, candidate filtering, scores, and numeric
/// settings must match at both ends. This codec preserves the model's
/// quantized next-token distribution; it does not make an undetectability
/// claim and it cannot survive edits to the generated text.
#[derive(Debug)]
pub(crate) struct GenerativeCodec<M> {
    model: M,
    pub(crate) config: ModelConfig,
}

impl<M: LanguageModel> GenerativeCodec<M> {
    pub(crate) fn new(model: M, config: ModelConfig) -> Result<Self, StegoError> {
        config::validate(&config)?;
        if config.expected_fingerprint != model.fingerprint() {
            return Err(StegoError::Model(format!(
                "fingerprint mismatch: configured {:?}, loaded {:?}",
                config.expected_fingerprint,
                model.fingerprint()
            )));
        }
        Ok(Self { model, config })
    }

    /// Generates cover text and reports the number of selected cover tokens.
    ///
    /// The callback is observational only and does not affect token choices.
    pub(crate) fn hide_with_progress<F>(
        &self,
        payload: &[u8],
        mut on_progress: F,
    ) -> Result<String, StegoError>
    where
        F: FnMut(usize),
    {
        if payload.len() > self.config.maximum_payload_bytes {
            return Err(StegoError::PayloadTooLarge {
                actual: payload.len(),
                maximum: self.config.maximum_payload_bytes,
            });
        }

        let framed = frame::encode(payload)?;
        let target_bits = framed.len() * 8;
        let source_bit = |offset: usize| {
            if offset < target_bits {
                bit_at(&framed, offset)
            } else if (offset - target_bits).is_multiple_of(2) {
                1
            } else {
                0
            }
        };

        let mut read_offset = 0;
        let mut decoder = Decoder::new(|| {
            let bit = source_bit(read_offset);
            read_offset += 1;
            bit
        });
        let confirmed = Cell::new(0_usize);
        let desynchronized = Cell::new(false);
        let mut encoder = Encoder::new(|bit| {
            let offset = confirmed.get();
            if bit != source_bit(offset) {
                desynchronized.set(true);
            }
            confirmed.set(offset + 1);
        });

        let mut context = self.model.tokenize(&self.config.prompt)?;
        let generated_capacity = (target_bits / 2).min(
            self.config
                .maximum_cover_tokens
                .saturating_add(self.config.maximum_finish_tokens),
        );
        let mut generated = Vec::with_capacity(generated_capacity);
        while confirmed.get() < target_bits {
            if generated.len() >= self.config.maximum_cover_tokens {
                return Err(StegoError::Model(format!(
                    "arithmetic coder exceeded {} cover tokens after confirming {}/{target_bits} bits",
                    self.config.maximum_cover_tokens,
                    confirmed.get(),
                )));
            }
            let candidates = self.candidates(&context, &generated)?;
            let frequencies = Frequencies::from_candidates(&candidates, self.config.temperature)?;
            let symbol = decoder.symbol(&frequencies);
            encoder.symbol(symbol, &frequencies);
            if desynchronized.get() {
                return Err(StegoError::Model(
                    "arithmetic encoder and decoder desynchronized".to_owned(),
                ));
            }
            let token = candidates[symbol].id();
            generated.push(token);
            context.push(token);
            on_progress(generated.len());
        }

        let mut finish_tokens = 0;
        while !self.model.is_natural_boundary(&generated)? {
            if finish_tokens == self.config.maximum_finish_tokens {
                break;
            }
            let candidates = self.candidates(&context, &generated)?;
            let token = self.finishing_token(&generated, &candidates)?;
            generated.push(token);
            context.push(token);
            finish_tokens += 1;
            on_progress(generated.len());
        }

        let text = self.model.detokenize(&generated)?;
        self.ensure_cover_bytes(&text)?;
        if self.model.tokenize(&text)? != generated {
            return Err(StegoError::Model(
                "tokenizer did not reproduce the generated token sequence".to_owned(),
            ));
        }
        Ok(text)
    }

    pub(crate) fn reveal(&self, cover_text: &str) -> Result<Vec<u8>, StegoError> {
        self.ensure_cover_bytes(cover_text)?;
        let observed = self.model.tokenize(cover_text)?;
        if observed.is_empty() {
            return Err(StegoError::NotCoverText);
        }
        if observed.len() > self.config.maximum_cover_tokens + self.config.maximum_finish_tokens {
            return Err(StegoError::MalformedCoverText(
                "carrier exceeds the configured cover-token limit",
            ));
        }

        let decoded = RefCell::new(Vec::with_capacity(observed.len()));
        let bit_count = Cell::new(0_usize);
        let mut encoder = Encoder::new(|bit| {
            let offset = bit_count.get();
            append_bit(&mut decoded.borrow_mut(), offset, bit);
            bit_count.set(offset + 1);
        });
        let mut context = self.model.tokenize(&self.config.prompt)?;
        let mut generated = Vec::with_capacity(observed.len());
        let mut data_end = None;
        let mut expected_frame_len = None;

        for (position, token) in observed.iter().copied().enumerate() {
            let candidates = self.candidates(&context, &generated)?;
            let symbol = candidates
                .iter()
                .position(|candidate| candidate.id() == token)
                .ok_or(StegoError::MalformedCoverText(
                    "token is outside the deterministic arithmetic candidate set",
                ))?;
            let frequencies = Frequencies::from_candidates(&candidates, self.config.temperature)?;
            encoder.symbol(symbol, &frequencies);
            generated.push(token);
            context.push(token);

            if expected_frame_len.is_none() && bit_count.get() >= frame::minimum_encoded_len() * 8 {
                expected_frame_len = frame::expected_len(
                    &complete_bytes(&decoded.borrow(), bit_count.get()),
                    self.config.maximum_payload_bytes,
                )?;
            }
            if expected_frame_len.is_some_and(|length| bit_count.get() >= length * 8) {
                data_end = Some(position + 1);
                break;
            }
        }

        let expected_frame_len = expected_frame_len.ok_or(StegoError::MalformedCoverText(
            "carrier ended before its frame header",
        ))?;
        let data_end = data_end.ok_or(StegoError::MalformedCoverText(
            "carrier ended before its complete arithmetic frame",
        ))?;
        if observed.len() - data_end > self.config.maximum_finish_tokens {
            return Err(StegoError::MalformedCoverText(
                "carrier has too many sentence-finishing tokens",
            ));
        }
        for token in observed[data_end..].iter().copied() {
            let candidates = self.candidates(&context, &generated)?;
            let expected = self.finishing_token(&generated, &candidates)?;
            if token != expected {
                return Err(StegoError::MalformedCoverText(
                    "carrier has a non-canonical sentence-finishing token",
                ));
            }
            generated.push(token);
            context.push(token);
        }

        let mut bytes = complete_bytes(&decoded.borrow(), bit_count.get());
        if bytes.len() < expected_frame_len {
            return Err(StegoError::MalformedCoverText("carrier frame is truncated"));
        }
        bytes.truncate(expected_frame_len);
        frame::decode(&bytes, self.config.maximum_payload_bytes)
    }

    #[cfg(test)]
    pub(super) fn model(&self) -> &M {
        &self.model
    }

    pub(super) fn ensure_cover_bytes(&self, cover_text: &str) -> Result<(), StegoError> {
        if cover_text.len() > self.config.maximum_cover_bytes {
            return Err(StegoError::CoverTooLarge {
                actual: cover_text.len(),
                maximum: self.config.maximum_cover_bytes,
            });
        }
        Ok(())
    }

    fn candidates(
        &self,
        context: &[TokenId],
        generated: &[TokenId],
    ) -> Result<Vec<TokenCandidate>, StegoError> {
        self.candidates_with_count(context, generated, self.config.candidate_count)
    }

    fn candidates_with_count(
        &self,
        context: &[TokenId],
        generated: &[TokenId],
        count: usize,
    ) -> Result<Vec<TokenCandidate>, StegoError> {
        let mut candidates = self.model.next_candidates(context, generated, count)?;
        if candidates.len() != count {
            return Err(StegoError::Model(format!(
                "model returned {} candidates; expected {}",
                candidates.len(),
                count
            )));
        }
        if candidates
            .iter()
            .any(|candidate| !candidate.score().is_finite())
        {
            return Err(StegoError::Model(
                "model returned a non-finite candidate score".to_owned(),
            ));
        }
        candidates.sort_by(|left, right| {
            right
                .score()
                .total_cmp(&left.score())
                .then_with(|| left.id().cmp(&right.id()))
        });
        let mut ids = HashSet::with_capacity(candidates.len());
        if candidates
            .iter()
            .any(|candidate| !ids.insert(candidate.id()))
        {
            return Err(StegoError::Model(
                "model returned duplicate candidate tokens".to_owned(),
            ));
        }
        Ok(candidates)
    }

    fn finishing_token(
        &self,
        generated: &[TokenId],
        candidates: &[TokenCandidate],
    ) -> Result<TokenId, StegoError> {
        for candidate in candidates {
            let mut trial = Vec::with_capacity(generated.len() + 1);
            trial.extend_from_slice(generated);
            trial.push(candidate.id());
            if self.model.is_natural_boundary(&trial)? {
                return Ok(candidate.id());
            }
        }
        Ok(candidates[0].id())
    }
}

fn bit_at(bytes: &[u8], offset: usize) -> u8 {
    bytes[offset / 8] >> (7 - offset % 8) & 1
}

fn append_bit(bytes: &mut Vec<u8>, offset: usize, bit: u8) {
    if offset / 8 == bytes.len() {
        bytes.push(0);
    }
    if bit == 1 {
        bytes[offset / 8] |= 1 << (7 - offset % 8);
    }
}

fn complete_bytes(bytes: &[u8], bit_count: usize) -> Vec<u8> {
    bytes[..bit_count / 8].to_vec()
}

#[cfg(test)]
mod tests;
