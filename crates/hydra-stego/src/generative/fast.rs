use crate::{frame, StegoError};

use super::{GenerativeCodec, LanguageModel, TokenCandidate, TokenId};

const CANDIDATE_COUNT: usize = 32;
pub(super) const VISIBLE_COVER_TOKENS: usize = 16;
const SEPARATOR: char = '\u{2063}';
const SUPPLEMENTARY_VARIATION_SELECTOR_START: u32 = 0xe0100;

impl<M: LanguageModel> GenerativeCodec<M> {
    /// Generates a short AI cover and stores the framed payload in trailing
    /// Unicode variation selectors.
    ///
    /// This profile is fast and high-capacity, but deliberately offers weaker
    /// concealment than arithmetic mode. Default-ignorable selectors are easy
    /// to detect and many text processors strip or normalize them.
    /// Fast-cover generation with the selected visible-token count reported
    /// after each model inference.
    pub(crate) fn hide_fast_with_progress<F>(
        &self,
        payload: &[u8],
        mut on_progress: F,
    ) -> Result<String, StegoError>
    where
        F: FnMut(usize),
    {
        let framed = frame_payload(self, payload)?;
        let mut cover = generate_visible_cover(self, &framed, &mut on_progress)?;
        ensure_selector_capacity(self, &cover, &framed)?;
        cover.push(SEPARATOR);
        cover.extend(framed.into_iter().map(byte_selector));
        self.ensure_cover_bytes(&cover)?;
        Ok(cover)
    }

    /// Recovers a payload from the fast Unicode profile without model
    /// inference. The recovered bytes still require HYDRA authentication.
    pub(crate) fn reveal_fast(&self, cover_text: &str) -> Result<Vec<u8>, StegoError> {
        self.ensure_cover_bytes(cover_text)?;
        let (_, encoded) = cover_text
            .rsplit_once(SEPARATOR)
            .ok_or(StegoError::NotCoverText)?;
        if encoded.is_empty() {
            return Err(StegoError::MalformedCoverText(
                "fast carrier has no variation-selector payload",
            ));
        }
        let maximum_frame_bytes = self
            .config
            .maximum_payload_bytes
            .checked_add(frame::ENCODED_OVERHEAD_BYTES)
            .expect("validated payload limit fits usize");
        let encoded_chars = encoded.chars().take(maximum_frame_bytes + 1).count();
        if encoded_chars > maximum_frame_bytes {
            return Err(StegoError::MalformedCoverText(
                "fast carrier exceeds the framed selector limit",
            ));
        }
        let framed = encoded
            .chars()
            .map(|character| {
                selector_byte(character).ok_or(StegoError::MalformedCoverText(
                    "fast carrier suffix contains a visible or unsupported character",
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        frame::decode(&framed, self.config.maximum_payload_bytes)
    }
}

pub(super) fn frame_payload<M: LanguageModel>(
    codec: &GenerativeCodec<M>,
    payload: &[u8],
) -> Result<Vec<u8>, StegoError> {
    if payload.len() > codec.config.maximum_payload_bytes {
        return Err(StegoError::PayloadTooLarge {
            actual: payload.len(),
            maximum: codec.config.maximum_payload_bytes,
        });
    }
    frame::encode(payload)
}

pub(super) fn generate_visible_cover<M, F>(
    codec: &GenerativeCodec<M>,
    seed: &[u8],
    mut on_progress: F,
) -> Result<String, StegoError>
where
    M: LanguageModel,
    F: FnMut(usize),
{
    let mut random = CoverRandom::new(seed);
    let mut context = codec.model.tokenize(&codec.config.prompt)?;
    let mut generated = Vec::with_capacity(VISIBLE_COVER_TOKENS);
    for token_count in 1..=VISIBLE_COVER_TOKENS {
        let candidates = codec.candidates_with_count(&context, &generated, CANDIDATE_COUNT)?;
        let token = sample_candidate(&candidates, &mut random)?;
        generated.push(token);
        context.push(token);
        on_progress(token_count);
    }

    let mut cover = codec.model.detokenize(&generated)?;
    codec.ensure_cover_bytes(&cover)?;
    if cover.trim().is_empty() {
        return Err(StegoError::Model(
            "fast profile generated an empty visible cover".to_owned(),
        ));
    }
    if cover
        .chars()
        .any(|character| character == SEPARATOR || selector_byte(character).is_some())
    {
        return Err(StegoError::Model(
            "fast profile generated a reserved invisible character".to_owned(),
        ));
    }
    cover.truncate(cover.trim_end().len());
    if !cover
        .chars()
        .next_back()
        .is_some_and(|character| matches!(character, '.' | '!' | '?'))
    {
        cover.push('.');
    }
    Ok(cover)
}

fn ensure_selector_capacity<M: LanguageModel>(
    codec: &GenerativeCodec<M>,
    visible_cover: &str,
    framed: &[u8],
) -> Result<(), StegoError> {
    let selector_bytes = framed.iter().try_fold(0_usize, |total, byte| {
        total.checked_add(if *byte < 16 { 3 } else { 4 })
    });
    let expected = selector_bytes
        .and_then(|bytes| bytes.checked_add(SEPARATOR.len_utf8()))
        .and_then(|bytes| bytes.checked_add(visible_cover.len()))
        .ok_or(StegoError::InvalidConfig(
            "fast Unicode carrier bound overflow",
        ))?;
    if expected > codec.config.maximum_cover_bytes {
        return Err(StegoError::CoverTooLarge {
            actual: expected,
            maximum: codec.config.maximum_cover_bytes,
        });
    }
    Ok(())
}

fn sample_candidate(
    candidates: &[TokenCandidate],
    random: &mut CoverRandom,
) -> Result<TokenId, StegoError> {
    let maximum = candidates
        .first()
        .ok_or_else(|| StegoError::Model("fast profile has no candidates".to_owned()))?
        .score();
    let weights = candidates
        .iter()
        .map(|candidate| (candidate.score() - maximum).exp())
        .collect::<Vec<_>>();
    let total = weights.iter().sum::<f64>();
    if !total.is_finite() || total <= 0.0 {
        return Err(StegoError::Model(
            "fast profile candidate distribution is invalid".to_owned(),
        ));
    }
    let mut target = random.unit_interval() * total;
    for (candidate, weight) in candidates.iter().zip(weights) {
        if target < weight {
            return Ok(candidate.id());
        }
        target -= weight;
    }
    Ok(candidates
        .last()
        .expect("non-empty candidates checked above")
        .id())
}

fn byte_selector(byte: u8) -> char {
    let scalar = if byte < 16 {
        0xfe00 + u32::from(byte)
    } else {
        SUPPLEMENTARY_VARIATION_SELECTOR_START + u32::from(byte) - 16
    };
    char::from_u32(scalar).expect("variation-selector scalars are valid")
}

fn selector_byte(character: char) -> Option<u8> {
    let scalar = character as u32;
    if (0xfe00..=0xfe0f).contains(&scalar) {
        return Some((scalar - 0xfe00) as u8);
    }
    if (SUPPLEMENTARY_VARIATION_SELECTOR_START..=0xe01ef).contains(&scalar) {
        return Some((scalar - SUPPLEMENTARY_VARIATION_SELECTOR_START + 16) as u8);
    }
    None
}

struct CoverRandom(u64);

impl CoverRandom {
    fn new(bytes: &[u8]) -> Self {
        let state = bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
        Self(if state == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            state
        })
    }

    fn unit_interval(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0 = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
        (self.0 >> 11) as f64 / ((1_u64 << 53) as f64)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::generative::ModelConfig;

    struct FastTextModel {
        calls: AtomicUsize,
    }

    impl LanguageModel for FastTextModel {
        fn fingerprint(&self) -> &str {
            "fast-text-model-v1"
        }

        fn tokenize(&self, _text: &str) -> Result<Vec<TokenId>, StegoError> {
            Ok(vec![0])
        }

        fn detokenize(&self, tokens: &[TokenId]) -> Result<String, StegoError> {
            Ok(tokens.iter().map(|token| format!(" word{token}")).collect())
        }

        fn next_candidates(
            &self,
            _context: &[TokenId],
            _generated: &[TokenId],
            count: usize,
        ) -> Result<Vec<TokenCandidate>, StegoError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok((1..=count as u32)
                .map(|id| TokenCandidate::new(id, -f64::from(id) / 8.0))
                .collect())
        }
    }

    fn codec() -> GenerativeCodec<FastTextModel> {
        codec_with_cover_limit(16 * 1024 * 1024)
    }

    fn codec_with_cover_limit(maximum_cover_bytes: usize) -> GenerativeCodec<FastTextModel> {
        GenerativeCodec::new(
            FastTextModel {
                calls: AtomicUsize::new(0),
            },
            ModelConfig {
                maximum_payload_bytes: 16 * 1024,
                maximum_cover_bytes,
                ..ModelConfig::new("fast-text-model-v1")
            },
        )
        .unwrap()
    }

    #[test]
    fn fast_profile_round_trips_without_visible_plaintext() {
        let codec = codec();
        let payload = b"opaque encrypted paragraph bytes";
        let cover = codec.hide_fast_with_progress(payload, |_| {}).unwrap();
        assert!(!cover.split(SEPARATOR).next().unwrap().contains("opaque"));
        assert_eq!(codec.reveal_fast(&cover).unwrap(), payload);
        assert_eq!(
            codec.model().calls.load(Ordering::Relaxed),
            VISIBLE_COVER_TOKENS
        );
    }

    #[test]
    fn payload_size_does_not_increase_model_inference_count() {
        let codec = codec();
        let payload = vec![0x5a; 8 * 1024];
        let cover = codec.hide_fast_with_progress(&payload, |_| {}).unwrap();
        assert_eq!(codec.reveal_fast(&cover).unwrap(), payload);
        assert_eq!(
            codec.model().calls.load(Ordering::Relaxed),
            VISIBLE_COVER_TOKENS
        );
    }

    #[test]
    fn fast_profile_rejects_oversized_selector_output_before_rendering_it() {
        let codec = codec_with_cover_limit(1024);
        let payload = vec![0x5a; 1024];
        assert!(matches!(
            codec.hide_fast_with_progress(&payload, |_| {}),
            Err(StegoError::CoverTooLarge { .. })
        ));
    }

    #[test]
    fn changed_fast_suffix_fails_its_frame_check() {
        let codec = codec();
        let mut cover = codec
            .hide_fast_with_progress(b"authenticated later by HYDRA", |_| {})
            .unwrap();
        let (last, _) = cover.char_indices().next_back().unwrap();
        cover.replace_range(last.., &byte_selector(0).to_string());
        assert!(codec.reveal_fast(&cover).is_err());
    }
}
