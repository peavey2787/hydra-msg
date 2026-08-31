use std::sync::atomic::{AtomicUsize, Ordering};

use super::{codec::encode_prose, template::templates, vocabulary::OPENERS, words};
use crate::generative::{TokenCandidate, TokenId};
use crate::{frame, generative::ModelConfig, StegoError};

use super::super::{fast, GenerativeCodec, LanguageModel};

struct HybridTextModel {
    calls: AtomicUsize,
}

impl LanguageModel for HybridTextModel {
    fn fingerprint(&self) -> &str {
        "fast-hybrid-text-model-v1"
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

fn codec() -> GenerativeCodec<HybridTextModel> {
    codec_with_cover_limit(16 * 1024 * 1024)
}

fn codec_with_cover_limit(maximum_cover_bytes: usize) -> GenerativeCodec<HybridTextModel> {
    GenerativeCodec::new(
        HybridTextModel {
            calls: AtomicUsize::new(0),
        },
        ModelConfig {
            maximum_payload_bytes: 16 * 1024,
            maximum_cover_bytes,
            ..ModelConfig::new("fast-hybrid-text-model-v1")
        },
    )
    .unwrap()
}

#[test]
fn hybrid_profile_round_trips_as_printable_prose() {
    let codec = codec();
    let payload = b"opaque encrypted paragraph bytes";
    let cover = codec
        .hide_fast_hybrid_with_progress(payload, |_| {})
        .unwrap();
    assert!(cover.is_ascii());
    assert!(cover
        .chars()
        .all(|character| character == ' ' || character.is_ascii_graphic()));
    assert!(!cover.contains("opaque"));
    assert!(!cover.contains("For reference, I noted"));
    assert_eq!(codec.reveal_fast_hybrid(&cover).unwrap(), payload);
    assert_eq!(
        codec.model().calls.load(Ordering::Relaxed),
        fast::VISIBLE_COVER_TOKENS
    );
}

#[test]
fn hybrid_profile_survives_surface_normalization() {
    let codec = codec();
    let cover = codec
        .hide_fast_hybrid_with_progress(b"normalized surface", |_| {})
        .unwrap();
    let normalized = cover
        .chars()
        .map(|character| {
            if character.is_ascii_alphabetic() {
                character.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>();
    assert_eq!(
        codec.reveal_fast_hybrid(&normalized).unwrap(),
        b"normalized surface"
    );
}

#[test]
fn hybrid_payload_size_does_not_increase_model_work() {
    let codec = codec();
    let payload = vec![0x5a; 8 * 1024];
    let cover = codec
        .hide_fast_hybrid_with_progress(&payload, |_| {})
        .unwrap();
    assert_eq!(codec.reveal_fast_hybrid(&cover).unwrap(), payload);
    assert_eq!(
        codec.model().calls.load(Ordering::Relaxed),
        fast::VISIBLE_COVER_TOKENS
    );
}

#[test]
fn hybrid_profile_rejects_oversized_prose_before_rendering_it() {
    let codec = codec_with_cover_limit(4096);
    let payload = vec![0x5a; 4096];
    assert!(matches!(
        codec.hide_fast_hybrid_with_progress(&payload, |_| {}),
        Err(StegoError::CoverTooLarge { .. })
    ));
}

#[test]
fn changed_hybrid_word_fails_frame_validation() {
    let codec = codec();
    let framed = frame::encode(b"authenticated later by HYDRA").unwrap();
    let cover = encode_prose(&framed).unwrap();
    let selected_opener = usize::from((framed[0] & 0x07) << 2 | framed[1] >> 6);
    let replacement_opener = (selected_opener + 1) % OPENERS.len();
    let changed = cover.replacen(OPENERS[selected_opener], OPENERS[replacement_opener], 1);
    assert_ne!(changed, cover);
    assert!(codec.reveal_fast_hybrid(&changed).is_err());
}

#[test]
fn every_template_round_trips_its_choices_unambiguously() {
    for template in templates() {
        let values = [1, 3, 5, 7, 9, 11, 13];
        let rendered = template.render(&values);
        let rendered_words = words(&rendered).collect::<Vec<_>>();
        let matches = templates()
            .iter()
            .filter_map(|candidate| candidate.parse(&rendered_words, 0))
            .collect::<Vec<_>>();
        assert_eq!(matches, vec![(rendered_words.len(), values)]);
    }
}
