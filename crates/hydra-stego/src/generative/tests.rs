use super::*;

#[derive(Debug, Clone, Copy)]
struct BiasedTextModel;

impl LanguageModel for BiasedTextModel {
    fn fingerprint(&self) -> &str {
        "test-biased-arithmetic-v1"
    }

    fn tokenize(&self, text: &str) -> Result<Vec<TokenId>, StegoError> {
        text.chars()
            .map(|character| match character {
                'a' => Ok(0),
                'b' => Ok(1),
                'c' => Ok(2),
                _ => Err(StegoError::NotCoverText),
            })
            .collect()
    }

    fn detokenize(&self, tokens: &[TokenId]) -> Result<String, StegoError> {
        tokens
            .iter()
            .map(|token| match token {
                0 => Ok('a'),
                1 => Ok('b'),
                2 => Ok('c'),
                _ => Err(StegoError::Model("unexpected test token".to_owned())),
            })
            .collect()
    }

    fn next_candidates(
        &self,
        _context: &[TokenId],
        _generated: &[TokenId],
        count: usize,
    ) -> Result<Vec<TokenCandidate>, StegoError> {
        if count != 3 {
            return Err(StegoError::Model(
                "test model requires three tokens".to_owned(),
            ));
        }
        Ok(vec![
            TokenCandidate::new(0, 0.0),
            TokenCandidate::new(1, -0.7),
            TokenCandidate::new(2, -2.2),
        ])
    }
}

fn codec() -> GenerativeCodec<BiasedTextModel> {
    GenerativeCodec::new(
        BiasedTextModel,
        ModelConfig {
            prompt: "a".to_owned(),
            candidate_count: 3,
            maximum_finish_tokens: 0,
            ..ModelConfig::new("test-biased-arithmetic-v1")
        },
    )
    .unwrap()
}

#[test]
fn arithmetic_round_trips_non_power_of_two_candidates() {
    let codec = codec();
    for payload in [
        Vec::new(),
        vec![0],
        vec![0, 1, 127, 128, 255],
        (0_u8..=63).collect(),
    ] {
        let cover = codec.hide_with_progress(&payload, |_| {}).unwrap();
        assert_eq!(codec.reveal(&cover).unwrap(), payload);
    }
}

#[test]
fn generation_progress_reports_each_selected_token() {
    let codec = codec();
    let reports = RefCell::new(Vec::new());
    let cover = codec
        .hide_with_progress(b"progress", |tokens| reports.borrow_mut().push(tokens))
        .unwrap();
    let reports = reports.into_inner();
    assert!(!reports.is_empty());
    assert!(reports.windows(2).all(|pair| pair[1] == pair[0] + 1));
    assert_eq!(reports.last().copied(), Some(cover.len()));
    assert_eq!(codec.reveal(&cover).unwrap(), b"progress");
}

#[test]
fn configuration_pins_the_model_fingerprint() {
    let config = ModelConfig {
        candidate_count: 3,
        ..ModelConfig::new("different")
    };
    assert!(matches!(
        GenerativeCodec::new(BiasedTextModel, config),
        Err(StegoError::Model(_))
    ));
}

#[test]
fn configuration_rejects_unpinned_or_oversized_limits() {
    let mut config = ModelConfig::new("");
    config.candidate_count = 3;
    assert!(matches!(
        GenerativeCodec::new(BiasedTextModel, config),
        Err(StegoError::InvalidConfig(_))
    ));

    let mut payload_config = ModelConfig::new("test-biased-arithmetic-v1");
    payload_config.candidate_count = 3;
    payload_config.maximum_payload_bytes = crate::frame::MAX_PAYLOAD_BYTES + 1;
    assert!(matches!(
        GenerativeCodec::new(BiasedTextModel, payload_config),
        Err(StegoError::InvalidConfig(_))
    ));

    let mut config = ModelConfig::new("test-biased-arithmetic-v1");
    config.candidate_count = 3;
    config.maximum_cover_bytes = 128 * 1024 * 1024 + 1;
    assert!(matches!(
        GenerativeCodec::new(BiasedTextModel, config),
        Err(StegoError::InvalidConfig(_))
    ));
}

#[test]
fn changed_cover_fails_to_authenticate_its_frame() {
    let codec = codec();
    let mut cover = codec
        .hide_with_progress(b"opaque encrypted packet", |_| {})
        .unwrap()
        .into_bytes();
    let last = cover.len() - 1;
    cover[last] = if cover[last] == b'a' { b'b' } else { b'a' };
    assert!(codec.reveal(std::str::from_utf8(&cover).unwrap()).is_err());
}
