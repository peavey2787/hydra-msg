use hydra_stego::{
    model::{LanguageModel, ModelConfig, TokenCandidate, TokenId},
    Stego, StegoError, StegoProfile,
};

const TOKEN_TEXT: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyzABCDEF";
const FINGERPRINT: &str = "production-api-test-model-v1";

#[derive(Debug, Clone, Copy)]
struct TestModel;

impl LanguageModel for TestModel {
    fn fingerprint(&self) -> &str {
        FINGERPRINT
    }

    fn tokenize(&self, text: &str) -> Result<Vec<TokenId>, StegoError> {
        text.bytes()
            .map(|byte| {
                TOKEN_TEXT
                    .iter()
                    .position(|candidate| *candidate == byte)
                    .map(|index| index as TokenId)
                    .ok_or(StegoError::NotCoverText)
            })
            .collect()
    }

    fn detokenize(&self, tokens: &[TokenId]) -> Result<String, StegoError> {
        let bytes = tokens
            .iter()
            .map(|token| {
                usize::try_from(*token)
                    .ok()
                    .and_then(|index| TOKEN_TEXT.get(index).copied())
                    .ok_or_else(|| StegoError::Model("unexpected test token".to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        String::from_utf8(bytes)
            .map_err(|_| StegoError::Model("test model produced invalid UTF-8".to_owned()))
    }

    fn next_candidates(
        &self,
        _context: &[TokenId],
        _generated: &[TokenId],
        count: usize,
    ) -> Result<Vec<TokenCandidate>, StegoError> {
        if count > TOKEN_TEXT.len() {
            return Err(StegoError::Model(
                "test candidate request is too large".to_owned(),
            ));
        }
        Ok((0..count)
            .map(|id| TokenCandidate::new(id as TokenId, -(id as f64) / 8.0))
            .collect())
    }
}

fn stego(maximum_cover_bytes: usize) -> Stego {
    let mut config = ModelConfig::new(FINGERPRINT);
    config.prompt = "a".to_owned();
    config.candidate_count = 32;
    config.maximum_payload_bytes = 4096;
    config.maximum_finish_tokens = 0;
    config.maximum_cover_tokens = 128 * 1024;
    config.maximum_cover_bytes = maximum_cover_bytes;
    Stego::with_model(TestModel, config).unwrap()
}

#[test]
fn public_facade_round_trips_all_four_profiles() {
    let stego = stego(4 * 1024 * 1024);
    let payload = b"opaque authenticated packet";
    for profile in [
        StegoProfile::Deterministic,
        StegoProfile::FastUnicode,
        StegoProfile::FastHybrid,
        StegoProfile::Arithmetic,
    ] {
        let cover = stego.encode(payload, profile).unwrap();
        assert_eq!(
            stego.decode(&cover, profile).unwrap(),
            payload,
            "{profile:?}"
        );
    }
}

#[test]
fn deterministic_and_hybrid_documented_normalization_survives() {
    let stego = stego(4 * 1024 * 1024);
    let payload = b"normalization contract";

    let deterministic = stego.encode(payload, StegoProfile::Deterministic).unwrap();
    let deterministic = normalize_case_punctuation_and_space(&deterministic);
    assert_eq!(
        stego
            .decode(&deterministic, StegoProfile::Deterministic)
            .unwrap(),
        payload
    );

    let hybrid = stego.encode(payload, StegoProfile::FastHybrid).unwrap();
    let hybrid = normalize_case_punctuation_and_space(&hybrid);
    assert_eq!(
        stego.decode(&hybrid, StegoProfile::FastHybrid).unwrap(),
        payload
    );
}

#[test]
fn exact_text_profiles_reject_transport_damage() {
    let stego = stego(4 * 1024 * 1024);
    let payload = b"exact transport contract";

    let fast = stego.encode(payload, StegoProfile::FastUnicode).unwrap();
    let stripped = fast
        .chars()
        .filter(|character| {
            let scalar = *character as u32;
            *character != '\u{2063}'
                && !(0xfe00..=0xfe0f).contains(&scalar)
                && !(0xe0100..=0xe01ef).contains(&scalar)
        })
        .collect::<String>();
    assert!(stego.decode(&stripped, StegoProfile::FastUnicode).is_err());

    let arithmetic = stego.encode(payload, StegoProfile::Arithmetic).unwrap();
    assert_eq!(
        stego.decode(&arithmetic, StegoProfile::Arithmetic).unwrap(),
        payload
    );
    let mut changed = arithmetic;
    changed.push('a');
    assert!(stego.decode(&changed, StegoProfile::Arithmetic).is_err());
}

#[test]
fn decode_limits_fail_before_unbounded_work() {
    let deterministic = Stego::new();
    assert!(matches!(
        deterministic.decode(&"x".repeat(12 * 1024 * 1024), StegoProfile::Deterministic),
        Err(StegoError::CoverTooLarge { .. })
    ));

    let stego = stego(4096);
    let oversized = "x".repeat(4097);
    for profile in [
        StegoProfile::FastUnicode,
        StegoProfile::FastHybrid,
        StegoProfile::Arithmetic,
    ] {
        assert!(matches!(
            stego.decode(&oversized, profile),
            Err(StegoError::CoverTooLarge { .. })
        ));
    }
}

#[test]
fn model_identity_and_profile_requirements_are_fail_closed() {
    assert!(!StegoProfile::Deterministic.requires_model());
    assert!(StegoProfile::FastUnicode.requires_model());
    assert!(StegoProfile::FastHybrid.requires_model());
    assert!(StegoProfile::Arithmetic.requires_model());

    let deterministic = Stego::new();
    assert_eq!(
        deterministic
            .encode(b"packet", StegoProfile::FastHybrid)
            .unwrap_err(),
        StegoError::ModelRequired
    );

    let config = ModelConfig::new("wrong-fingerprint");
    assert!(matches!(
        Stego::with_model(TestModel, config),
        Err(StegoError::Model(_))
    ));

    let mut oversized = ModelConfig::new(FINGERPRINT);
    oversized.maximum_payload_bytes = 64 * 1024 + 1;
    assert!(matches!(
        Stego::with_model(TestModel, oversized),
        Err(StegoError::InvalidConfig(_))
    ));
}

fn normalize_case_punctuation_and_space(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_ascii_alphabetic() {
                character.to_ascii_uppercase()
            } else if character.is_ascii_digit() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("   ")
}
