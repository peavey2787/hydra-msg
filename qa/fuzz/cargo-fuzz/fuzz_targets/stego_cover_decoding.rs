#![no_main]

use hydra_stego::{
    model::{LanguageModel, ModelConfig, TokenCandidate, TokenId},
    Stego, StegoError, StegoProfile,
};
use libfuzzer_sys::fuzz_target;

const FINGERPRINT: &str = "hydra-stego-fuzz-model-v1";
const MAX_ACCEPTED_COVER_BYTES: usize = 4 * 1024;
const MAX_FUZZ_INPUT_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy)]
struct FuzzModel;

impl LanguageModel for FuzzModel {
    fn fingerprint(&self) -> &str {
        FINGERPRINT
    }

    fn tokenize(&self, text: &str) -> Result<Vec<TokenId>, StegoError> {
        Ok(text.chars().map(|character| character as TokenId % 32).collect())
    }

    fn detokenize(&self, tokens: &[TokenId]) -> Result<String, StegoError> {
        Ok(tokens
            .iter()
            .map(|token| char::from(b'a' + (*token % 26) as u8))
            .collect())
    }

    fn next_candidates(
        &self,
        _context: &[TokenId],
        _generated: &[TokenId],
        count: usize,
    ) -> Result<Vec<TokenCandidate>, StegoError> {
        if count > 32 {
            return Err(StegoError::Model("fuzz candidate request exceeds 32".to_owned()));
        }
        Ok((0..count)
            .map(|id| TokenCandidate::new(id as TokenId, -(id as f64)))
            .collect())
    }
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_FUZZ_INPUT_BYTES)];
    let cover = String::from_utf8_lossy(data);

    let mut config = ModelConfig::new(FINGERPRINT);
    config.prompt = "a".to_owned();
    config.candidate_count = 32;
    config.maximum_payload_bytes = 4096;
    config.maximum_finish_tokens = 8;
    config.maximum_cover_tokens = MAX_ACCEPTED_COVER_BYTES;
    config.maximum_cover_bytes = MAX_ACCEPTED_COVER_BYTES;
    let stego = Stego::with_model(FuzzModel, config).expect("fuzz config is valid");

    for profile in [
        StegoProfile::Deterministic,
        StegoProfile::FastUnicode,
        StegoProfile::FastHybrid,
        StegoProfile::Arithmetic,
    ] {
        let _ = stego.decode(&cover, profile);
    }
});
