use crate::StegoError;

pub type TokenId = u32;

/// One deterministic next-token choice returned by a language model.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TokenCandidate {
    id: TokenId,
    score: f64,
}

impl TokenCandidate {
    pub const fn new(id: TokenId, score: f64) -> Self {
        Self { id, score }
    }

    pub const fn id(self) -> TokenId {
        self.id
    }

    pub const fn score(self) -> f64 {
        self.score
    }
}

/// Deterministic token surface required by AI-backed [`crate::Stego`] profiles.
///
/// Sender and receiver must use the same fingerprint, tokenizer, model weights,
/// scores, and candidate filtering. A remote or nondeterministic inference API
/// is not suitable unless the application makes those properties reproducible.
pub trait LanguageModel: Send + Sync {
    fn fingerprint(&self) -> &str;

    fn tokenize(&self, text: &str) -> Result<Vec<TokenId>, StegoError>;

    fn detokenize(&self, tokens: &[TokenId]) -> Result<String, StegoError>;

    fn next_candidates(
        &self,
        context: &[TokenId],
        generated: &[TokenId],
        count: usize,
    ) -> Result<Vec<TokenCandidate>, StegoError>;

    /// Reports whether generated tokens end at a natural visible boundary.
    fn is_natural_boundary(&self, _generated: &[TokenId]) -> Result<bool, StegoError> {
        Ok(true)
    }
}

impl<T: LanguageModel + ?Sized> LanguageModel for Box<T> {
    fn fingerprint(&self) -> &str {
        (**self).fingerprint()
    }

    fn tokenize(&self, text: &str) -> Result<Vec<TokenId>, StegoError> {
        (**self).tokenize(text)
    }

    fn detokenize(&self, tokens: &[TokenId]) -> Result<String, StegoError> {
        (**self).detokenize(tokens)
    }

    fn next_candidates(
        &self,
        context: &[TokenId],
        generated: &[TokenId],
        count: usize,
    ) -> Result<Vec<TokenCandidate>, StegoError> {
        (**self).next_candidates(context, generated, count)
    }

    fn is_natural_boundary(&self, generated: &[TokenId]) -> Result<bool, StegoError> {
        (**self).is_natural_boundary(generated)
    }
}
