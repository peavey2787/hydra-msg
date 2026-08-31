use crate::{
    deterministic::DeterministicCodec,
    generative::{GenerativeCodec, LanguageModel, ModelConfig},
    StegoError,
};

/// One of the four supported steganographic carrier profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoProfile {
    /// Model-free technical telemetry carrier.
    Deterministic,
    /// Short AI cover plus Unicode variation-selector payload.
    FastUnicode,
    /// Short AI introduction plus printable grammatical carrier text.
    FastHybrid,
    /// Probability-weighted arithmetic coding over a deterministic model.
    Arithmetic,
}

impl StegoProfile {
    pub const fn requires_model(self) -> bool {
        !matches!(self, Self::Deterministic)
    }
}

/// Production facade for all HYDRA steganographic carrier profiles.
///
/// Construct with [`Stego::new`] for deterministic-only operation or
/// [`Stego::with_model`] to enable all four profiles.
pub struct Stego {
    deterministic: DeterministicCodec,
    generative: Option<GenerativeCodec<Box<dyn LanguageModel>>>,
}

impl Default for Stego {
    fn default() -> Self {
        Self::new()
    }
}

impl Stego {
    /// Creates a deterministic-only stego facade for compact HYDRA envelopes.
    ///
    /// The payload ceiling is the crate's 64 KiB compact-envelope limit.
    pub fn new() -> Self {
        Self {
            deterministic: DeterministicCodec::try_new(crate::frame::MAX_PAYLOAD_BYTES)
                .expect("the fixed compact-envelope stego limit is valid"),
            generative: None,
        }
    }

    /// Creates a stego facade with all four profiles enabled.
    ///
    /// `config.expected_fingerprint` must exactly match the loaded model.
    pub fn with_model<M>(model: M, config: ModelConfig) -> Result<Self, StegoError>
    where
        M: LanguageModel + 'static,
    {
        let maximum_payload_bytes = config.maximum_payload_bytes;
        let model: Box<dyn LanguageModel> = Box::new(model);
        Ok(Self {
            deterministic: DeterministicCodec::try_new(maximum_payload_bytes)?,
            generative: Some(GenerativeCodec::new(model, config)?),
        })
    }

    /// Encodes opaque bytes with the selected stego profile.
    pub fn encode(&self, payload: &[u8], profile: StegoProfile) -> Result<String, StegoError> {
        self.encode_with_progress(payload, profile, |_| {})
    }

    /// Encodes while reporting selected AI cover tokens.
    ///
    /// Deterministic mode performs no model inference and therefore does not
    /// invoke the callback.
    pub fn encode_with_progress<F>(
        &self,
        payload: &[u8],
        profile: StegoProfile,
        on_progress: F,
    ) -> Result<String, StegoError>
    where
        F: FnMut(usize),
    {
        match profile {
            StegoProfile::Deterministic => self.deterministic.hide(payload),
            StegoProfile::Arithmetic => self
                .generative(profile)?
                .hide_with_progress(payload, on_progress),
            StegoProfile::FastUnicode => self
                .generative(profile)?
                .hide_fast_with_progress(payload, on_progress),
            StegoProfile::FastHybrid => self
                .generative(profile)?
                .hide_fast_hybrid_with_progress(payload, on_progress),
        }
    }

    /// Recovers opaque bytes from a carrier using the explicitly selected
    /// profile. Profile auto-detection is intentionally not performed.
    pub fn decode(&self, cover_text: &str, profile: StegoProfile) -> Result<Vec<u8>, StegoError> {
        match profile {
            StegoProfile::Deterministic => self.deterministic.reveal(cover_text),
            StegoProfile::Arithmetic => self.generative(profile)?.reveal(cover_text),
            StegoProfile::FastUnicode => self.generative(profile)?.reveal_fast(cover_text),
            StegoProfile::FastHybrid => self.generative(profile)?.reveal_fast_hybrid(cover_text),
        }
    }

    fn generative(
        &self,
        profile: StegoProfile,
    ) -> Result<&GenerativeCodec<Box<dyn LanguageModel>>, StegoError> {
        debug_assert!(profile.requires_model());
        self.generative.as_ref().ok_or(StegoError::ModelRequired)
    }
}
