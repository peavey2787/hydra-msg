//! Reversible text carriers for opaque HYDRA packets.
//!
//! The crate exposes one application-facing facade: [`Stego`]. Encryption,
//! authentication, sequencing, replay handling, and fragmentation remain the
//! responsibility of `hydra-msg`.

#![forbid(unsafe_code)]

mod api;
mod deterministic;
mod error;
mod frame;
mod generative;
#[cfg(not(target_arch = "wasm32"))]
mod process;

pub use api::{Stego, StegoProfile};
pub use error::StegoError;

/// Advanced model integration used only by AI-backed stego profiles.
///
/// Normal applications only need [`Stego`], [`StegoProfile`], and
/// [`StegoError`]. Implement this module's [`LanguageModel`] trait only when
/// supplying a custom deterministic local inference backend.
pub mod model {
    pub use crate::generative::{LanguageModel, ModelConfig, TokenCandidate, TokenId};
    #[cfg(not(target_arch = "wasm32"))]
    pub use crate::process::{ProcessLanguageModel, ProcessModelConfig};
}
