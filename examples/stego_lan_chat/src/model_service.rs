use std::{cell::Cell, path::PathBuf, sync::Mutex};

use hydra_stego::{
    model::{LanguageModel, ModelConfig, ProcessLanguageModel, ProcessModelConfig},
    Stego, StegoProfile,
};

use crate::cover_profile::CoverProfile;
use crate::json;
use crate::model_catalog::{self, ModelEntry};
use crate::model_runtime;

type ServiceResult<T> = Result<T, String>;

pub(crate) struct ModelService {
    active: Mutex<Option<ActiveModel>>,
    deterministic: Stego,
    progress: Mutex<ModelProgress>,
    generation: Mutex<GenerationProgress>,
    logical_cores: usize,
}

struct ActiveModel {
    stego: Stego,
    fingerprint: String,
}

struct ModelProgress {
    entry: Option<ModelEntry>,
    ready: bool,
    loading: bool,
    percent: u8,
    phase: String,
    fingerprint: Option<String>,
    error: Option<String>,
}

impl Default for ModelProgress {
    fn default() -> Self {
        Self {
            entry: None,
            ready: false,
            loading: false,
            percent: 0,
            phase: "No local model loaded".to_owned(),
            fingerprint: None,
            error: None,
        }
    }
}

struct GenerationProgress {
    active: bool,
    tokens: usize,
    phase: String,
    error: Option<String>,
}

impl Default for GenerationProgress {
    fn default() -> Self {
        Self {
            active: false,
            tokens: 0,
            phase: "Idle".to_owned(),
            error: None,
        }
    }
}

impl ModelService {
    pub(crate) fn new() -> Self {
        Self {
            active: Mutex::new(None),
            deterministic: Stego::new(),
            progress: Mutex::new(ModelProgress::default()),
            generation: Mutex::new(GenerationProgress::default()),
            logical_cores: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
        }
    }

    pub(crate) fn catalog_json(&self) -> String {
        model_catalog::json(self.logical_cores)
    }

    pub(crate) fn status_json(&self) -> ServiceResult<String> {
        let progress = self
            .progress
            .lock()
            .map_err(|_| "model-service lock is poisoned".to_owned())?;
        let model_fields = progress.entry.map_or_else(String::new, |entry| {
            format!(
                ",\"modelId\":{},\"label\":{}",
                json::string(entry.id),
                json::string(entry.label),
            )
        });
        let fingerprint = progress
            .fingerprint
            .as_ref()
            .map_or_else(String::new, |value| {
                format!(",\"fingerprint\":{}", json::string(value))
            });
        let error = progress.error.as_ref().map_or_else(String::new, |value| {
            format!(",\"error\":{}", json::string(value))
        });
        Ok(format!(
            "{{\"ready\":{},\"loading\":{},\"progress\":{},\"phase\":{}{}{}{}}}",
            progress.ready,
            progress.loading,
            progress.percent,
            json::string(&progress.phase),
            model_fields,
            fingerprint,
            error,
        ))
    }

    pub(crate) fn generation_json(&self) -> ServiceResult<String> {
        let generation = self
            .generation
            .lock()
            .map_err(|_| "generation-progress lock is poisoned".to_owned())?;
        let error = generation.error.as_ref().map_or_else(String::new, |value| {
            format!(",\"error\":{}", json::string(value))
        });
        Ok(format!(
            "{{\"active\":{},\"tokens\":{},\"phase\":{}{}}}",
            generation.active,
            generation.tokens,
            json::string(&generation.phase),
            error,
        ))
    }

    pub(crate) fn select(&self, id: &str) -> ServiceResult<String> {
        let entry = model_catalog::find(id).ok_or_else(|| "unknown model id".to_owned())?;
        {
            let mut progress = self
                .progress
                .lock()
                .map_err(|_| "model-service lock is poisoned".to_owned())?;
            if progress.ready && progress.entry.is_some_and(|active| active.id == entry.id) {
                drop(progress);
                return self.status_json();
            }
            if progress.loading {
                return Err("another local model is already loading".to_owned());
            }
            *progress = ModelProgress {
                entry: Some(entry),
                ready: false,
                loading: true,
                percent: 1,
                phase: "Preparing the local model runtime".to_owned(),
                fingerprint: None,
                error: None,
            };
        }
        self.active
            .lock()
            .map_err(|_| "model-service lock is poisoned".to_owned())?
            .take();

        let result = self.load(entry);
        match result {
            Ok(active_model) => {
                let fingerprint = active_model.fingerprint.clone();
                *self
                    .active
                    .lock()
                    .map_err(|_| "model-service lock is poisoned".to_owned())? = Some(active_model);
                *self
                    .progress
                    .lock()
                    .map_err(|_| "model-service lock is poisoned".to_owned())? = ModelProgress {
                    entry: Some(entry),
                    ready: true,
                    loading: false,
                    percent: 100,
                    phase: "Local model ready".to_owned(),
                    fingerprint: Some(fingerprint),
                    error: None,
                };
            }
            Err(error) => {
                *self
                    .progress
                    .lock()
                    .map_err(|_| "model-service lock is poisoned".to_owned())? = ModelProgress {
                    entry: Some(entry),
                    ready: false,
                    loading: false,
                    percent: 0,
                    phase: "Model load failed".to_owned(),
                    fingerprint: None,
                    error: Some(error.clone()),
                };
                return Err(error);
            }
        }
        self.status_json()
    }

    fn load(&self, entry: ModelEntry) -> ServiceResult<ActiveModel> {
        let process_config = ProcessModelConfig::new(
            self.python_path()?,
            model_script(),
            entry.repository,
            entry.revision,
        );
        let model = ProcessLanguageModel::spawn_with_progress(&process_config, |percent, phase| {
            self.update_progress(percent, phase)
        })
        .map_err(|error| error.to_string())?;
        let fingerprint = model.fingerprint().to_owned();
        self.update_progress(99, "Initializing stego carrier settings");
        let mut config = ModelConfig::new(fingerprint.clone());
        config.prompt = "Two longtime friends are planning a meetup. Alex writes one complete conversational sentence of at most eight words:"
            .to_owned();
        config.candidate_count = 64;
        config.temperature = 1.0;
        config.maximum_payload_bytes = hydra_session_limit();
        config.maximum_finish_tokens = 48;
        config.maximum_cover_tokens = 32 * 1024;
        let stego = Stego::with_model(model, config).map_err(|error| error.to_string())?;
        Ok(ActiveModel { stego, fingerprint })
    }

    fn update_progress(&self, percent: u8, phase: &str) {
        if let Ok(mut progress) = self.progress.lock() {
            if progress.loading {
                progress.percent = progress.percent.max(percent.min(99));
                progress.phase = phase.to_owned();
            }
        }
    }

    pub(crate) fn hide(&self, payload: &[u8]) -> ServiceResult<Vec<u8>> {
        self.hide_profile(payload, CoverProfile::Arithmetic)
    }

    pub(crate) fn hide_fast(&self, payload: &[u8]) -> ServiceResult<Vec<u8>> {
        self.hide_profile(payload, CoverProfile::FastUnicode)
    }

    pub(crate) fn hide_fast_hybrid(&self, payload: &[u8]) -> ServiceResult<Vec<u8>> {
        self.hide_profile(payload, CoverProfile::FastHybrid)
    }

    pub(crate) fn hide_deterministic(&self, payload: &[u8]) -> ServiceResult<Vec<u8>> {
        self.deterministic
            .encode(payload, StegoProfile::Deterministic)
            .map(String::into_bytes)
            .map_err(|error| error.to_string())
    }

    fn hide_profile(&self, payload: &[u8], profile: CoverProfile) -> ServiceResult<Vec<u8>> {
        let active = self
            .active
            .lock()
            .map_err(|_| "model-service lock is poisoned".to_owned())?;
        let model = active
            .as_ref()
            .ok_or_else(|| "load a stego model before sending cover text".to_owned())?;
        self.set_generation(true, 0, "Framing the encrypted HYDRA envelope", None);
        let last_tokens = Cell::new(0_usize);
        let mut on_progress = |tokens| {
            last_tokens.set(tokens);
            if tokens == 1 || tokens.is_multiple_of(4) {
                self.set_generation(true, tokens, profile.phase(), None);
            }
        };
        let result = model
            .stego
            .encode_with_progress(payload, stego_profile(profile), &mut on_progress)
            .map(String::into_bytes)
            .map_err(|error| error.to_string());
        match &result {
            Ok(_) => self.set_generation(false, last_tokens.get(), profile.ready_phase(), None),
            Err(error) => self.set_generation(
                false,
                last_tokens.get(),
                "Cover generation failed",
                Some(error.clone()),
            ),
        }
        result
    }

    pub(crate) fn reveal(&self, cover: &[u8]) -> ServiceResult<Vec<u8>> {
        self.reveal_profile(cover, CoverProfile::Arithmetic)
    }

    pub(crate) fn reveal_fast(&self, cover: &[u8]) -> ServiceResult<Vec<u8>> {
        self.reveal_profile(cover, CoverProfile::FastUnicode)
    }

    pub(crate) fn reveal_fast_hybrid(&self, cover: &[u8]) -> ServiceResult<Vec<u8>> {
        self.reveal_profile(cover, CoverProfile::FastHybrid)
    }

    pub(crate) fn reveal_deterministic(&self, cover: &[u8]) -> ServiceResult<Vec<u8>> {
        let cover =
            std::str::from_utf8(cover).map_err(|_| "cover request body is not UTF-8".to_owned())?;
        self.deterministic
            .decode(cover, StegoProfile::Deterministic)
            .map_err(|error| error.to_string())
    }

    fn reveal_profile(&self, cover: &[u8], profile: CoverProfile) -> ServiceResult<Vec<u8>> {
        let cover =
            std::str::from_utf8(cover).map_err(|_| "cover request body is not UTF-8".to_owned())?;
        let active = self
            .active
            .lock()
            .map_err(|_| "model-service lock is poisoned".to_owned())?;
        let model = active
            .as_ref()
            .ok_or_else(|| "load the matching stego model before decoding cover text".to_owned())?;
        model
            .stego
            .decode(cover, stego_profile(profile))
            .map_err(|error| error.to_string())
    }

    fn set_generation(&self, active: bool, tokens: usize, phase: &str, error: Option<String>) {
        if let Ok(mut generation) = self.generation.lock() {
            *generation = GenerationProgress {
                active,
                tokens,
                phase: phase.to_owned(),
                error,
            };
        }
    }
}

impl ModelService {
    fn python_path(&self) -> ServiceResult<PathBuf> {
        model_runtime::resolve_or_bootstrap(|percent, phase| self.update_progress(percent, phase))
    }
}

fn model_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("model/hf_model.py")
}

const fn stego_profile(profile: CoverProfile) -> StegoProfile {
    match profile {
        CoverProfile::Arithmetic => StegoProfile::Arithmetic,
        CoverProfile::FastUnicode => StegoProfile::FastUnicode,
        CoverProfile::FastHybrid => StegoProfile::FastHybrid,
    }
}

const fn hydra_session_limit() -> usize {
    64 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unloaded_status_is_valid_json_shape() {
        assert_eq!(
            ModelService::new().status_json().unwrap(),
            "{\"ready\":false,\"loading\":false,\"progress\":0,\"phase\":\"No local model loaded\"}"
        );
    }

    #[test]
    fn idle_generation_status_is_valid_json_shape() {
        assert_eq!(
            ModelService::new().generation_json().unwrap(),
            "{\"active\":false,\"tokens\":0,\"phase\":\"Idle\"}"
        );
    }

    #[test]
    fn missing_model_id_is_rejected_before_runtime_lookup() {
        assert_eq!(
            ModelService::new().select("not-a-model").unwrap_err(),
            "unknown model id"
        );
    }
}
