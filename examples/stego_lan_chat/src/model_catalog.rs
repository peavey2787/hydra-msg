#[derive(Clone, Copy)]
pub(crate) struct ModelEntry {
    pub id: &'static str,
    pub label: &'static str,
    pub repository: &'static str,
    pub revision: &'static str,
    pub estimated_download_mb: u32,
    pub minimum_ram_gb: u8,
    pub context_tokens: u32,
    pub speed: &'static str,
    pub quality: &'static str,
    pub summary: &'static str,
}

pub(crate) const MODELS: [ModelEntry; 4] = [
    ModelEntry {
        id: "smollm2-135m",
        label: "SmolLM2 135M Instruct",
        repository: "HuggingFaceTB/SmolLM2-135M-Instruct",
        revision: "12fd25f77366fa6b3b4b768ec3050bf629380bac",
        estimated_download_mb: 270,
        minimum_ram_gb: 2,
        context_tokens: 8192,
        speed: "fastest CPU option",
        quality: "basic",
        summary: "Best first run and the recommendation for low-resource machines; its 8K context fits ordinary compact chat envelopes.",
    },
    ModelEntry {
        id: "smollm2-360m",
        label: "SmolLM2 360M Instruct",
        repository: "HuggingFaceTB/SmolLM2-360M-Instruct",
        revision: "a10cc1512eabd3dde888204e902eca88bddb4951",
        estimated_download_mb: 720,
        minimum_ram_gb: 4,
        context_tokens: 8192,
        speed: "fast on modern CPUs",
        quality: "balanced",
        summary: "A quality step up while retaining enough context for normal compact chat envelopes.",
    },
    ModelEntry {
        id: "qwen-0.5b",
        label: "Qwen2.5 0.5B Instruct",
        repository: "Qwen/Qwen2.5-0.5B-Instruct",
        revision: "7ae557604adf67be50417f59c2c2f167def9a775",
        estimated_download_mb: 1050,
        minimum_ram_gb: 5,
        context_tokens: 32768,
        speed: "slower on CPU",
        quality: "best long-context option",
        summary: "Recommended on stronger machines when longer cover texts matter.",
    },
    ModelEntry {
        id: "tinyllama",
        label: "TinyLlama 1.1B Chat",
        repository: "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
        revision: "fe8a4ea1ffedaf415f4da2f062534de366a451e6",
        estimated_download_mb: 2200,
        minimum_ram_gb: 7,
        context_tokens: 2048,
        speed: "slowest CPU option",
        quality: "larger chat model",
        summary: "For experimentation on machines with ample RAM; not the default.",
    },
];

pub(crate) fn find(id: &str) -> Option<ModelEntry> {
    MODELS.iter().copied().find(|model| model.id == id)
}

pub(crate) fn recommendation(logical_cores: usize) -> &'static str {
    match logical_cores {
        0..=4 => "smollm2-135m",
        5..=8 => "smollm2-360m",
        _ => "qwen-0.5b",
    }
}

pub(crate) fn json(logical_cores: usize) -> String {
    let recommended = recommendation(logical_cores);
    let models = MODELS
        .iter()
        .map(|model| {
            format!(
                "{{\"id\":\"{}\",\"label\":\"{}\",\"repository\":\"{}\",\"revision\":\"{}\",\"estimatedDownloadMb\":{},\"minimumRamGb\":{},\"contextTokens\":{},\"speed\":\"{}\",\"quality\":\"{}\",\"summary\":\"{}\",\"serverRecommended\":{}}}",
                model.id,
                model.label,
                model.repository,
                model.revision,
                model.estimated_download_mb,
                model.minimum_ram_gb,
                model.context_tokens,
                model.speed,
                model.quality,
                model.summary,
                model.id == recommended,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"logicalCores\":{logical_cores},\"recommendedModelId\":\"{recommended}\",\"models\":[{models}]}}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalog_id_is_unique_and_resolvable() {
        for (index, model) in MODELS.iter().enumerate() {
            assert_eq!(
                find(model.id).map(|entry| entry.repository),
                Some(model.repository)
            );
            assert!(!MODELS[..index]
                .iter()
                .any(|previous| previous.id == model.id));
            assert_eq!(model.revision.len(), 40);
            assert!(model.revision.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }
}
