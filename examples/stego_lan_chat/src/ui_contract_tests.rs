#[test]
fn ai_model_ui_is_profile_scoped_and_auto_loading() {
    let html = include_str!("../web/index.html");
    let app = include_str!("../web/app.js");

    assert!(html.contains("id=\"ai-model-control\" class=\"ai-model-control\" hidden"));
    assert!(!html.contains("id=\"model-setup\""));
    assert!(!html.contains("id=\"load-model\""));
    assert!(app
        .contains("profile === 'fast' || profile === 'fast-hybrid' || profile === 'arithmetic'",));
    assert!(app.contains("profileRequiresModel() && !activeModelReady()"));
    assert!(app.contains("ui['ai-model-select'].addEventListener('change'"));
    assert!(app.contains("status.modelId !== requestedModelId"));
}

#[test]
fn deterministic_profile_never_requires_ai_model_readiness() {
    let app = include_str!("../web/app.js");
    assert!(!app.contains("return profile !== 'deterministic'"));
    assert!(app.contains("ui['ai-model-control'].hidden = !required"));
}
