use super::{content_type, package_file_path, percent_decode};

#[test]
fn package_paths_allow_wasm_pack_assets_but_not_escape() {
    assert!(package_file_path("hydra_msg_wasm.js").is_some());
    assert!(package_file_path("snippets/pkg/inline0.js").is_some());
    for invalid in ["", "../secret", "/absolute", "a\\b", "./file.js"] {
        assert!(package_file_path(invalid).is_none(), "accepted {invalid:?}");
    }
}

#[test]
fn content_types_cover_gui_assets() {
    assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
    assert_eq!(content_type("styles.css"), "text/css; charset=utf-8");
    assert_eq!(content_type("app.js"), "text/javascript; charset=utf-8");
    assert_eq!(content_type("module_bg.wasm"), "application/wasm");
    assert_eq!(
        content_type("manifest.webmanifest"),
        "application/manifest+json"
    );
    assert_eq!(content_type("hydra-icon-192.png"), "image/png");
    assert_eq!(content_type("favicon.ico"), "image/x-icon");
}

#[test]
fn percent_decoding_accepts_normal_components_and_rejects_invalid_escapes() {
    assert_eq!(percent_decode("room%20alpha").unwrap(), "room alpha");
    assert_eq!(percent_decode("join%2Fonce").unwrap(), "join/once");
    assert!(percent_decode("broken%2").is_err());
    assert!(percent_decode("broken%XZ").is_err());
}

#[test]
fn gui_contract_is_chat_first_and_has_context_help() {
    let html = include_str!("../web/index.html");
    for required in [
        "conversation-list",
        "message-composer",
        "advanced-drawer",
        "stego-profile",
        "identity-select",
        "contact-card-preview",
        "lobby-preview",
        "storage-mode-label",
        "auth-token",
        "diagnostics-result",
    ] {
        assert!(
            html.contains(&format!("id=\"{required}\"")),
            "missing GUI capability control {required}"
        );
    }
    assert!(html.matches("data-help=").count() >= 12);
    assert!(!html.contains("<summary><span>Identity & profile</span><button"));
    assert!(!html.contains("<label>Members<div"));
    assert!(!html.contains("Public-SDK route console"));

    for option in [
        ">encrypted<",
        ">stego-instant<",
        ">stego-unicode<",
        ">stego hybrid<",
        ">stego-ai<",
    ] {
        assert!(
            html.contains(option),
            "missing composer carrier option {option}"
        );
    }
    assert!(html.contains("id=\"privacy-toggle\""));
    assert!(html.contains("id=\"carrier-view-toggle\""));
    assert!(!html.contains("id=\"show-carrier-toggle\""));
    assert!(html.contains("rel=\"manifest\" href=\"/manifest.webmanifest\""));
    assert!(html.contains("src=\"/hydra-icon-192.png\""));
    let manifest = include_str!("../web/manifest.webmanifest");
    assert!(manifest.contains("\"short_name\": \"HYDRA\""));
    assert!(manifest.contains("/hydra-icon-192.png"));
    assert!(manifest.contains("/hydra-icon-512.png"));

    let app = include_str!("../web/app.js");
    assert!(app.contains("message.stegoView === 'decoded'"));
    assert!(app.contains("message.privacyRevealed = !message.privacyRevealed"));
    assert!(app.contains("setCarrierRevealAll"));
    assert!(app.contains("message.privacyRevealed = this.carrierRevealAll"));
    assert!(app.contains("stego-group-"));
    assert!(app.contains("encodeGroupText"));
    assert!(app.contains("messageViewStore.load"));
    assert!(app.contains("messageViewStore.put"));
    assert!(app.contains("delete-request"));
    assert!(app.contains("delete-response"));
    assert!(app.contains("HANDSHAKE_RESPONSE_TIMEOUT_MS"));
    assert!(app.contains("HANDSHAKE_RETRY_DELAYS_MS"));
    assert!(app.contains("sendHandshakeAttempt"));
    assert!(app.contains("scheduleHandshakeRetry"));
    assert!(app.contains("'handshake-offer', state.offer, state.token"));
    assert!(app.contains("'handshake-answer', answer, attemptToken"));
    assert!(app.contains("state.token !== attemptToken"));
    assert!(app.contains("'handshake-finish', state.finish, state.token"));
    assert!(app.contains("acceptHandshakeFinish(message.from, payload, message.tag)"));
    assert!(app.contains("'handshake-complete', new Uint8Array(), attemptToken"));
    assert!(app.contains("mask.textContent = input.value.replace(/[^\\s]/g, '*'"));
    assert!(!app.contains("Enable stego for replies"));

    let ui = include_str!("../web/ui.js");
    assert!(ui.contains("hasCarrier && !showDecoded"));
    assert!(ui.contains("maskText(message?.text)"));
    assert!(ui.contains("list.scrollTop = oldScrollTop"));
    assert!(ui.contains("carrierScrolls"));
    assert!(ui.contains("Request removal for everyone"));
    assert!(ui.contains("installMessageMenuDismissal"));
    assert!(ui.contains("toggleMessageMenu"));
    assert!(ui.contains("document.addEventListener('pointerdown'"));
    assert!(ui.contains("event.key === 'Escape'"));
    assert!(ui.contains("aria-haspopup=\"menu\""));
    assert!(!ui.contains("Stego ·"));
    assert!(!ui.contains("data-enable-stego"));

    let styles = include_str!("../web/styles.css");
    assert!(styles.contains("height: 100dvh"));
    assert!(styles.contains("grid-template-rows: 62px minmax(0, 1fr) auto"));
    assert!(styles.contains(".message-list { height: 100%; overflow-y: auto"));

    let client = include_str!("../web/hydra-client.js");
    assert!(client.contains("listMessages(contactId)).map(wasmU64)"));
    assert!(client.contains("getMessage(wasmU64(id))"));
    assert!(client.contains("deleteMessage(wasmU64(id))"));
    assert!(!client.contains("listMessages(contactId)).map(Number)"));
    assert!(client.contains("runExclusive(task)"));
    assert!(client.contains("whenIdle()"));

    let protocol = include_str!("../web/message-protocol.js");
    assert!(protocol.contains("newMessageKey"));
    assert!(protocol.contains("decodeControl"));
    assert!(protocol.contains("encodeGroupText"));
    assert!(protocol.contains("decodeGroupText"));

    let store = include_str!("../web/message-view-store.js");
    assert!(store.contains("indexedDB.open"));
    assert!(store.contains("delete copy.stegoView"));
    assert!(store.contains("message: persistedMessage(message)"));
}
