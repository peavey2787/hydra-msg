use super::{
    assets::{APP_CSS, APP_JS, INDEX_HTML},
    forms::parse_form,
    router::route_request,
    security::{generate_session_token, GuiSecurity, GUI_TOKEN_HEADER},
    server::{
        is_loopback_bind_addr, resolve_bind_addr, resolve_bind_config, GUI_DEFAULT_ADDR,
        GUI_REQUEST_TIMEOUT,
    },
    state::GuiAppState,
};
use crate::gui::http::{
    HttpRequest, GUI_SECURITY_HEADERS, MAX_HTTP_BODY_BYTES, MAX_HTTP_HEADER_BYTES,
};
use std::{
    collections::HashMap,
    io::Write,
    net::{TcpListener, TcpStream},
    thread,
};

fn test_headers_with_host(token: Option<&str>, host: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("host".to_owned(), host.to_owned());
    if let Some(token) = token {
        headers.insert(GUI_TOKEN_HEADER.to_owned(), token.to_owned());
    }
    headers
}

fn test_headers(token: Option<&str>) -> HashMap<String, String> {
    test_headers_with_host(token, "127.0.0.1:8787")
}

fn test_request(method: &str, path: &str, token: Option<&str>) -> HttpRequest {
    test_request_with_body(method, path, token, Vec::new())
}

fn test_request_with_body(
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> HttpRequest {
    HttpRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        headers: test_headers(token),
        body,
    }
}

fn read_http_request_from_bytes(bytes: Vec<u8>) -> Result<HttpRequest, String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let writer = thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        let _ = stream.write_all(&bytes);
    });
    let (mut stream, _) = listener.accept().unwrap();
    let result = HttpRequest::read(&mut stream);
    writer.join().unwrap();
    result
}

#[test]
fn percent_decodes_form_values() {
    let form = parse_form(b"alias=sample+bob&public_key_hex=aa%20bb").unwrap();
    assert_eq!(form.get("alias").unwrap(), "sample bob");
    assert_eq!(form.get("public_key_hex").unwrap(), "aa bb");
}

#[test]
fn default_gui_addr_is_localhost() {
    assert_eq!(resolve_bind_addr(&[]).unwrap(), GUI_DEFAULT_ADDR);
    assert_eq!(
        resolve_bind_addr(&["--addr".to_owned(), "127.0.0.1:0".to_owned()]).unwrap(),
        "127.0.0.1:0",
    );
}

#[test]
fn remote_gui_addr_requires_dangerous_flag() {
    let bind = resolve_bind_config(&["--addr".to_owned(), "0.0.0.0:8787".to_owned()]).unwrap();
    assert!(!bind.dangerous_allow_remote);
    assert!(!is_loopback_bind_addr(&bind.addr).unwrap());
    let dangerous = resolve_bind_config(&[
        "--addr".to_owned(),
        "0.0.0.0:8787".to_owned(),
        "--dangerous-allow-remote".to_owned(),
    ])
    .unwrap();
    assert!(dangerous.dangerous_allow_remote);
}

#[test]
fn static_route_requires_valid_host_only() {
    let security = GuiSecurity::for_tests("test-token");
    let request = test_request("GET", "/app.css", None);
    let app_state = GuiAppState::new();
    let response = route_request(&request, &security, &app_state);
    assert_eq!(response.status_code, 200);
    assert_eq!(response.content_type, "text/css; charset=utf-8");
}

#[test]
fn api_route_requires_session_token() {
    let security = GuiSecurity::for_tests("test-token");
    let request = test_request("GET", "/api/state", None);
    let app_state = GuiAppState::new();
    let response = route_request(&request, &security, &app_state);
    assert_eq!(response.status_code, 403);
    assert!(response.body.contains("missing GUI session token"));
}

#[test]
fn api_route_accepts_valid_session_token() {
    let security = GuiSecurity::for_tests("test-token");
    let request = test_request("GET", "/api/state", Some("test-token"));
    let app_state = GuiAppState::new();
    let response = route_request(&request, &security, &app_state);
    assert_ne!(response.status_code, 403);
}

#[test]
fn post_route_rejects_cross_site_origin() {
    let security = GuiSecurity::for_tests("test-token");
    let mut request = test_request("POST", "/api/config/set", Some("test-token"));
    request
        .headers
        .insert("origin".to_owned(), "http://evil.example".to_owned());
    let app_state = GuiAppState::new();
    let response = route_request(&request, &security, &app_state);
    assert_eq!(response.status_code, 403);
    assert!(response.body.contains("Origin"));
}

#[test]
fn remote_host_header_is_rejected_by_default() {
    let security = GuiSecurity::for_tests("test-token");
    let mut request = test_request("GET", "/app.css", None);
    request.headers = test_headers_with_host(None, "192.0.2.10:8787");
    let app_state = GuiAppState::new();
    let response = route_request(&request, &security, &app_state);
    assert_eq!(response.status_code, 403);
    assert!(response.body.contains("Host"));
}

#[test]
fn all_post_routes_require_token_and_origin_validation() {
    let security = GuiSecurity::for_tests("test-token");
    let app_state = GuiAppState::new();
    let post_routes = [
        "/api/config/set",
        "/api/contacts/my-card",
        "/api/contacts/add",
        "/api/contacts/review",
        "/api/contacts/trust",
        "/api/contacts/verify-qr",
        "/api/bootstrap/create",
        "/api/bootstrap/accept",
        "/api/chats/direct",
        "/api/chats/group",
        "/api/chats/send",
        "/api/chats/receive-review",
        "/api/identity/generate",
        "/api/identity/import-store",
        "/api/identity/import-backup",
        "/api/identity/switch",
        "/api/identity/unlock-session",
        "/api/identity/lock-all",
        "/api/identity/idle-timeout",
        "/api/recovery/export-backup",
        "/api/recovery/inspect-backup",
        "/api/recovery/export-checkpoint",
        "/api/recovery/check-history",
    ];

    for path in post_routes {
        let no_token = test_request("POST", path, None);
        let response = route_request(&no_token, &security, &app_state);
        assert_eq!(
            response.status_code, 403,
            "{path} accepted a missing GUI token"
        );
        assert!(
            response.body.contains("session token"),
            "{path} did not report token failure"
        );

        let mut cross_site = test_request("POST", path, Some("test-token"));
        cross_site
            .headers
            .insert("origin".to_owned(), "http://evil.example".to_owned());
        let response = route_request(&cross_site, &security, &app_state);
        assert_eq!(
            response.status_code, 403,
            "{path} accepted a cross-site Origin"
        );
        assert!(
            response.body.contains("Origin"),
            "{path} did not report Origin failure"
        );
    }
}

#[test]
fn static_assets_include_mobile_accessibility_contract() {
    assert!(INDEX_HTML.contains(r#"name="viewport""#));
    assert!(INDEX_HTML.contains(r#"class="skip-link""#));
    assert!(INDEX_HTML.contains(r#"role="tablist""#));
    assert!(INDEX_HTML.contains(r#"role="tabpanel""#));
    assert!(INDEX_HTML.contains(r#"aria-live="polite""#));
    assert!(INDEX_HTML.contains(r#"id="app-status""#));
    assert!(APP_CSS.contains(":focus-visible"));
    assert!(APP_CSS.contains("@media (max-width: 860px)"));
    assert!(APP_CSS.contains("@media (max-width: 520px)"));
    assert!(APP_CSS.contains("prefers-reduced-motion"));
    assert!(APP_JS.contains("function activateTab"));
    assert!(APP_JS.contains("ArrowRight"));
    assert!(APP_JS.contains("setStatus"));
}

#[test]
fn security_header_block_contains_required_browser_controls() {
    assert!(GUI_SECURITY_HEADERS.contains("Cache-Control: no-store"));
    assert!(GUI_SECURITY_HEADERS.contains("X-Content-Type-Options: nosniff"));
    assert!(GUI_SECURITY_HEADERS.contains("Referrer-Policy: no-referrer"));
    assert!(GUI_SECURITY_HEADERS.contains("Content-Security-Policy:"));
    assert!(GUI_SECURITY_HEADERS.contains("frame-ancestors 'none'"));
    assert!(GUI_SECURITY_HEADERS.contains("form-action 'self'"));
}

#[test]
fn gui_request_timeout_is_bounded() {
    assert_eq!(GUI_REQUEST_TIMEOUT.as_secs(), 5);
}

#[test]
fn oversized_content_length_is_rejected() {
    let request = format!(
        "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nContent-Length: {}\r\n\r\n",
        MAX_HTTP_BODY_BYTES + 1
    );
    let error = match read_http_request_from_bytes(request.into_bytes()) {
        Ok(_) => panic!("oversized body request was accepted"),
        Err(error) => error,
    };
    assert!(error.contains("body too large"));
}

#[test]
fn oversized_header_is_rejected() {
    let mut request = b"GET / HTTP/1.1\r\n".to_vec();
    request.extend_from_slice(b"X-Long: ");
    request.resize(request.len() + MAX_HTTP_HEADER_BYTES + 1, b'a');
    let error = match read_http_request_from_bytes(request) {
        Ok(_) => panic!("oversized header request was accepted"),
        Err(error) => error,
    };
    assert!(error.contains("header too large"));
}

#[test]
fn api_state_does_not_return_private_secret_fields() {
    let security = GuiSecurity::for_tests("test-token");
    let request = test_request("GET", "/api/state", Some("test-token"));
    let app_state = GuiAppState::new();
    let response = route_request(&request, &security, &app_state);
    if response.status_code == 200 {
        assert!(!response.body.contains("password"));
        assert!(!response.body.contains("private_key"));
        assert!(!response.body.contains("private_seed"));
        assert!(!response.body.contains("identity_seed"));
    }
}

#[test]
fn index_injects_process_token() {
    let security = GuiSecurity::for_tests("test-token");
    let request = test_request("GET", "/", None);
    let app_state = GuiAppState::new();
    let response = route_request(&request, &security, &app_state);
    assert_eq!(response.status_code, 200);
    assert!(response.body.contains("test-token"));
}

#[test]
fn generated_token_is_256_bit_hex() {
    let token = generate_session_token().unwrap();
    assert_eq!(token.len(), 64);
    assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
}
