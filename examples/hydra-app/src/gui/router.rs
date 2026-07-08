use super::{
    assets::{APP_CSS, APP_JS},
    handlers::{
        api_bootstrap_accept, api_bootstrap_create, api_chat_create_direct, api_chat_create_group,
        api_chat_receive_review, api_chat_send, api_config_set, api_contacts_add,
        api_contacts_my_card, api_contacts_review, api_contacts_trust, api_contacts_verify_qr,
        api_identity_generate, api_identity_idle_timeout, api_identity_import_backup,
        api_identity_import_store, api_identity_lock_all, api_identity_switch,
        api_identity_unlock_session, api_recovery_check_history, api_recovery_export_backup,
        api_recovery_export_checkpoint, api_recovery_inspect_backup, api_state,
    },
    html::render_index_html,
    http::{asset_response, html_response, json_error, json_response, HttpRequest, HttpResponse},
    security::GuiSecurity,
    state::GuiAppState,
};

pub(crate) fn route_request(
    request: &HttpRequest,
    security: &GuiSecurity,
    app_state: &GuiAppState,
) -> HttpResponse {
    if let Err(error) = security.authorize(request) {
        return HttpResponse::new(
            403,
            "Forbidden",
            "application/json; charset=utf-8",
            json_error(&error),
        );
    }
    let result = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            Ok(html_response(render_index_html(security.token())))
        }
        ("GET", "/app.css") => Ok(asset_response("text/css; charset=utf-8", APP_CSS)),
        ("GET", "/app.js") => Ok(asset_response(
            "application/javascript; charset=utf-8",
            APP_JS,
        )),
        ("GET", "/api/state") => api_state(app_state).map(json_response),
        ("POST", "/api/config/set") => api_config_set(&request.body, app_state).map(json_response),
        ("POST", "/api/contacts/my-card") => api_contacts_my_card(app_state).map(json_response),
        ("POST", "/api/contacts/add") => api_contacts_add(&request.body).map(json_response),
        ("POST", "/api/contacts/review") => api_contacts_review(&request.body).map(json_response),
        ("POST", "/api/contacts/trust") => api_contacts_trust(&request.body).map(json_response),
        ("POST", "/api/contacts/verify-qr") => {
            api_contacts_verify_qr(&request.body).map(json_response)
        }
        ("POST", "/api/bootstrap/create") => {
            api_bootstrap_create(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/bootstrap/accept") => api_bootstrap_accept(&request.body).map(json_response),
        ("POST", "/api/chats/direct") => {
            api_chat_create_direct(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/chats/group") => {
            api_chat_create_group(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/chats/send") => api_chat_send(&request.body, app_state).map(json_response),
        ("POST", "/api/chats/receive-review") => {
            api_chat_receive_review(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/identity/generate") => {
            api_identity_generate(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/identity/import-store") => {
            api_identity_import_store(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/identity/import-backup") => {
            api_identity_import_backup(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/identity/switch") => {
            api_identity_switch(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/identity/unlock-session") => {
            api_identity_unlock_session(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/identity/lock-all") => api_identity_lock_all(app_state).map(json_response),
        ("POST", "/api/identity/idle-timeout") => {
            api_identity_idle_timeout(&request.body, app_state).map(json_response)
        }
        ("POST", "/api/recovery/export-backup") => {
            api_recovery_export_backup(&request.body).map(json_response)
        }
        ("POST", "/api/recovery/inspect-backup") => {
            api_recovery_inspect_backup(&request.body).map(json_response)
        }
        ("POST", "/api/recovery/export-checkpoint") => {
            api_recovery_export_checkpoint(&request.body).map(json_response)
        }
        ("POST", "/api/recovery/check-history") => {
            api_recovery_check_history(&request.body).map(json_response)
        }
        _ => Ok(HttpResponse::new(
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            "not found".to_owned(),
        )),
    };
    result.unwrap_or_else(|error| {
        HttpResponse::new(
            400,
            "Bad Request",
            "application/json; charset=utf-8",
            json_error(&error),
        )
    })
}
