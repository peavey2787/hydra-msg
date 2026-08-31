#![forbid(unsafe_code)]
#![deny(dead_code, deprecated, unused)]

mod auth_service;
#[path = "../../stego_lan_chat/src/cover_profile.rs"]
mod cover_profile;
mod http;
#[path = "../../stego_lan_chat/src/json.rs"]
mod json;
mod lan_hub;
#[path = "../../stego_lan_chat/src/model_catalog.rs"]
mod model_catalog;
#[path = "../../stego_lan_chat/src/model_runtime.rs"]
mod model_runtime;
#[path = "../../stego_lan_chat/src/model_service.rs"]
mod model_service;

use std::{
    env, fs,
    net::{TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    sync::Arc,
    thread,
};

use auth_service::DemoAuthService;
use http::{
    bad_request, content_type, not_found, read_request, response, service_response, write_response,
    Request, Response,
};
use lan_hub::LanHub;
use model_service::ModelService;

type ServerResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> ServerResult<()> {
    let address = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8787".to_owned());
    let listener = TcpListener::bind(&address)?;
    let services = Arc::new(Services {
        models: ModelService::new(),
        lan: LanHub::new(),
        auth: DemoAuthService::new().map_err(std::io::Error::other)?,
    });

    println!("HYDRA GUI: http://{address}");
    println!("Use 0.0.0.0:8787 to open the app from other devices on your LAN.");
    println!("The browser owns HYDRA state; this host serves assets, LAN rendezvous, and optional AI stego models.");

    for stream in listener.incoming() {
        let services = Arc::clone(&services);
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &services) {
                        eprintln!("GUI request failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }
    Ok(())
}

struct Services {
    models: ModelService,
    lan: LanHub,
    auth: DemoAuthService,
}

fn handle_connection(mut stream: TcpStream, services: &Services) -> ServerResult<()> {
    let response = match read_request(&mut stream) {
        Ok(request) => route(&request, services),
        Err(error) => bad_request(&error),
    };
    write_response(&mut stream, &response)?;
    Ok(())
}

fn route(request: &Request, services: &Services) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => asset("index.html"),
        ("GET", "/styles.css") => asset("styles.css"),
        ("GET", "/app.js") => asset("app.js"),
        ("GET", "/bytes.js") => asset("bytes.js"),
        ("GET", "/hydra-client.js") => asset("hydra-client.js"),
        ("GET", "/lan-client.js") => asset("lan-client.js"),
        ("GET", "/message-protocol.js") => asset("message-protocol.js"),
        ("GET", "/message-view-store.js") => asset("message-view-store.js"),
        ("GET", "/stego-client.js") => asset("stego-client.js"),
        ("GET", "/ui.js") => asset("ui.js"),
        ("GET", "/advanced.js") => asset("advanced.js"),
        ("GET", "/favicon.ico") => asset("favicon.ico"),
        ("GET", "/hydra-icon-192.png") => asset("hydra-icon-192.png"),
        ("GET", "/hydra-icon-512.png") => asset("hydra-icon-512.png"),
        ("GET", "/manifest.webmanifest") => asset("manifest.webmanifest"),
        ("GET", "/api/health") => response(
            "200 OK",
            "application/json; charset=utf-8",
            b"{\"ok\":true}".to_vec(),
        ),
        ("GET", "/api/stego/models") => response(
            "200 OK",
            "application/json; charset=utf-8",
            services.models.catalog_json().into_bytes(),
        ),
        ("GET", "/api/stego/status") => service_response(services.models.status_json(), true),
        ("GET", "/api/stego/generation") => {
            service_response(services.models.generation_json(), true)
        }
        ("POST", "/api/stego/hide") => service_response(services.models.hide(&request.body), false),
        ("POST", "/api/stego/hide-fast") => {
            service_response(services.models.hide_fast(&request.body), false)
        }
        ("POST", "/api/stego/hide-fast-hybrid") => {
            service_response(services.models.hide_fast_hybrid(&request.body), false)
        }
        ("POST", "/api/stego/hide-deterministic") => {
            service_response(services.models.hide_deterministic(&request.body), false)
        }
        ("POST", "/api/stego/reveal") => {
            service_response(services.models.reveal(&request.body), false)
        }
        ("POST", "/api/stego/reveal-fast") => {
            service_response(services.models.reveal_fast(&request.body), false)
        }
        ("POST", "/api/stego/reveal-fast-hybrid") => {
            service_response(services.models.reveal_fast_hybrid(&request.body), false)
        }
        ("POST", "/api/stego/reveal-deterministic") => {
            service_response(services.models.reveal_deterministic(&request.body), false)
        }
        ("POST", path) if path.starts_with("/api/stego/select/") => {
            service_response(services.models.select(&path[18..]), true)
        }
        ("POST", path) if path.starts_with("/api/lan/register/") => {
            service_response(services.lan.register(&path[18..], &request.body), true)
        }
        ("GET", path) if path.starts_with("/api/lan/peers/") => {
            service_response(services.lan.peers(&path[15..]), true)
        }
        ("GET", path) if path.starts_with("/api/lan/inbox/") => {
            service_response(services.lan.receive(&path[15..]), true)
        }
        ("POST", path) if path.starts_with("/api/lan/leave/") => {
            service_response(services.lan.leave(&path[15..]), true)
        }
        ("POST", path) if path.starts_with("/api/lan/send/") => {
            route_lan_send(path, request, services)
        }
        ("POST", path) if path.starts_with("/api/auth/issue/") => route_auth_issue(path, services),
        ("POST", "/api/auth/nullifier") => {
            service_response(services.auth.nullifier(&request.body), false)
        }
        ("POST", path) if path.starts_with("/api/auth/accept/") => {
            route_auth_accept(path, request, services)
        }
        ("POST", path) if path.starts_with("/api/auth/revoke/") => {
            route_auth_revoke(path, request, services)
        }
        ("GET", path) if path.starts_with("/pkg/") => serve_package_file(&path[5..]),
        _ => not_found(),
    }
}

fn route_lan_send(path: &str, request: &Request, services: &Services) -> Response {
    let parts = path[14..].split('/').collect::<Vec<_>>();
    if !(parts.len() == 3 || parts.len() == 4) {
        return response(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            b"LAN send path must contain sender, recipient, message kind, and optional message tag"
                .to_vec(),
        );
    }
    service_response(
        services.lan.send(
            parts[0],
            parts[1],
            parts[2],
            parts.get(3).copied(),
            &request.body,
        ),
        true,
    )
}

fn route_auth_issue(path: &str, services: &Services) -> Response {
    let parts = path[16..].split('/').collect::<Vec<_>>();
    if parts.len() != 3 {
        return bad_request("anonymous-auth issue path is invalid");
    }
    let scope = match percent_decode(parts[0]) {
        Ok(value) => value,
        Err(error) => return bad_request(&error),
    };
    let action = match percent_decode(parts[1]) {
        Ok(value) => value,
        Err(error) => return bad_request(&error),
    };
    let expiry = if parts[2] == "none" {
        None
    } else {
        match parts[2].parse::<u64>() {
            Ok(value) => Some(value),
            Err(_) => return bad_request("anonymous-auth expiry is invalid"),
        }
    };
    service_response(services.auth.issue(&scope, &action, expiry), false)
}

fn route_auth_accept(path: &str, request: &Request, services: &Services) -> Response {
    let parts = path[17..].split('/').collect::<Vec<_>>();
    if parts.len() != 3 {
        return bad_request("anonymous-auth accept path is invalid");
    }
    let scope = match percent_decode(parts[0]) {
        Ok(value) => value,
        Err(error) => return bad_request(&error),
    };
    let action = match percent_decode(parts[1]) {
        Ok(value) => value,
        Err(error) => return bad_request(&error),
    };
    let now = match parts[2].parse::<u64>() {
        Ok(value) => value,
        Err(_) => return bad_request("anonymous-auth current time is invalid"),
    };
    service_response(
        services.auth.accept(&request.body, &scope, &action, now),
        true,
    )
}

fn route_auth_revoke(path: &str, request: &Request, services: &Services) -> Response {
    let parts = path[17..].split('/').collect::<Vec<_>>();
    if parts.len() != 2 {
        return bad_request("anonymous-auth revoke path is invalid");
    }
    let scope = match percent_decode(parts[0]) {
        Ok(value) => value,
        Err(error) => return bad_request(&error),
    };
    let action = match percent_decode(parts[1]) {
        Ok(value) => value,
        Err(error) => return bad_request(&error),
    };
    service_response(services.auth.revoke(&request.body, &scope, &action), false)
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("URL component has a truncated percent escape".to_owned());
            }
            let high = hex_nibble(bytes[index + 1])?;
            let low = hex_nibble(bytes[index + 2])?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "URL component is not UTF-8".to_owned())
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("URL component contains an invalid percent escape".to_owned()),
    }
}

fn asset(name: &str) -> Response {
    let bytes: &'static [u8] = match name {
        "index.html" => include_bytes!("../web/index.html"),
        "styles.css" => include_bytes!("../web/styles.css"),
        "app.js" => include_bytes!("../web/app.js"),
        "bytes.js" => include_bytes!("../web/bytes.js"),
        "hydra-client.js" => include_bytes!("../web/hydra-client.js"),
        "lan-client.js" => include_bytes!("../web/lan-client.js"),
        "message-protocol.js" => include_bytes!("../web/message-protocol.js"),
        "message-view-store.js" => include_bytes!("../web/message-view-store.js"),
        "stego-client.js" => include_bytes!("../web/stego-client.js"),
        "ui.js" => include_bytes!("../web/ui.js"),
        "advanced.js" => include_bytes!("../web/advanced.js"),
        "favicon.ico" => include_bytes!("../web/favicon.ico"),
        "hydra-icon-192.png" => include_bytes!("../web/hydra-icon-192.png"),
        "hydra-icon-512.png" => include_bytes!("../web/hydra-icon-512.png"),
        "manifest.webmanifest" => include_bytes!("../web/manifest.webmanifest"),
        _ => return not_found(),
    };
    response("200 OK", content_type(name), bytes.to_vec())
}

fn serve_package_file(name: &str) -> Response {
    let Some(path) = package_file_path(name) else {
        return response(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            b"invalid package path".to_vec(),
        );
    };
    match fs::read(path) {
        Ok(bytes) => response("200 OK", content_type(name), bytes),
        Err(_) => response(
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"WASM package missing; run examples/hydra-gui/scripts/build-wasm first".to_vec(),
        ),
    }
}

fn package_file_path(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('\\') {
        return None;
    }
    let relative = Path::new(name);
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("web/pkg")
            .join(relative),
    )
}

#[cfg(test)]
mod tests;
