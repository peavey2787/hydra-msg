mod cover_profile;
mod json;
mod model_catalog;
mod model_runtime;
mod model_service;
mod peer_broker;
#[cfg(test)]
mod ui_contract_tests;

use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    sync::Arc,
    thread,
};

use model_service::ModelService;
use peer_broker::PeerBroker;

type ServerResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

fn main() -> ServerResult<()> {
    let address = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8790".to_owned());
    let listener = TcpListener::bind(&address)?;
    let services = Arc::new(Services {
        models: ModelService::new(),
        peers: PeerBroker::new(),
    });

    println!("HYDRA steganographic LAN chat: http://{address}");
    println!("Use 0.0.0.0:8790 to make the page reachable on your LAN.");
    println!("Build WASM before use. The deterministic cover mode needs no AI runtime.");

    for stream in listener.incoming() {
        let services = Arc::clone(&services);
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &services) {
                        eprintln!("request failed: {error}");
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
    peers: PeerBroker,
}

fn handle_connection(mut stream: TcpStream, services: &Services) -> ServerResult<()> {
    let response = match read_request(&mut stream) {
        Ok(request) => route(&request, services),
        Err(error) => response(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            error.into_bytes(),
        ),
    };
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    Ok(())
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut bytes = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(position) = find_bytes(&bytes, b"\r\n\r\n") {
            break position + 4;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err("request headers exceed 32 KiB".to_owned());
        }
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("request ended before its headers".to_owned());
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "request headers are not UTF-8".to_owned())?;
    let mut lines = header.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_owned())?
        .split_whitespace();
    let method = request_line
        .next()
        .ok_or_else(|| "missing request method".to_owned())?
        .to_owned();
    let path = request_line
        .next()
        .ok_or_else(|| "missing request path".to_owned())?
        .split('?')
        .next()
        .unwrap_or("/")
        .to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|_| "invalid Content-Length".to_owned())?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err("request body exceeds 8 MiB".to_owned());
    }
    let total = header_end
        .checked_add(content_length)
        .ok_or_else(|| "request length overflow".to_owned())?;
    while bytes.len() < total {
        let mut chunk = [0_u8; 16 * 1024];
        let read = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("request body is truncated".to_owned());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > total {
            bytes.truncate(total);
        }
    }
    Ok(Request {
        method,
        path,
        body: bytes[header_end..total].to_vec(),
    })
}

struct Response {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

fn route(request: &Request, services: &Services) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => ok(
            "text/html; charset=utf-8",
            include_bytes!("../web/index.html"),
        ),
        ("GET", "/app.js") => ok(
            "text/javascript; charset=utf-8",
            include_bytes!("../web/app.js"),
        ),
        ("GET", "/bytes.js") => ok(
            "text/javascript; charset=utf-8",
            include_bytes!("../web/bytes.js"),
        ),
        ("GET", "/carrier.js") => ok(
            "text/javascript; charset=utf-8",
            include_bytes!("../web/carrier.js"),
        ),
        ("GET", "/lan-peer.js") => ok(
            "text/javascript; charset=utf-8",
            include_bytes!("../web/lan-peer.js"),
        ),
        ("GET", "/styles.css") => ok(
            "text/css; charset=utf-8",
            include_bytes!("../web/styles.css"),
        ),
        ("GET", "/favicon.ico") => ok("image/x-icon", include_bytes!("../web/favicon.ico")),
        ("GET", "/hydra-icon-192.png") => {
            ok("image/png", include_bytes!("../web/hydra-icon-192.png"))
        }
        ("GET", "/hydra-icon-512.png") => {
            ok("image/png", include_bytes!("../web/hydra-icon-512.png"))
        }
        ("GET", "/manifest.webmanifest") => ok(
            "application/manifest+json",
            include_bytes!("../web/manifest.webmanifest"),
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
        ("POST", path) if path.starts_with("/api/lan/join/") => {
            service_response(services.peers.join(&path[14..], &request.body), true)
        }
        ("GET", path) if path.starts_with("/api/lan/status/") => {
            service_response(services.peers.status(&path[16..]), true)
        }
        ("POST", path) if path.starts_with("/api/lan/offer/") => service_response(
            services.peers.signal(&path[15..], "offer", &request.body),
            true,
        ),
        ("POST", path) if path.starts_with("/api/lan/answer/") => service_response(
            services.peers.signal(&path[16..], "answer", &request.body),
            true,
        ),
        ("POST", path) if path.starts_with("/api/lan/leave/") => {
            service_response(services.peers.leave(&path[15..]), true)
        }
        ("GET", path) if path.starts_with("/pkg/") => serve_package_file(&path[5..]),
        _ => not_found(),
    }
}

fn service_response(result: Result<impl Into<Vec<u8>>, String>, json: bool) -> Response {
    match result {
        Ok(body) => response(
            "200 OK",
            if json {
                "application/json; charset=utf-8"
            } else {
                "application/octet-stream"
            },
            body.into(),
        ),
        Err(error) => response(
            "409 Conflict",
            "text/plain; charset=utf-8",
            error.into_bytes(),
        ),
    }
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
            b"WASM package missing; run the example build-wasm script first".to_vec(),
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

fn ok(content_type: &'static str, body: &'static [u8]) -> Response {
    response("200 OK", content_type, body.to_vec())
}

fn not_found() -> Response {
    response(
        "404 Not Found",
        "text/plain; charset=utf-8",
        b"not found".to_vec(),
    )
}

fn response(status: &'static str, content_type: &'static str, body: Vec<u8>) -> Response {
    Response {
        status,
        content_type,
        body,
    }
}

fn content_type(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else if path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{content_type, package_file_path};

    #[test]
    fn package_path_allows_wasm_pack_snippet_modules() {
        let path = package_file_path("snippets/hydra-msg-abc123/inline0.js")
            .expect("nested wasm-pack snippet path should be valid");
        assert!(path.ends_with("pkg/snippets/hydra-msg-abc123/inline0.js"));
        assert_eq!(
            content_type(path.to_str().expect("UTF-8 path")),
            "text/javascript; charset=utf-8"
        );
    }

    #[test]
    fn package_path_rejects_escape_and_non_url_paths() {
        for invalid in [
            "",
            "../secret",
            "snippets/../../secret",
            "/absolute.js",
            "snippets\\module.js",
            "./hydra_msg.js",
        ] {
            assert!(package_file_path(invalid).is_none(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn package_content_types_cover_generated_assets() {
        assert_eq!(content_type("module.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("module_bg.wasm"), "application/wasm");
        assert_eq!(content_type("package.json"), "application/json");
    }

    #[test]
    fn model_catalog_bootstraps_independently_from_wasm_session() {
        let app = include_str!("../web/app.js");
        let boot_start = app
            .find("async function boot()")
            .expect("browser boot function must exist");
        let boot = &app[boot_start..];
        let catalog = boot
            .find("await initializeModelUi()")
            .expect("boot must initialize the AI model catalog");
        let session = boot
            .find("void startAutomaticSession()")
            .expect("boot must start the encrypted session independently");
        assert!(
            catalog < session,
            "model catalog must render before WASM session startup"
        );
        assert!(
            !boot[..session].contains("await loadWasm()"),
            "missing WASM must not prevent model choices from rendering"
        );
    }
}
