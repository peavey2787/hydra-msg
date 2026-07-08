use std::{
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
};

use hydra_msg::HydraResult;

fn main() -> HydraResult<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8789".to_string());
    let listener = TcpListener::bind(&addr)?;

    println!("HYDRA WebRTC manual carrier example listening on http://{addr}");
    println!("Use 0.0.0.0:8789 to expose it on your LAN.");
    println!("Build WASM first with examples/webrtc_manual_carrier/scripts/build-wasm.ps1 or .sh");
    println!("Contact-card exchange is intentionally manual/out-of-band in this example.");

    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut buffer = [0_u8; 8192];
        let read = stream.read(&mut buffer)?;
        let request = String::from_utf8_lossy(&buffer[..read]);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");

        let (status, content_type, body) = if let Some(pkg_path) = path.strip_prefix("/pkg/") {
            serve_pkg_file(pkg_path)
        } else {
            ("200 OK", "text/html; charset=utf-8", index_html().as_bytes().to_vec())
        };

        let response_head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response_head.as_bytes())?;
        stream.write_all(&body)?;
    }

    Ok(())
}

fn serve_pkg_file(pkg_path: &str) -> (&'static str, &'static str, Vec<u8>) {
    if pkg_path.contains("..") || pkg_path.contains('/') || pkg_path.contains('\\') {
        return ("400 Bad Request", "text/plain; charset=utf-8", b"bad pkg path".to_vec());
    }

    let path = Path::new("examples/webrtc_manual_carrier/web/pkg").join(pkg_path);
    match fs::read(&path) {
        Ok(bytes) => ("200 OK", content_type_for(pkg_path), bytes),
        Err(_) => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"WASM package not found. Build crates/hydra-msg-wasm with wasm-pack first.".to_vec(),
        ),
    }
}

fn content_type_for(path: &str) -> &'static str {
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

fn index_html() -> &'static str {
    include_str!("../web/index.html")
}
