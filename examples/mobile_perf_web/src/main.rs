use std::{
    env, fs,
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    path::{Component, Path, PathBuf},
    time::UNIX_EPOCH,
};

use hydra_msg::{Hydra, HydraResult};

fn main() -> HydraResult<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8788".to_string());
    let listener = TcpListener::bind(&addr)?;
    println!("HYDRA mobile perf web host listening on http://{addr}");
    println!("Use 0.0.0.0:8788 to expose it on your LAN.");
    println!("Build WASM first with: examples/mobile_perf_web/scripts/build-wasm.sh");
    println!("Serving WASM package from {}", pkg_dir().display());

    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut buffer = [0_u8; 4096];
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if is_client_disconnect(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let request = String::from_utf8_lossy(&buffer[..read]);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|path| path.split(['?', '#']).next())
            .unwrap_or("/");

        let (status, content_type, body) = if path == "/benchmark" {
            ("200 OK", "application/json", benchmark_json()?.into_bytes())
        } else if path == "/app.js" {
            (
                "200 OK",
                "text/javascript; charset=utf-8",
                include_str!("../web/app.js").as_bytes().to_vec(),
            )
        } else if path == "/pkg-health" {
            pkg_health_json()
        } else if path == "/interop/TV-PERSIST-FULL-000/state_envelope.bin" {
            (
                "200 OK",
                "application/octet-stream",
                include_bytes!(
                    "../../../qa/vectors/persistence/positive/TV-PERSIST-FULL-000/state_envelope.bin"
                )
                .to_vec(),
            )
        } else if let Some(pkg_path) = path.strip_prefix("/pkg/") {
            serve_pkg_file(pkg_path)
        } else {
            (
                "200 OK",
                "text/html; charset=utf-8",
                index_html().into_bytes(),
            )
        };

        let response_head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            body.len()
        );
        if let Err(error) = stream
            .write_all(response_head.as_bytes())
            .and_then(|()| stream.write_all(&body))
        {
            if is_client_disconnect(&error) {
                continue;
            }
            return Err(error.into());
        }
    }

    Ok(())
}

fn is_client_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
    )
}

fn benchmark_json() -> HydraResult<String> {
    let hydra = Hydra::open("target/examples/mobile_perf_web/server", "example-state")?;
    let report = hydra.benchmark()?;
    Ok(format!(
        "{{\"suite\":\"{}\",\"iterations\":{},\"handshakeAvgMs\":{},\"sendReceiveAvgMs\":{}}}",
        report.suite, report.iterations, report.handshake_avg_ms, report.send_receive_avg_ms
    ))
}

fn serve_pkg_file(pkg_path: &str) -> (&'static str, &'static str, Vec<u8>) {
    let Some(path) = safe_pkg_path(pkg_path) else {
        return (
            "400 Bad Request",
            "text/plain; charset=utf-8",
            b"bad pkg path".to_vec(),
        );
    };
    match fs::read(&path) {
        Ok(bytes) => ("200 OK", content_type_for(pkg_path), bytes),
        Err(_) => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            format!(
                "WASM package file not found: /pkg/{pkg_path}. \
                 Build it with examples/mobile_perf_web/scripts/build-wasm.sh, \
                 then restart this host."
            )
            .into_bytes(),
        ),
    }
}

fn pkg_health_json() -> (&'static str, &'static str, Vec<u8>) {
    let js = pkg_dir().join("hydra_msg_wasm.js");
    let wasm = pkg_dir().join("hydra_msg_wasm_bg.wasm");
    let cache_key = pkg_cache_key(&js, &wasm);
    let body = format!(
        "{{\"pkgDir\":\"{}\",\"jsExists\":{},\"wasmExists\":{},\"cacheKey\":\"{}\",\"buildCommand\":\"examples/mobile_perf_web/scripts/build-wasm.sh\"}}",
        json_escape(&pkg_dir().display().to_string()),
        js.is_file(),
        wasm.is_file(),
        json_escape(&cache_key)
    );
    ("200 OK", "application/json", body.into_bytes())
}

fn pkg_cache_key(js: &Path, wasm: &Path) -> String {
    let mut parts = Vec::new();
    for path in [js, wasm] {
        let Ok(metadata) = fs::metadata(path) else {
            parts.push("missing".to_string());
            continue;
        };
        let len = metadata.len();
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        parts.push(format!("{len}-{modified}"));
    }
    parts.join("-")
}

fn safe_pkg_path(pkg_path: &str) -> Option<PathBuf> {
    let relative = Path::new(pkg_path);
    if relative.is_absolute() {
        return None;
    }
    let mut out = pkg_dir();
    for component in relative.components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => return None,
        }
    }
    Some(out)
}

fn pkg_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("web/pkg")
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\"', "\\\"")
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

fn index_html() -> String {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HYDRA facade and persistence benchmark</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; line-height: 1.45; }
    button { font-size: 1rem; padding: .7rem 1rem; margin-right: .5rem; margin-bottom: .5rem; }
    button:disabled { opacity: .55; }
    pre { background: #111; color: #eee; padding: 1rem; overflow: auto; min-height: 16rem; }
    .note { color: #555; }
    code { background: #f3f3f3; padding: .1rem .25rem; }
  </style>
</head>
<body>
  <h1>HYDRA facade and browser persistence benchmark</h1>
  <p class="note">
    Server benchmark runs <code>hydra.benchmark()</code> on the machine hosting this page.
    Browser WASM benchmark and IndexedDB persistence validation run on this device.
  </p>
  <button data-action="server">Run server-side facade benchmark</button>
  <button data-action="wasm">Run browser/device HYDRA WASM benchmark</button>
  <button data-action="persistent-suite">Run IndexedDB persistence validation suite</button>
  <button data-action="persistent-reopen">Reopen persistent profile</button>
  <button data-action="api-misuse">Run browser API misuse guard</button>
  <button data-action="crash-consistency">Run IndexedDB crash-consistency probe</button>
  <button data-action="multi-tab">Run IndexedDB multi-tab concurrency probe</button>
  <button data-action="interop-fixture">Run WASM/native fixture interop probe</button>
  <button data-action="quota">Probe browser quota/lifecycle</button>
  <button data-action="clear">Clear validation profiles</button>
  <pre id="out">Click a button.</pre>
  <script type="module" src="/app.js"></script>
</body>
</html>
"#
    .to_string()
}
