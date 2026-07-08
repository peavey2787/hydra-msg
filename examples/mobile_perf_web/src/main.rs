use std::{
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
};

use hydra_msg::{Hydra, HydraResult};

fn main() -> HydraResult<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8788".to_string());
    let listener = TcpListener::bind(&addr)?;
    println!("HYDRA mobile perf web host listening on http://{addr}");
    println!("Use 0.0.0.0:8788 to expose it on your LAN.");
    println!("Build WASM first with: wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg");

    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer)?;
        let request = String::from_utf8_lossy(&buffer[..read]);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");

        let (status, content_type, body) = if path == "/benchmark" {
            ("200 OK", "application/json", benchmark_json()?.into_bytes())
        } else if let Some(pkg_path) = path.strip_prefix("/pkg/") {
            serve_pkg_file(pkg_path)
        } else {
            ("200 OK", "text/html; charset=utf-8", index_html().into_bytes())
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

fn benchmark_json() -> HydraResult<String> {
    let hydra = Hydra::open("target/examples/mobile_perf_web/server")?;
    let report = hydra.benchmark()?;
    Ok(format!(
        "{{\"suite\":\"{}\",\"iterations\":{},\"handshakeAvgMs\":{},\"sendReceiveAvgMs\":{}}}",
        report.suite,
        report.iterations,
        report.handshake_avg_ms,
        report.send_receive_avg_ms
    ))
}

fn serve_pkg_file(pkg_path: &str) -> (&'static str, &'static str, Vec<u8>) {
    if pkg_path.contains("..") || pkg_path.contains('/') || pkg_path.contains('\\') {
        return ("400 Bad Request", "text/plain; charset=utf-8", b"bad pkg path".to_vec());
    }
    let path = Path::new("examples/mobile_perf_web/web/pkg").join(pkg_path);
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

fn index_html() -> String {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HYDRA facade benchmark</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 920px; margin: 2rem auto; padding: 0 1rem; }
    button { font-size: 1rem; padding: .7rem 1rem; margin-right: .5rem; margin-bottom: .5rem; }
    pre { background: #111; color: #eee; padding: 1rem; overflow: auto; }
    .note { color: #555; }
    code { background: #f3f3f3; padding: .1rem .25rem; }
  </style>
</head>
<body>
  <h1>HYDRA facade benchmark</h1>
  <p class="note">
    Server benchmark runs <code>hydra.benchmark()</code> on the machine hosting this page.
    Browser WASM benchmark runs the <code>hydra-msg-wasm</code> facade binding on this device.
  </p>
  <button id="run-server">Run server-side facade benchmark</button>
  <button id="run-wasm">Run browser/device HYDRA WASM benchmark</button>
  <pre id="out">Click a button.</pre>
  <script type="module">
    const out = document.getElementById('out');

    document.getElementById('run-server').addEventListener('click', async () => {
      out.textContent = 'Running server benchmark...';
      const started = performance.now();
      const response = await fetch('/benchmark');
      const json = await response.json();
      const elapsed = performance.now() - started;
      out.textContent = JSON.stringify({ kind: 'server', wallMsFromBrowser: elapsed, ...json }, null, 2);
    });

    document.getElementById('run-wasm').addEventListener('click', async () => {
      out.textContent = 'Loading WASM package...';
      try {
        const mod = await import('/pkg/hydra_msg_wasm.js');
        await mod.default();
        const hydra = mod.WasmHydra.openDefault();
        const started = performance.now();
        const report = hydra.benchmark();
        const elapsed = performance.now() - started;
        out.textContent = JSON.stringify({
          kind: 'browser-wasm',
          wallMsOnThisDevice: elapsed,
          suite: report.suite,
          iterations: report.iterations,
          handshakeAvgMs: report.handshakeAvgMs,
          sendReceiveAvgMs: report.sendReceiveAvgMs
        }, null, 2);
      } catch (error) {
        out.textContent = String(error) + '\n\nBuild WASM first:\nwasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg';
      }
    });
  </script>
</body>
</html>
"#
    .to_string()
}
