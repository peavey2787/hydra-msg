use crate::text::{hex_decode, hex_encode, json_escape, parse_form};
use hydra_app_core::{
    ContactId, HydraApp, HydraLobbyPolicy, HydraMessage, IdentityId, LobbyId,
    ReceivedHydraMessage,
};
use std::{
    collections::HashMap,
    error::Error,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
};

const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

struct Response {
    status: &'static str,
    content_type: &'static str,
    body: String,
}

pub fn serve(
    data_dir: PathBuf,
    state_password: String,
    address: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    if !address.ip().is_loopback() {
        return Err("hydra-app GUI only binds to loopback addresses".into());
    }
    let app = Arc::new(Mutex::new(HydraApp::open(data_dir, state_password)?));
    let listener = TcpListener::bind(address)?;
    println!("HYDRA GUI listening on http://{address}");
    for stream in listener.incoming() {
        let app = Arc::clone(&app);
        drop(thread::spawn(move || {
            if let Err(error) = handle_connection(stream, app, address) {
                eprintln!("GUI request error: {error}");
            }
        }));
    }
    Ok(())
}

fn handle_connection(
    stream: Result<TcpStream, std::io::Error>,
    app: Arc<Mutex<HydraApp>>,
    address: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let mut stream = stream?;
    let request = read_request(&mut stream)?;
    let response = route(request, &app, address);
    write_response(&mut stream, response)?;
    Ok(())
}

fn route(request: Request, app: &Arc<Mutex<HydraApp>>, address: SocketAddr) -> Response {
    if request.method == "GET" && request.path == "/" {
        return html_response(index_html(address));
    }
    if request.method == "GET" {
        return match handle_get(&request.path, app) {
            Ok(body) => json_response("200 OK", body),
            Err(error) => json_error("400 Bad Request", &error),
        };
    }
    if request.method != "POST" {
        return json_error("405 Method Not Allowed", "method not allowed");
    }
    if request.headers.get("x-hydra-request").map(String::as_str) != Some("1") {
        return json_error("403 Forbidden", "missing HYDRA same-origin request header");
    }
    if let Some(origin) = request.headers.get("origin") {
        if origin != &format!("http://{address}") {
            return json_error("403 Forbidden", "origin is not the local HYDRA GUI");
        }
    }
    let fields = match parse_form(&request.body) {
        Ok(fields) => fields,
        Err(error) => return json_error("400 Bad Request", &error),
    };
    match handle_post(&request.path, &fields, app) {
        Ok(body) => json_response("200 OK", body),
        Err(error) => json_error("400 Bad Request", &error),
    }
}

fn handle_get(path: &str, app: &Arc<Mutex<HydraApp>>) -> Result<String, String> {
    let app = app.lock().map_err(|_| "app state lock is poisoned")?;
    match path {
        "/api/identity/list" => {
            let values = app
                .list_identities()
                .into_iter()
                .map(|identity| {
                    format!(
                        "{{\"id\":\"{}\",\"label\":\"{}\",\"unlocked\":{}}}",
                        identity.id().hex(),
                        json_escape(identity.label()),
                        identity.unlocked()
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!("{{\"identities\":[{values}]}}"))
        }
        "/api/contacts/list" => {
            let values = app
                .list_contacts()
                .into_iter()
                .map(|contact| contact_json(&contact))
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!("{{\"contacts\":[{values}]}}"))
        }
        "/api/lobbies/list" => {
            let values = app
                .list_lobbies()
                .into_iter()
                .map(|lobby| lobby_json(&lobby))
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!("{{\"lobbies\":[{values}]}}"))
        }
        "/api/backup/status" | "/api/storage/status" => {
            let status = app.storage_status();
            Ok(format!(
                "{{\"data_dir\":\"{}\",\"encrypted_state\":{}}}",
                json_escape(&status.data_dir.display().to_string()),
                status.encrypted_state
            ))
        }
        "/api/storage/debug-status" => {
            let status = app.storage_debug_status();
            Ok(format!(
                concat!(
                    "{{\"data_dir\":\"{}\",\"encrypted_state\":{},",
                    "\"identity_count\":{},\"contact_count\":{},",
                    "\"session_count\":{},\"message_count\":{},",
                    "\"lobby_count\":{},\"state_generation\":{}}}"
                ),
                json_escape(&status.data_dir.display().to_string()),
                status.encrypted_state,
                status.identity_count,
                status.contact_count,
                status.session_count,
                status.message_count,
                status.lobby_count,
                status.state_generation
            ))
        }
        _ => Err("route not found".to_owned()),
    }
}

fn handle_post(
    path: &str,
    fields: &HashMap<String, String>,
    app: &Arc<Mutex<HydraApp>>,
) -> Result<String, String> {
    let mut app = app.lock().map_err(|_| "app state lock is poisoned")?;
    match path {
        "/api/identity/generate" => {
            let id = app
                .generate_identity(field(fields, "label")?, field(fields, "password")?)
                .map_err(sdk_error)?;
            Ok(format!("{{\"id\":\"{}\"}}", id.hex()))
        }
        "/api/identity/switch" => {
            let id = identity_id(fields)?;
            app.switch_identity(id, field(fields, "password")?)
                .map_err(sdk_error)?;
            ok_json()
        }
        "/api/identity/unlock" => {
            let id = identity_id(fields)?;
            app.unlock_identity(id, field(fields, "password")?)
                .map_err(sdk_error)?;
            ok_json()
        }
        "/api/identity/lock" => {
            match fields.get("id").map(String::as_str) {
                None | Some("") | Some("active") => {
                    app.lock_active_identity().map_err(sdk_error)?;
                }
                Some(id) => app
                    .lock_identity(IdentityId::from_hex(id).map_err(sdk_error)?)
                    .map_err(sdk_error)?,
            }
            ok_json()
        }
        "/api/identity/export" => {
            let bytes = app
                .export_identity(identity_id(fields)?, field(fields, "password")?)
                .map_err(sdk_error)?;
            bytes_json("identity", &bytes)
        }
        "/api/identity/import" => {
            let bytes = bytes_field(fields, "identity_hex")?;
            let id = app
                .import_identity(
                    bytes,
                    field(fields, "password")?,
                    field(fields, "label")?,
                )
                .map_err(sdk_error)?;
            Ok(format!("{{\"id\":\"{}\"}}", id.hex()))
        }
        "/api/identity/change-password" => {
            app.change_identity_password(
                identity_id(fields)?,
                field(fields, "old_password")?,
                field(fields, "new_password")?,
            )
            .map_err(sdk_error)?;
            ok_json()
        }
        "/api/identity/delete" => {
            app.delete_identity(identity_id(fields)?, field(fields, "password")?)
                .map_err(sdk_error)?;
            ok_json()
        }
        "/api/contacts/my-card" => {
            let bytes = match fields.get("label").map(String::as_str) {
                None | Some("") => app.create_contact_card(),
                Some(label) => app.create_labeled_contact_card(label),
            }
            .map_err(sdk_error)?;
            bytes_json("card", &bytes)
        }
        "/api/contacts/preview" => {
            let contact = app
                .preview_contact_card(bytes_field(fields, "card_hex")?)
                .map_err(sdk_error)?;
            Ok(contact_json(&contact))
        }
        "/api/contacts/add" => {
            let contact = app
                .add_contact(bytes_field(fields, "card_hex")?)
                .map_err(sdk_error)?;
            Ok(contact_json(&contact))
        }
        "/api/contacts/verify" => {
            app.verify_contact(contact_id(fields)?, field(fields, "safety_code")?)
                .map_err(sdk_error)?;
            ok_json()
        }
        "/api/contacts/export" => {
            let bytes = app.export_contacts().map_err(sdk_error)?;
            bytes_json("contacts", &bytes)
        }
        "/api/contacts/import" => {
            app.import_contacts(bytes_field(fields, "contacts_hex")?)
                .map_err(sdk_error)?;
            ok_json()
        }
        "/api/handshake/offer" => {
            let bytes = app.handshake_offer(contact_id(fields)?).map_err(sdk_error)?;
            bytes_json("offer", &bytes)
        }
        "/api/handshake/answer" => {
            let bytes = app
                .handshake_answer(bytes_field(fields, "offer_hex")?)
                .map_err(sdk_error)?;
            bytes_json("answer", &bytes)
        }
        "/api/handshake/finish" => {
            app.finish_handshake(bytes_field(fields, "answer_hex")?)
                .map_err(sdk_error)?;
            ok_json()
        }
        "/api/messages/send" => {
            let packets = app
                .send_message(
                    contact_id(fields)?,
                    HydraMessage::text(field(fields, "text")?),
                )
                .map_err(sdk_error)?;
            let values = packets
                .iter()
                .map(|packet| format!("\"{}\"", hex_encode(packet)))
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!("{{\"packets\":[{values}]}}"))
        }
        "/api/messages/receive" => {
            let received = app
                .receive_message(bytes_field(fields, "packet_hex")?)
                .map_err(sdk_error)?;
            Ok(received_json(received.as_ref()))
        }
        "/api/lobbies/create" => {
            let max_members = field(fields, "max_members")?
                .parse::<usize>()
                .map_err(|_| "max_members is invalid")?;
            let lobby = app
                .create_lobby(HydraLobbyPolicy::new(
                    field(fields, "label")?,
                    max_members,
                ))
                .map_err(sdk_error)?;
            Ok(lobby_json(&lobby))
        }
        "/api/lobbies/add-member" => {
            app.add_lobby_member(lobby_id(fields)?, contact_id(fields)?)
                .map_err(sdk_error)?;
            ok_json()
        }
        "/api/lobbies/invite" => {
            let bytes = app
                .create_lobby_invite(lobby_id(fields)?)
                .map_err(sdk_error)?;
            bytes_json("invite", &bytes)
        }
        "/api/lobbies/join" => {
            let lobby = app
                .join_lobby(bytes_field(fields, "invite_hex")?)
                .map_err(sdk_error)?;
            Ok(lobby_json(&lobby))
        }
        "/api/lobbies/send" => {
            let packets = app
                .send_lobby_message(
                    lobby_id(fields)?,
                    HydraMessage::text(field(fields, "text")?),
                )
                .map_err(sdk_error)?;
            let values = packets
                .iter()
                .map(|packet| {
                    format!(
                        concat!(
                            "{{\"recipient\":\"{}\",\"routing_hint\":\"{}\",",
                            "\"packet_hex\":\"{}\"}}"
                        ),
                        packet.recipient.hex(),
                        hex_encode(&packet.routing_hint.bytes()),
                        hex_encode(&packet.bytes)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!("{{\"packets\":[{values}]}}"))
        }
        "/api/lobbies/receive" => {
            let received = app
                .receive_lobby_message(bytes_field(fields, "packet_hex")?)
                .map_err(sdk_error)?;
            Ok(received_json(received.as_ref()))
        }
        "/api/lobbies/leave" => {
            app.leave_lobby(lobby_id(fields)?).map_err(sdk_error)?;
            ok_json()
        }
        "/api/backup/export" => {
            let bytes = app
                .export_backup(field(fields, "password")?)
                .map_err(sdk_error)?;
            bytes_json("backup", &bytes)
        }
        "/api/backup/verify" => {
            app.verify_backup(
                bytes_field(fields, "backup_hex")?,
                field(fields, "password")?,
            )
            .map_err(sdk_error)?;
            ok_json()
        }
        "/api/backup/import" => {
            app.import_backup(
                bytes_field(fields, "backup_hex")?,
                field(fields, "password")?,
            )
            .map_err(sdk_error)?;
            ok_json()
        }
        "/api/backup/change-state-password" => {
            app.change_state_password(
                field(fields, "old_password")?,
                field(fields, "new_password")?,
            )
            .map_err(sdk_error)?;
            ok_json()
        }
        _ => Err("route not found".to_owned()),
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Request, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("connection closed before HTTP headers".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("HTTP request is too large".into());
        }
        if let Some(index) = find_header_end(&bytes) {
            break index;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or("missing HTTP request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or("missing HTTP method")?.to_owned();
    let raw_path = request_parts.next().ok_or("missing HTTP path")?;
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if headers
                .insert(name.trim().to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
            {
                return Err("duplicate HTTP header".into());
            }
        }
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_REQUEST_BYTES {
        return Err("HTTP request body is too large".into());
    }
    let body_start = header_end + 4;
    while bytes.len().saturating_sub(body_start) < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("connection closed before HTTP body".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("HTTP request is too large".into());
        }
    }
    let body = std::str::from_utf8(&bytes[body_start..body_start + content_length])?.to_owned();
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_response(stream: &mut TcpStream, response: Response) -> Result<(), std::io::Error> {
    let headers = format!(
        concat!(
            "HTTP/1.1 {}\r\n",
            "Content-Type: {}; charset=utf-8\r\n",
            "Content-Length: {}\r\n",
            "Cache-Control: no-store\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ",
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'\r\n",
            "Referrer-Policy: no-referrer\r\n",
            "Connection: close\r\n\r\n"
        ),
        response.status,
        response.content_type,
        response.body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(response.body.as_bytes())
}

fn html_response(body: String) -> Response {
    Response {
        status: "200 OK",
        content_type: "text/html",
        body,
    }
}

fn json_response(status: &'static str, body: String) -> Response {
    Response {
        status,
        content_type: "application/json",
        body,
    }
}

fn json_error(status: &'static str, error: &str) -> Response {
    json_response(
        status,
        format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(error)),
    )
}

fn ok_json() -> Result<String, String> {
    Ok("{\"ok\":true}".to_owned())
}

fn bytes_json(name: &str, bytes: &[u8]) -> Result<String, String> {
    Ok(format!(
        "{{\"{name}_hex\":\"{}\",\"byte_length\":{}}}",
        hex_encode(bytes),
        bytes.len()
    ))
}

fn field<'a>(fields: &'a HashMap<String, String>, name: &str) -> Result<&'a str, String> {
    fields
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing field: {name}"))
}

fn bytes_field(fields: &HashMap<String, String>, name: &str) -> Result<Vec<u8>, String> {
    hex_decode(field(fields, name)?)
}

fn identity_id(fields: &HashMap<String, String>) -> Result<IdentityId, String> {
    IdentityId::from_hex(field(fields, "id")?).map_err(sdk_error)
}

fn contact_id(fields: &HashMap<String, String>) -> Result<ContactId, String> {
    ContactId::from_hex(field(fields, "contact_id")?).map_err(sdk_error)
}

fn lobby_id(fields: &HashMap<String, String>) -> Result<LobbyId, String> {
    LobbyId::from_hex(field(fields, "lobby_id")?).map_err(sdk_error)
}

fn sdk_error(error: impl ToString) -> String {
    error.to_string()
}

fn contact_json(contact: &hydra_app_core::HydraContact) -> String {
    format!(
        concat!(
            "{{\"id\":\"{}\",\"label\":\"{}\",\"verified\":{},",
            "\"blocked\":{},\"safety_code\":\"{}\"}}"
        ),
        contact.id().hex(),
        json_escape(contact.label()),
        contact.verified(),
        contact.blocked(),
        json_escape(&contact.safety_code())
    )
}

fn lobby_json(lobby: &hydra_app_core::HydraLobby) -> String {
    let members = lobby
        .members()
        .iter()
        .map(|member| format!("\"{}\"", member.hex()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        concat!(
            "{{\"id\":\"{}\",\"label\":\"{}\",\"max_members\":{},",
            "\"members\":[{}]}}"
        ),
        lobby.id().hex(),
        json_escape(&lobby.policy().label),
        lobby.policy().max_members,
        members
    )
}

fn received_json(message: Option<&ReceivedHydraMessage>) -> String {
    match message {
        None => "{\"complete\":false}".to_owned(),
        Some(message) => {
            let text = message.text().unwrap_or_else(|_| "<binary message>".to_owned());
            let lobby = message
                .lobby_id()
                .map(|id| format!("\"{}\"", id.hex()))
                .unwrap_or_else(|| "null".to_owned());
            format!(
                concat!(
                    "{{\"complete\":true,\"from\":\"{}\",\"message_id\":{},",
                    "\"lobby_id\":{},\"text\":\"{}\",\"attachment_count\":{}}}"
                ),
                message.from().hex(),
                message.message_id().value(),
                lobby,
                json_escape(&text),
                message.attachments().len()
            )
        }
    }
}

fn index_html(address: SocketAddr) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HYDRA Production Reference App</title>
<style>
:root {{ color-scheme: dark; font-family: system-ui, sans-serif; }}
body {{ max-width: 1100px; margin: 0 auto; padding: 2rem; background: #101318; color: #edf2f7; }}
h1, h2 {{ margin-bottom: .4rem; }}
.card {{ background: #171c24; border: 1px solid #303846; border-radius: 12px; padding: 1rem; margin: 1rem 0; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(280px,1fr)); gap: 1rem; }}
input, textarea, select, button {{ width: 100%; box-sizing: border-box; padding: .7rem; margin: .35rem 0; border-radius: 8px; border: 1px solid #465166; background: #0d1117; color: inherit; }}
button {{ cursor: pointer; background: #284b7a; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #0d1117; padding: 1rem; border-radius: 8px; min-height: 7rem; }}
code {{ color: #9bd5ff; }}
</style>
</head>
<body>
<h1>HYDRA production reference app</h1>
<p>Bound to <code>http://{address}</code>. All security-sensitive state and packet processing is owned by the public <code>hydra-msg</code> SDK.</p>
<div class="grid">
  <section class="card"><h2>Encrypted storage</h2><button data-get="/api/storage/status">Status</button><button data-get="/api/storage/debug-status">Debug status</button></section>
  <section class="card"><h2>SDK records</h2><button data-get="/api/identity/list">Identities</button><button data-get="/api/contacts/list">Contacts</button><button data-get="/api/lobbies/list">Lobbies</button></section>
</div>
<section class="card">
<h2>Public-SDK route console</h2>
<p>POST form fields as URL-encoded data. Binary SDK values use lowercase hex. Example: <code>/api/identity/generate</code> with <code>label=Primary&amp;password=secret</code>.</p>
<select id="route">
<option>/api/identity/generate</option><option>/api/identity/switch</option><option>/api/identity/unlock</option><option>/api/identity/lock</option><option>/api/identity/export</option><option>/api/identity/import</option><option>/api/identity/change-password</option><option>/api/identity/delete</option>
<option>/api/contacts/my-card</option><option>/api/contacts/preview</option><option>/api/contacts/add</option><option>/api/contacts/verify</option><option>/api/contacts/export</option><option>/api/contacts/import</option>
<option>/api/handshake/offer</option><option>/api/handshake/answer</option><option>/api/handshake/finish</option>
<option>/api/messages/send</option><option>/api/messages/receive</option>
<option>/api/lobbies/create</option><option>/api/lobbies/add-member</option><option>/api/lobbies/invite</option><option>/api/lobbies/join</option><option>/api/lobbies/send</option><option>/api/lobbies/receive</option><option>/api/lobbies/leave</option>
<option>/api/backup/export</option><option>/api/backup/verify</option><option>/api/backup/import</option><option>/api/backup/change-state-password</option>
</select>
<textarea id="fields" rows="8" placeholder="label=Primary&password=secret"></textarea>
<button id="submit">Send SDK operation</button>
</section>
<section class="card"><h2>Result</h2><pre id="result">Ready.</pre></section>
<script>
const result = document.getElementById('result');
async function show(response) {{ result.textContent = JSON.stringify(await response.json(), null, 2); }}
document.querySelectorAll('[data-get]').forEach(button => button.addEventListener('click', async () => show(await fetch(button.dataset.get, {{cache:'no-store'}}))));
document.getElementById('submit').addEventListener('click', async () => {{
  const route = document.getElementById('route').value;
  const body = document.getElementById('fields').value;
  show(await fetch(route, {{method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded','X-Hydra-Request':'1'}}, body}}));
}});
</script>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::{find_header_end, index_html, received_json};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn http_header_boundary_is_detected() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n"), Some(27));
        assert_eq!(find_header_end(b"incomplete"), None);
    }

    #[test]
    fn route_console_exposes_the_sdk_command_groups() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787);
        let html = index_html(address);
        for route in [
            "/api/identity/generate",
            "/api/contacts/my-card",
            "/api/handshake/offer",
            "/api/messages/send",
            "/api/lobbies/create",
            "/api/backup/export",
            "/api/storage/status",
        ] {
            assert!(html.contains(route), "missing route: {route}");
        }
        assert_eq!(received_json(None), "{\"complete\":false}");
    }
}
