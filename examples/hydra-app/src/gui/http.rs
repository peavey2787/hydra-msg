use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
};

use super::encoding::json_escape;

pub(crate) const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
pub(crate) const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;

pub(crate) const GUI_SECURITY_HEADERS: &str = concat!(
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n",
);

pub(crate) struct HttpRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Vec<u8>,
}

impl HttpRequest {
    pub(crate) fn read(stream: &mut TcpStream) -> Result<Self, String> {
        let mut buffer = Vec::new();
        let mut temp = [0_u8; 4096];
        loop {
            let read = stream
                .read(&mut temp)
                .map_err(|error| format!("cannot read HTTP request: {error}"))?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&temp[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if buffer.len() > MAX_HTTP_HEADER_BYTES {
                return Err("HTTP request header too large".to_owned());
            }
        }
        let header_end = buffer
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .ok_or_else(|| "malformed HTTP request".to_owned())?;
        let header_text = String::from_utf8_lossy(&buffer[..header_end]);
        let mut lines = header_text.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| "missing HTTP request line".to_owned())?;
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .ok_or_else(|| "missing HTTP method".to_owned())?
            .to_owned();
        let raw_path = request_parts
            .next()
            .ok_or_else(|| "missing HTTP path".to_owned())?;
        let path = raw_path.split('?').next().unwrap_or(raw_path).to_owned();
        let mut headers = HashMap::new();
        let mut content_length = 0_usize;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let normalized = name.trim().to_ascii_lowercase();
            let value = value.trim().to_owned();
            if normalized == "content-length" {
                content_length = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid Content-Length: {error}"))?;
                if content_length > MAX_HTTP_BODY_BYTES {
                    return Err("HTTP request body too large".to_owned());
                }
            }
            headers.insert(normalized, value);
        }
        let mut body = buffer[header_end..].to_vec();
        while body.len() < content_length {
            let read = stream
                .read(&mut temp)
                .map_err(|error| format!("cannot read HTTP request body: {error}"))?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&temp[..read]);
            if body.len() > MAX_HTTP_BODY_BYTES {
                return Err("HTTP request body too large".to_owned());
            }
        }
        body.truncate(content_length);
        Ok(Self {
            method,
            path,
            headers,
            body,
        })
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

pub(crate) struct HttpResponse {
    pub(crate) status_code: u16,
    pub(crate) status_text: &'static str,
    pub(crate) content_type: &'static str,
    pub(crate) body: String,
}

impl HttpResponse {
    pub(crate) fn new(
        status_code: u16,
        status_text: &'static str,
        content_type: &'static str,
        body: String,
    ) -> Self {
        Self {
            status_code,
            status_text,
            content_type,
            body,
        }
    }
}

pub(crate) fn write_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let headers = format!(
        concat!(
            "HTTP/1.1 {} {}\r\n",
            "Content-Type: {}\r\n",
            "Content-Length: {}\r\n",
            "{}",
            "Connection: close\r\n",
            "\r\n"
        ),
        status_code,
        status_text,
        content_type,
        body.len(),
        GUI_SECURITY_HEADERS,
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|error| format!("cannot write HTTP response: {error}"))
}

pub(crate) fn html_response(body: String) -> HttpResponse {
    HttpResponse::new(200, "OK", "text/html; charset=utf-8", body)
}

pub(crate) fn asset_response(content_type: &'static str, body: &str) -> HttpResponse {
    HttpResponse::new(200, "OK", content_type, body.to_owned())
}

pub(crate) fn json_response(body: String) -> HttpResponse {
    HttpResponse::new(200, "OK", "application/json; charset=utf-8", body)
}

pub(crate) fn json_error(error: &str) -> String {
    format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(error))
}
