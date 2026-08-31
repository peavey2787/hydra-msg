use std::{
    io::{Read, Write},
    net::TcpStream,
};

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 12 * 1024 * 1024;

pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) body: Vec<u8>,
}

pub(crate) struct Response {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

pub(crate) fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
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
        return Err("request body exceeds 12 MiB".to_owned());
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

pub(crate) fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)
}

pub(crate) fn service_response(result: Result<impl Into<Vec<u8>>, String>, json: bool) -> Response {
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

pub(crate) fn bad_request(message: &str) -> Response {
    response(
        "400 Bad Request",
        "text/plain; charset=utf-8",
        message.as_bytes().to_vec(),
    )
}

pub(crate) fn not_found() -> Response {
    response(
        "404 Not Found",
        "text/plain; charset=utf-8",
        b"not found".to_vec(),
    )
}

pub(crate) fn response(
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response {
    Response {
        status,
        content_type,
        body,
    }
}

pub(crate) fn content_type(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".webmanifest") {
        "application/manifest+json"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else {
        "application/octet-stream"
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
