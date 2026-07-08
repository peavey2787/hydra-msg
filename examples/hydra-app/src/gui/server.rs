use std::{
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

use super::{
    http::{write_response, HttpRequest},
    router::route_request,
    security::GuiSecurity,
    state::GuiAppState,
};

pub(crate) const GUI_DEFAULT_ADDR: &str = "127.0.0.1:8787";
pub(crate) const GUI_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run(args: &[String]) -> Result<(), String> {
    let bind = resolve_bind_config(args)?;
    if !bind.dangerous_allow_remote && !is_loopback_bind_addr(&bind.addr)? {
        return Err("refusing non-loopback GUI bind without --dangerous-allow-remote".to_owned());
    }

    let listener = TcpListener::bind(&bind.addr)
        .map_err(|error| format!("cannot bind GUI server at {}: {error}", bind.addr))?;
    let local_addr = listener
        .local_addr()
        .map_err(|error| format!("cannot read GUI server address: {error}"))?;
    let security = GuiSecurity::new(local_addr, bind.dangerous_allow_remote)?;
    let app_state = GuiAppState::new();
    println!("HYDRA-MSG GUI listening at http://{local_addr}");
    println!("GUI session token generated for this process and required for every API request.");
    if bind.dangerous_allow_remote {
        eprintln!(
            "WARNING: remote GUI binding was explicitly enabled. Use only behind a trusted firewall."
        );
    }
    println!("Press Ctrl+C to stop.");
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_connection(&mut stream, &security, &app_state) {
                    let _ = write_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        "text/plain; charset=utf-8",
                        error.as_bytes(),
                    );
                }
            }
            Err(error) => eprintln!("GUI connection failed: {error}"),
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuiBindConfig {
    pub(crate) addr: String,
    pub(crate) dangerous_allow_remote: bool,
}

#[cfg(test)]
pub(crate) fn resolve_bind_addr(args: &[String]) -> Result<String, String> {
    resolve_bind_config(args).map(|config| config.addr)
}

pub(crate) fn resolve_bind_config(args: &[String]) -> Result<GuiBindConfig, String> {
    let mut addr = GUI_DEFAULT_ADDR.to_owned();
    let mut dangerous_allow_remote = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--addr" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(gui_usage());
                };
                addr = value.clone();
                index += 2;
            }
            "--dangerous-allow-remote" => {
                dangerous_allow_remote = true;
                index += 1;
            }
            value if index == 0 && !value.starts_with('-') => {
                addr = value.to_owned();
                index += 1;
            }
            _ => return Err(gui_usage()),
        }
    }
    Ok(GuiBindConfig {
        addr,
        dangerous_allow_remote,
    })
}

fn gui_usage() -> String {
    "usage: hydra-app gui [--addr <loopback-ip:port>] [--dangerous-allow-remote]".to_owned()
}

pub(crate) fn is_loopback_bind_addr(addr: &str) -> Result<bool, String> {
    let socket = addr
        .parse::<SocketAddr>()
        .map_err(|error| format!("GUI bind address must be an ip:port socket address: {error}"))?;
    Ok(socket.ip().is_loopback())
}

fn handle_connection(
    stream: &mut TcpStream,
    security: &GuiSecurity,
    app_state: &GuiAppState,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(GUI_REQUEST_TIMEOUT))
        .map_err(|error| format!("cannot set GUI read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(GUI_REQUEST_TIMEOUT))
        .map_err(|error| format!("cannot set GUI write timeout: {error}"))?;
    let request = HttpRequest::read(stream)?;
    let response = route_request(&request, security, app_state);
    write_response(
        stream,
        response.status_code,
        response.status_text,
        response.content_type,
        response.body.as_bytes(),
    )
}

pub(crate) fn split_host_port(host: &str) -> Result<(&str, Option<u16>), String> {
    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return Err("malformed bracketed IPv6 Host header".to_owned());
        };
        let port = if let Some(port_text) = suffix.strip_prefix(':') {
            Some(parse_port(port_text)?)
        } else if suffix.is_empty() {
            None
        } else {
            return Err("malformed bracketed IPv6 Host header".to_owned());
        };
        return Ok((inner, port));
    }
    match host.rsplit_once(':') {
        Some((name, port_text)) if !name.contains(':') => Ok((name, Some(parse_port(port_text)?))),
        Some(_) => Ok((host, None)),
        None => Ok((host, None)),
    }
}

fn parse_port(port_text: &str) -> Result<u16, String> {
    port_text
        .parse::<u16>()
        .map_err(|error| format!("invalid Host port: {error}"))
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}
