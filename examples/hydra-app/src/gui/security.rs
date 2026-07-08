use std::net::SocketAddr;

use getrandom::SysRng;
use rand_core::TryRng;

use super::{
    encoding::encode_hex,
    http::HttpRequest,
    server::{is_loopback_host, split_host_port},
};

pub(crate) const GUI_TOKEN_HEADER: &str = "x-hydra-gui-token";

#[derive(Clone, Debug)]
pub(crate) struct GuiSecurity {
    token: String,
    local_addr: SocketAddr,
    dangerous_allow_remote: bool,
}

impl GuiSecurity {
    pub(crate) fn new(
        local_addr: SocketAddr,
        dangerous_allow_remote: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            token: generate_session_token()?,
            local_addr,
            dangerous_allow_remote,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests(token: &str) -> Self {
        Self {
            token: token.to_owned(),
            local_addr: super::server::GUI_DEFAULT_ADDR.parse().unwrap(),
            dangerous_allow_remote: false,
        }
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn authorize(&self, request: &HttpRequest) -> Result<(), String> {
        self.validate_host(request)?;
        if request.path.starts_with("/api/") {
            self.validate_token(request)?;
        }
        if request.method == "POST" {
            self.validate_origin(request)?;
        }
        Ok(())
    }

    fn validate_host(&self, request: &HttpRequest) -> Result<(), String> {
        let host = request
            .header("host")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "missing Host header".to_owned())?;
        if host == self.local_addr.to_string() {
            return Ok(());
        }
        let (host_name, port) = split_host_port(host)?;
        if port != Some(self.local_addr.port()) {
            return Err("GUI Host header does not match listener port".to_owned());
        }
        if self.dangerous_allow_remote || is_loopback_host(host_name) {
            Ok(())
        } else {
            Err("GUI Host header is not loopback".to_owned())
        }
    }

    fn validate_origin(&self, request: &HttpRequest) -> Result<(), String> {
        let Some(origin_or_referer) = request
            .header("origin")
            .or_else(|| request.header("referer"))
        else {
            return Ok(());
        };
        let host = origin_or_referer
            .strip_prefix("http://")
            .or_else(|| origin_or_referer.strip_prefix("https://"))
            .ok_or_else(|| "GUI request has unsupported Origin scheme".to_owned())?;
        let host = host.split('/').next().unwrap_or(host);
        let (host_name, port) = split_host_port(host)?;
        if port != Some(self.local_addr.port()) {
            return Err("GUI Origin/Referer port mismatch".to_owned());
        }
        if self.dangerous_allow_remote || is_loopback_host(host_name) {
            Ok(())
        } else {
            Err("GUI Origin/Referer is not loopback".to_owned())
        }
    }

    fn validate_token(&self, request: &HttpRequest) -> Result<(), String> {
        let token = request
            .header(GUI_TOKEN_HEADER)
            .ok_or_else(|| "missing GUI session token".to_owned())?;
        if constant_time_eq(token.as_bytes(), self.token.as_bytes()) {
            Ok(())
        } else {
            Err("invalid GUI session token".to_owned())
        }
    }
}

pub(crate) fn generate_session_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| format!("cannot generate GUI session token: {error}"))?;
    Ok(encode_hex(&bytes))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&a, &b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
