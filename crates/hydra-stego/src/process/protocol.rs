use crate::{
    generative::{TokenCandidate, TokenId},
    StegoError,
};

pub(super) enum Response {
    Progress(u8, String),
    Ok(String),
    Error(String),
}

pub(super) fn parse_response(bytes: &[u8]) -> Result<Response, StegoError> {
    let mut bytes = bytes;
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    let response = std::str::from_utf8(bytes)
        .map_err(|_| StegoError::Model("model response is not UTF-8".to_owned()))?;
    if let Some(progress) = response.strip_prefix("progress\t") {
        let (percent, message) = progress
            .split_once('\t')
            .ok_or_else(|| StegoError::Model("model returned invalid progress".to_owned()))?;
        let percent = percent
            .parse::<u8>()
            .map_err(|_| StegoError::Model("model returned invalid progress percent".to_owned()))?;
        if percent > 100 {
            return Err(StegoError::Model(
                "model returned progress above 100 percent".to_owned(),
            ));
        }
        let message = String::from_utf8(hex_decode(message)?)
            .map_err(|_| StegoError::Model("model progress is not UTF-8".to_owned()))?;
        return Ok(Response::Progress(percent, message));
    }
    if response == "ok" {
        return Ok(Response::Ok(String::new()));
    }
    if let Some(value) = response.strip_prefix("ok\t") {
        return Ok(Response::Ok(value.to_owned()));
    }
    if let Some(error) = response.strip_prefix("err\t") {
        let decoded = hex_decode(error)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_else(|| error.to_owned());
        return Ok(Response::Error(decoded));
    }
    Err(StegoError::Model(
        "model returned an invalid protocol response".to_owned(),
    ))
}

pub(super) fn join_tokens(tokens: &[TokenId]) -> String {
    use std::fmt::Write as _;

    let mut joined = String::with_capacity(tokens.len().saturating_mul(3));
    for (index, token) in tokens.iter().enumerate() {
        if index != 0 {
            joined.push(',');
        }
        write!(&mut joined, "{token}").expect("writing to String cannot fail");
    }
    joined
}

pub(super) fn parse_tokens(value: &str, maximum_tokens: usize) -> Result<Vec<TokenId>, StegoError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let tokens = value
        .split(',')
        .take(maximum_tokens.saturating_add(1))
        .map(|token| {
            token
                .parse()
                .map_err(|_| StegoError::Model("invalid token id from model".to_owned()))
        })
        .collect::<Result<Vec<_>, StegoError>>()?;
    if tokens.len() > maximum_tokens {
        return Err(StegoError::Model(
            "model returned too many token ids".to_owned(),
        ));
    }
    Ok(tokens)
}

pub(super) fn parse_candidates(
    value: &str,
    maximum_candidates: usize,
) -> Result<Vec<TokenCandidate>, StegoError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let entries = value.split(',').take(maximum_candidates.saturating_add(1));
    let candidates = entries
        .map(|entry| {
            let (id, score) = entry.split_once(':').ok_or_else(|| {
                StegoError::Model("invalid candidate response from model".to_owned())
            })?;
            Ok(TokenCandidate::new(
                id.parse()
                    .map_err(|_| StegoError::Model("invalid candidate token id".to_owned()))?,
                score
                    .parse()
                    .map_err(|_| StegoError::Model("invalid candidate score".to_owned()))?,
            ))
        })
        .collect::<Result<Vec<_>, StegoError>>()?;
    if candidates.len() > maximum_candidates {
        return Err(StegoError::Model(
            "model returned more candidates than requested".to_owned(),
        ));
    }
    Ok(candidates)
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(TABLE[(byte >> 4) as usize] as char);
        encoded.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) fn hex_decode(value: &str) -> Result<Vec<u8>, StegoError> {
    if !value.len().is_multiple_of(2) {
        return Err(StegoError::Model("invalid hex from model".to_owned()));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(hex_nibble(pair[0])? << 4 | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, StegoError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(StegoError::Model("invalid hex from model".to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_helpers_round_trip_and_reject_malformed_responses() {
        let text = "hello, café";
        assert_eq!(
            hex_decode(&hex_encode(text.as_bytes())).unwrap(),
            text.as_bytes()
        );
        assert_eq!(
            parse_tokens(&join_tokens(&[1, 7, u32::MAX]), 3).unwrap(),
            [1, 7, u32::MAX]
        );
        assert!(parse_tokens("1,2", 1).is_err());
        assert!(parse_candidates("1:0,2:0", 1).is_err());
        assert!(parse_response(b"progress\t101\t00\n").is_err());
        assert!(parse_response(b"wat\n").is_err());
    }
}
