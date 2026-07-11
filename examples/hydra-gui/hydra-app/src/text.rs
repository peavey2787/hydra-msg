use std::{collections::HashMap, fmt::Write as _};

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.len() & 1 != 0 {
        return Err("hex input must contain an even number of characters".to_owned());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|_| "hex input is not utf-8")?;
        out.push(u8::from_str_radix(text, 16).map_err(|_| "hex input is invalid")?);
    }
    Ok(out)
}

pub fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out
}

pub fn parse_form(body: &str) -> Result<HashMap<String, String>, String> {
    let mut fields = HashMap::new();
    if body.is_empty() {
        return Ok(fields);
    }
    for pair in body.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key)?;
        let value = percent_decode(value)?;
        if fields.insert(key, value).is_some() {
            return Err("duplicate form field".to_owned());
        }
    }
    Ok(fields)
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err("invalid percent encoding".to_owned());
                }
                let pair = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .map_err(|_| "invalid percent encoding")?;
                out.push(u8::from_str_radix(pair, 16).map_err(|_| "invalid percent encoding")?);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "form value is not utf-8".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{hex_decode, hex_encode, json_escape, parse_form};

    #[test]
    fn binary_and_form_encodings_roundtrip() {
        let bytes = [0_u8, 1, 127, 255];
        assert_eq!(
            hex_decode(&hex_encode(&bytes)).expect("decode hex"),
            bytes.to_vec()
        );
        let fields = parse_form("label=Primary+ID&password=a%2Bb").expect("parse form");
        assert_eq!(fields.get("label").map(String::as_str), Some("Primary ID"));
        assert_eq!(fields.get("password").map(String::as_str), Some("a+b"));
        assert_eq!(
            parse_form("password=first&password=second"),
            Err("duplicate form field".to_owned())
        );
    }

    #[test]
    fn json_text_is_escaped_without_loss() {
        assert_eq!(json_escape("a\n\"b\\c"), "a\\n\\\"b\\\\c");
    }
}
