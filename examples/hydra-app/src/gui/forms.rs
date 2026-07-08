use std::collections::HashMap;

pub(crate) fn required_form_value<'a>(
    form: &'a HashMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    form.get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing form field '{key}'"))
}

pub(crate) fn parse_form(body: &[u8]) -> Result<HashMap<String, String>, String> {
    let text =
        std::str::from_utf8(body).map_err(|error| format!("form body must be utf-8: {error}"))?;
    let mut form = HashMap::new();
    for field in text.split('&').filter(|field| !field.is_empty()) {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        form.insert(percent_decode(key)?, percent_decode(value)?);
    }
    Ok(form)
}

fn percent_decode(input: &str) -> Result<String, String> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                out.push((high << 4) | low);
                index += 3;
            }
            b'%' => return Err("truncated percent escape".to_owned()),
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|error| format!("decoded form value is not utf-8: {error}"))
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid percent escape".to_owned()),
    }
}
