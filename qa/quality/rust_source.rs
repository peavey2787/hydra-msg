use std::{fs, path::{Path, PathBuf}};

#[derive(Clone, Debug)]
pub struct Function {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub cc: u32,
}

pub fn rust_sources(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    visit(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn visit(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        if p.is_dir() {
            if p.file_name().and_then(|s| s.to_str()) != Some("target") { visit(&p, out)?; }
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
    Ok(())
}

pub fn is_test_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.contains("/tests/") || p.ends_with("/tests.rs") || p.ends_with("/test_support.rs") || p.ends_with("_tests.rs")
}

pub fn functions(source: &str) -> Vec<Function> {
    let masked = mask(source);
    let test_ranges = cfg_test_ranges(&masked);
    let starts = line_starts(&masked);
    let bytes = masked.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        if is_word_at(bytes, i, b"fn") {
            let mut at = skip_ws(bytes, i + 2);
            let Some((name, after_name)) = identifier(bytes, at) else { i += 2; continue };
            at = after_name;
            let Some(open) = signature_open_brace(bytes, at) else { i += 2; continue };
            let Some(close) = matching_brace(bytes, open) else { i += 2; continue };
            if test_ranges.iter().any(|(a, b)| i >= *a && i <= *b) { i = close + 1; continue; }
            let start_line = line_of(&starts, i);
            let end_line = line_of(&starts, close);
            let cc = complexity(&masked[open + 1..close]);
            out.push(Function { name, start_line, end_line, cc });
            i = close + 1;
        } else {
            i += 1;
        }
    }
    out
}

fn signature_open_brace(bytes: &[u8], mut i: usize) -> Option<usize> {
    let mut paren = 0_i32;
    let mut bracket = 0_i32;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b';' if paren == 0 && bracket == 0 => return None,
            b'{' if paren == 0 && bracket == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn complexity(body: &str) -> u32 {
    let bytes = body.as_bytes();
    let mut words = Vec::new();
    let mut arrows = 0_u32;
    let mut bool_ops = 0_u32;
    let mut i = 0;
    while i < bytes.len() {
        if let Some((word, end)) = identifier(bytes, i) {
            words.push(word);
            i = end;
            continue;
        }
        if i + 1 < bytes.len() {
            if &bytes[i..i + 2] == b"=>" { arrows += 1; i += 2; continue; }
            if &bytes[i..i + 2] == b"&&" || &bytes[i..i + 2] == b"||" { bool_ops += 1; i += 2; continue; }
        }
        i += 1;
    }
    let decisions = words.iter().filter(|w| matches!(w.as_str(), "if" | "for" | "while" | "loop")).count() as u32;
    let matches = words.iter().filter(|w| w.as_str() == "match").count() as u32;
    1 + decisions + bool_ops + arrows.saturating_sub(matches)
}

fn cfg_test_ranges(masked: &str) -> Vec<(usize, usize)> {
    let bytes = masked.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = masked[from..].find("#[cfg(test)]") {
        let start = from + rel;
        let mut i = start + "#[cfg(test)]".len();
        while i < bytes.len() && bytes[i] != b'{' && bytes[i] != b';' { i += 1; }
        if i < bytes.len() && bytes[i] == b'{' {
            if let Some(close) = matching_brace(bytes, i) { out.push((start, close)); from = close + 1; continue; }
        }
        from = i.saturating_add(1);
    }
    out
}

fn matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0_i32;
    for (off, byte) in bytes[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => { depth -= 1; if depth == 0 { return Some(open + off); } }
            _ => {}
        }
    }
    None
}

fn line_starts(s: &str) -> Vec<usize> {
    let mut v = vec![0];
    for (i, b) in s.bytes().enumerate() { if b == b'\n' { v.push(i + 1); } }
    v
}

fn line_of(starts: &[usize], pos: usize) -> usize {
    starts.partition_point(|start| *start <= pos)
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
    i
}

fn identifier(bytes: &[u8], i: usize) -> Option<(String, usize)> {
    if i >= bytes.len() || !(bytes[i] == b'_' || bytes[i].is_ascii_alphabetic()) { return None; }
    let mut end = i + 1;
    while end < bytes.len() && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric()) { end += 1; }
    Some((String::from_utf8_lossy(&bytes[i..end]).into_owned(), end))
}

fn is_word_at(bytes: &[u8], i: usize, word: &[u8]) -> bool {
    if i + word.len() > bytes.len() || &bytes[i..i + word.len()] != word { return false; }
    let before = i.checked_sub(1).and_then(|j| bytes.get(j)).copied();
    let after = bytes.get(i + word.len()).copied();
    !before.is_some_and(is_ident_byte) && !after.is_some_and(is_ident_byte)
}

fn is_ident_byte(b: u8) -> bool { b == b'_' || b.is_ascii_alphanumeric() }

fn mask(source: &str) -> String {
    let b = source.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && &b[i..i + 2] == b"//" {
            let mut j = i; while j < b.len() && b[j] != b'\n' { out[j] = b' '; j += 1; } i = j; continue;
        }
        if i + 1 < b.len() && &b[i..i + 2] == b"/*" {
            let mut j = i + 2; let mut depth = 1;
            out[i] = b' '; out[i + 1] = b' ';
            while j < b.len() && depth > 0 {
                if j + 1 < b.len() && &b[j..j + 2] == b"/*" { depth += 1; out[j]=b' '; out[j+1]=b' '; j+=2; continue; }
                if j + 1 < b.len() && &b[j..j + 2] == b"*/" { depth -= 1; out[j]=b' '; out[j+1]=b' '; j+=2; continue; }
                if b[j] != b'\n' { out[j] = b' '; } j += 1;
            }
            i = j; continue;
        }
        if b[i] == b'r' {
            let mut h = i + 1; while h < b.len() && b[h] == b'#' { h += 1; }
            if h < b.len() && b[h] == b'"' {
                let hashes = h - (i + 1); let mut j = h + 1;
                while j < b.len() {
                    if b[j] == b'"' && j + 1 + hashes <= b.len() && b[j + 1..j + 1 + hashes].iter().all(|x| *x == b'#') { j += 1 + hashes; break; }
                    j += 1;
                }
                for k in i..j { if out[k] != b'\n' { out[k] = b' '; } } i = j; continue;
            }
        }
        if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() {
                if b[j] == b'\\' { j += 2; continue; }
                if b[j] == b'"' { j += 1; break; }
                j += 1;
            }
            for k in i..j.min(b.len()) { if out[k] != b'\n' { out[k] = b' '; } }
            i = j;
            continue;
        }
        if b[i] == b'\'' {
            // Mask character literals but do not treat Rust lifetimes (for example
            // `'a` or `'static`) as quoted strings. A char literal must have a
            // closing apostrophe within the small lexical forms Rust permits.
            let mut j = i + 1;
            if j < b.len() {
                // UTF-8 scalar chars need only a few bytes; escaped chars such as
                // `\u{1F600}` need a slightly wider bound. Lifetimes have no
                // nearby closing apostrophe and therefore remain unmasked.
                let cap = (i + if b[j] == b'\\' { 20 } else { 8 }).min(b.len());
                while j < cap && b[j] != b'\'' && b[j] != b'\n' { j += 1; }
            }
            if j < b.len() && b[j] == b'\'' {
                j += 1;
                for k in i..j { if out[k] != b'\n' { out[k] = b' '; } }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    String::from_utf8(out).expect("Rust source is UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_functions_ignores_test_module_and_counts_decisions() {
        let source = r#"fn plain(x: bool) { if x && true { loop { break; } } }
#[cfg(test)] mod tests { fn hidden() { if true {} } }
fn choice(x: u8) { match x { 0 => {}, 1 => {}, _ => {} } }"#;
        let f = functions(source);
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].name.as_str(), f[0].cc), ("plain", 4));
        assert_eq!((f[1].name.as_str(), f[1].cc), ("choice", 3));
    }

    #[test]
    fn lifetimes_are_not_masked_as_character_literals() {
        let source = "fn borrowed<'a>(value: &'a str) -> &'a str { if value.is_empty() { value } else { value } }";
        let f = functions(source);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "borrowed");
        assert_eq!(f[0].cc, 2);
    }

    #[test]
    fn character_literals_do_not_change_brace_or_decision_scanning() {
        let source = r#"fn chars<'a>(value: &'a str) { let close = '}'; let escaped = '\u{1F600}'; if !value.is_empty() { let _ = (close, escaped); } }"#;
        let f = functions(source);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "chars");
        assert_eq!(f[0].cc, 2);
    }
}
