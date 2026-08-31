#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, Default)]
pub struct FileCoverage {
    pub lines: BTreeMap<usize, u64>,
    pub branches: BTreeMap<usize, (u64, u64)>,
}

pub fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

pub fn parse(contents: &str) -> Result<HashMap<String, FileCoverage>, String> {
    let mut files = HashMap::<String, FileCoverage>::new();
    let mut current: Option<String> = None;
    for (index, raw) in contents.lines().enumerate() {
        if let Some(path) = raw.strip_prefix("SF:") {
            let path = normalize(path);
            files.entry(path.clone()).or_default();
            current = Some(path);
            continue;
        }
        let Some(path) = current.as_ref() else { continue };
        let file = files.get_mut(path).expect("LCOV source file initialized");
        if let Some(value) = raw.strip_prefix("DA:") {
            let mut fields = value.split(',');
            let line = parse_usize(fields.next(), index, "DA line")?;
            let hits = parse_u64(fields.next(), index, "DA hits")?;
            file.lines
                .entry(line)
                .and_modify(|old| *old = (*old).max(hits))
                .or_insert(hits);
        } else if let Some(value) = raw.strip_prefix("BRDA:") {
            let mut fields = value.split(',');
            let line = parse_usize(fields.next(), index, "BRDA line")?;
            let _block = fields.next();
            let _branch = fields.next();
            let taken = fields.next().ok_or_else(|| format!("LCOV:{}: malformed BRDA", index + 1))?;
            let entry = file.branches.entry(line).or_default();
            entry.0 += 1;
            if taken != "-" && taken.parse::<u64>().unwrap_or(0) > 0 {
                entry.1 += 1;
            }
        }
    }
    Ok(files)
}

fn parse_usize(value: Option<&str>, index: usize, field: &str) -> Result<usize, String> {
    value
        .ok_or_else(|| format!("LCOV:{}: missing {field}", index + 1))?
        .parse::<usize>()
        .map_err(|_| format!("LCOV:{}: invalid {field}", index + 1))
}

fn parse_u64(value: Option<&str>, index: usize, field: &str) -> Result<u64, String> {
    value
        .ok_or_else(|| format!("LCOV:{}: missing {field}", index + 1))?
        .parse::<u64>()
        .map_err(|_| format!("LCOV:{}: invalid {field}", index + 1))
}

pub fn find<'a>(files: &'a HashMap<String, FileCoverage>, wanted: &str) -> Option<&'a FileCoverage> {
    let wanted = normalize(wanted);
    files.iter().find_map(|(path, coverage)| {
        (path == &wanted || path.ends_with(&format!("/{wanted}"))).then_some(coverage)
    })
}

pub fn range_coverage(file: &FileCoverage, start: usize, end: usize) -> (u64, u64, u64, u64) {
    let mut lines_found = 0;
    let mut lines_hit = 0;
    for (_, hits) in file.lines.range(start..=end) {
        lines_found += 1;
        if *hits > 0 { lines_hit += 1; }
    }
    let mut branches_found = 0;
    let mut branches_hit = 0;
    for (_, (found, hit)) in file.branches.range(start..=end) {
        branches_found += found;
        branches_hit += hit;
    }
    (lines_found, lines_hit, branches_found, branches_hit)
}

pub fn percent(hit: u64, found: u64) -> f64 {
    if found == 0 { 100.0 } else { (hit as f64 / found as f64) * 100.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_paths_lines_and_branches() {
        let parsed = parse("SF:C:\\repo\\crates\\x.rs\nDA:10,1\nDA:11,0\nBRDA:11,0,0,0\nBRDA:11,0,1,2\n").unwrap();
        let file = find(&parsed, "crates/x.rs").unwrap();
        assert_eq!(range_coverage(file, 10, 11), (2, 1, 2, 1));
    }
}
