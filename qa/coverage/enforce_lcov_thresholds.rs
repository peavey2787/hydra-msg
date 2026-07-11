#![forbid(unsafe_code)]
#![deny(warnings)]

use std::collections::HashMap;

#[cfg(not(test))]
use std::{env, fs, path::Path, process::ExitCode};

#[derive(Debug, Clone, PartialEq)]
struct ManifestRow {
    id: String,
    min_line: f64,
    min_branch: f64,
    source: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CoverageRecord {
    lines_found: u64,
    lines_hit: u64,
    branches_found: u64,
    branches_hit: u64,
}

fn parse_manifest(contents: &str, label: &str) -> Result<Vec<ManifestRow>, String> {
    let mut rows = Vec::new();
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts = line.split('|').collect::<Vec<_>>();
        if parts.len() != 7 {
            return Err(format!(
                "{label}:{}: expected 7 pipe-separated fields",
                index + 1
            ));
        }
        if parts.iter().any(|part| part.trim().is_empty()) {
            return Err(format!("{label}:{}: empty manifest field", index + 1));
        }
        rows.push(ManifestRow {
            id: parts[0].to_owned(),
            min_line: parse_percent(parts[2], label, index + 1, "line")?,
            min_branch: parse_percent(parts[3], label, index + 1, "branch")?,
            source: normalize(parts[4]),
        });
    }
    if rows.is_empty() {
        return Err(format!("{label}: no coverage rows found"));
    }
    Ok(rows)
}

fn parse_percent(value: &str, label: &str, line: usize, kind: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| format!("{label}:{line}: invalid {kind} percentage: {value}"))?;
    if !(0.0..=100.0).contains(&parsed) {
        return Err(format!(
            "{label}:{line}: {kind} percentage must be between 0 and 100: {value}"
        ));
    }
    Ok(parsed)
}

fn parse_lcov(contents: &str, label: &str) -> Result<HashMap<String, CoverageRecord>, String> {
    let mut records = HashMap::<String, CoverageRecord>::new();
    let mut current_file: Option<String> = None;

    for (index, raw) in contents.lines().enumerate() {
        if let Some(path) = raw.strip_prefix("SF:") {
            let normalized = normalize(path);
            records.entry(normalized.clone()).or_default();
            current_file = Some(normalized);
            continue;
        }

        let Some(file_name) = current_file.as_ref() else {
            continue;
        };
        let record = records
            .get_mut(file_name)
            .expect("current LCOV file must have an initialized record");
        if let Some(value) = raw.strip_prefix("LF:") {
            record.lines_found += parse_count(value, label, index + 1, "LF")?;
        } else if let Some(value) = raw.strip_prefix("LH:") {
            record.lines_hit += parse_count(value, label, index + 1, "LH")?;
        } else if let Some(value) = raw.strip_prefix("BRF:") {
            record.branches_found += parse_count(value, label, index + 1, "BRF")?;
        } else if let Some(value) = raw.strip_prefix("BRH:") {
            record.branches_hit += parse_count(value, label, index + 1, "BRH")?;
        }
    }

    Ok(records)
}

fn parse_count(value: &str, label: &str, line: usize, field: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{label}:{line}: invalid {field} count: {value}"))
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

fn find_record<'a>(
    records: &'a HashMap<String, CoverageRecord>,
    source: &str,
) -> Option<&'a CoverageRecord> {
    let wanted = normalize(source);
    records.iter().find_map(|(file_name, record)| {
        (file_name == &wanted || file_name.ends_with(&format!("/{wanted}"))).then_some(record)
    })
}

fn percentage(hit: u64, found: u64) -> f64 {
    if found == 0 {
        100.0
    } else {
        (hit as f64 / found as f64) * 100.0
    }
}

fn enforce(
    rows: &[ManifestRow],
    records: &HashMap<String, CoverageRecord>,
) -> Result<(), Vec<String>> {
    let mut failures = Vec::new();
    for row in rows {
        let Some(record) = find_record(records, &row.source) else {
            failures.push(format!(
                "{}: no LCOV record for {}",
                row.id, row.source
            ));
            continue;
        };
        let line_pct = percentage(record.lines_hit, record.lines_found);
        let branch_pct = percentage(record.branches_hit, record.branches_found);
        if line_pct + 1e-9 < row.min_line {
            failures.push(format!(
                "{}: line coverage {line_pct:.2}% < {:.2}% for {}",
                row.id, row.min_line, row.source
            ));
        }
        if record.branches_found == 0 && row.min_branch > 0.0 {
            failures.push(format!("{}: no branch data for {}", row.id, row.source));
        } else if branch_pct + 1e-9 < row.min_branch {
            failures.push(format!(
                "{}: branch coverage {branch_pct:.2}% < {:.2}% for {}",
                row.id, row.min_branch, row.source
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

#[cfg(not(test))]
fn run(manifest_path: &Path, report_path: &Path) -> Result<(), String> {
    let manifest_contents = fs::read_to_string(manifest_path)
        .map_err(|error| format!("failed to read {}: {error}", manifest_path.display()))?;
    let report_contents = fs::read_to_string(report_path)
        .map_err(|error| format!("failed to read {}: {error}", report_path.display()))?;
    let rows = parse_manifest(&manifest_contents, &manifest_path.display().to_string())?;
    let records = parse_lcov(&report_contents, &report_path.display().to_string())?;
    enforce(&rows, &records).map_err(|failures| failures.join("\n"))?;
    println!("critical-path LCOV thresholds passed");
    Ok(())
}

#[cfg(not(test))]
fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!(
            "usage: {} <manifest.tsv> <report.lcov>",
            args.first()
                .map(String::as_str)
                .unwrap_or("enforce-lcov-thresholds")
        );
        return ExitCode::from(2);
    }
    match run(Path::new(&args[1]), Path::new(&args[2])) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str =
        "critical|negative path|90|75|crates/example.rs|tests/example.rs|rejects_bad_input\n";

    #[test]
    fn manifest_requires_seven_nonempty_fields_and_valid_percentages() {
        assert!(parse_manifest(MANIFEST, "manifest").is_ok());
        assert!(parse_manifest("bad|row\n", "manifest").is_err());
        assert!(parse_manifest("id|class|101|0|a|b|c\n", "manifest").is_err());
        assert!(parse_manifest("# comments only\n", "manifest").is_err());
    }

    #[test]
    fn lcov_records_accumulate_and_windows_paths_are_normalized() {
        let records = parse_lcov(
            "SF:C:\\repo\\crates\\example.rs\nLF:5\nLH:4\nBRF:2\nBRH:1\nSF:C:\\repo\\crates\\example.rs\nLF:5\nLH:5\nBRF:2\nBRH:2\n",
            "report",
        )
        .expect("valid LCOV");
        assert_eq!(
            find_record(&records, "crates/example.rs"),
            Some(&CoverageRecord {
                lines_found: 10,
                lines_hit: 9,
                branches_found: 4,
                branches_hit: 3,
            })
        );
    }

    #[test]
    fn thresholds_pass_at_exact_boundaries() {
        let rows = parse_manifest(MANIFEST, "manifest").expect("valid manifest");
        let records = parse_lcov(
            "SF:/repo/crates/example.rs\nLF:10\nLH:9\nBRF:4\nBRH:3\n",
            "report",
        )
        .expect("valid LCOV");
        assert_eq!(enforce(&rows, &records), Ok(()));
    }

    #[test]
    fn thresholds_report_missing_records_lines_and_branches() {
        let rows = parse_manifest(MANIFEST, "manifest").expect("valid manifest");
        assert!(matches!(enforce(&rows, &HashMap::new()), Err(failures) if failures.len() == 1));

        let records = parse_lcov(
            "SF:/repo/crates/example.rs\nLF:10\nLH:8\nBRF:4\nBRH:2\n",
            "report",
        )
        .expect("valid LCOV");
        assert!(matches!(enforce(&rows, &records), Err(failures) if failures.len() == 2));

        let records = parse_lcov(
            "SF:/repo/crates/example.rs\nLF:10\nLH:10\nBRF:0\nBRH:0\n",
            "report",
        )
        .expect("valid LCOV");
        let failures = enforce(&rows, &records).expect_err("branch data is required");
        assert_eq!(
            failures,
            vec!["critical: no branch data for crates/example.rs".to_owned()]
        );
    }
}
