#![forbid(unsafe_code)]
#![deny(warnings)]

mod lcov;
mod rust_source;

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use lcov::{find, percent, range_coverage};

const NATIVE_LINE_MIN: f64 = 85.0;
const NATIVE_BRANCH_MIN: f64 = 65.0;
const ZERO_HIT_COMPLEX_CC: u32 = 8;
const MAX_CC: u32 = 12;
const MAX_CRAP: f64 = 25.0;

#[derive(Clone, Debug)]
struct Critical {
    id: String,
    source: String,
    function: String,
    reason: String,
}

#[derive(Default)]
struct CoverageTotals {
    lines_found: u64,
    lines_hit: u64,
    branches_found: u64,
    branches_hit: u64,
}

impl CoverageTotals {
    fn add(&mut self, lines_found: u64, lines_hit: u64, branches_found: u64, branches_hit: u64) {
        self.lines_found += lines_found;
        self.lines_hit += lines_hit;
        self.branches_found += branches_found;
        self.branches_hit += branches_hit;
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err(format!(
            "usage: {} <report.lcov> <critical-functions.tsv> <output.tsv>",
            args.first()
                .map(String::as_str)
                .unwrap_or("enforce-quality")
        ));
    }
    let coverage = lcov::parse(
        &fs::read_to_string(&args[1]).map_err(|error| format!("{}: {error}", args[1]))?,
    )?;
    let critical = parse_critical(
        &fs::read_to_string(&args[2]).map_err(|error| format!("{}: {error}", args[2]))?,
        &args[2],
    )?;
    let critical_map = critical
        .iter()
        .map(|entry| ((entry.source.clone(), entry.function.clone()), entry))
        .collect::<HashMap<_, _>>();
    let mut seen_critical = HashSet::new();
    let mut failures = Vec::new();
    let mut report = String::from(
        "source\tfunction\tstart\tend\tcc\tline_coverage\tbranch_coverage\tcrap\tcritical\n",
    );
    let mut measured = 0_u64;
    let mut native_measured = 0_u64;
    let mut adapter_measured = 0_u64;
    let mut native = CoverageTotals::default();

    for path in production_sources()? {
        let relative = normalize_repo_path(&path)?;
        if rust_source::is_test_path(&relative) {
            continue;
        }
        let source =
            fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let funcs = rust_source::functions(&source);
        let file_cov = find(&coverage, &relative);
        for function in funcs {
            if function.cc > MAX_CC {
                failures.push(format!(
                    "CC {} > {MAX_CC}: {}::{} (lines {}-{})",
                    function.cc,
                    relative,
                    function.name,
                    function.start_line,
                    function.end_line
                ));
            }
            let key = (relative.clone(), function.name.clone());
            let critical_entry = critical_map.get(&key).copied();
            if critical_entry.is_some() {
                seen_critical.insert(key.clone());
            }
            let Some(file_cov) = file_cov else {
                if let Some(entry) = critical_entry {
                    failures.push(format!(
                        "critical function has no LCOV file record: {} ({}::{})",
                        entry.id, relative, function.name
                    ));
                }
                continue;
            };
            let (lf, lh, bf, bh) =
                range_coverage(file_cov, function.start_line, function.end_line);
            if lf == 0 {
                if let Some(entry) = critical_entry {
                    failures.push(format!(
                        "critical function has no executable LCOV lines: {} ({}::{})",
                        entry.id, relative, function.name
                    ));
                }
                continue;
            }

            measured += 1;
            let line_pct = percent(lh, lf);
            let branch_pct = percent(bh, bf);
            let critical_flag = critical_entry.is_some();
            let function_crap = crap(function.cc, line_pct / 100.0);
            report.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{:.2}\t{:.2}\t{:.2}\t{}\n",
                relative,
                function.name,
                function.start_line,
                function.end_line,
                function.cc,
                line_pct,
                branch_pct,
                function_crap,
                critical_flag
            ));

            if critical_flag {
                if line_pct + 1e-9 < 100.0 {
                    failures.push(format!(
                        "line coverage {line_pct:.2}% < 100.00%: {}::{}",
                        relative, function.name
                    ));
                }
                if bf > 0 && branch_pct + 1e-9 < 100.0 {
                    failures.push(format!(
                        "branch coverage {branch_pct:.2}% < 100.00%: {}::{}",
                        relative, function.name
                    ));
                }
            }

            if native_coverage_in_scope(&relative) {
                native_measured += 1;
                native.add(lf, lh, bf, bh);
                if lh == 0
                    && function.cc >= ZERO_HIT_COMPLEX_CC
                    && !formatting_only(&function.name)
                {
                    failures.push(format!(
                        "zero-hit native function has CC {} >= {ZERO_HIT_COMPLEX_CC}: {}::{}",
                        function.cc, relative, function.name
                    ));
                }
                if lh > 0 && function_crap > MAX_CRAP + 1e-9 {
                    failures.push(format!(
                        "CRAP {function_crap:.2} > {MAX_CRAP:.2}: {}::{} (CC {}, line {line_pct:.2}%)",
                        relative, function.name, function.cc
                    ));
                }
            } else {
                adapter_measured += 1;
            }
        }
    }

    for entry in &critical {
        let key = (entry.source.clone(), entry.function.clone());
        if !seen_critical.contains(&key) {
            failures.push(format!(
                "critical function target not found uniquely in production scan: {}: {}::{} ({})",
                entry.id, entry.source, entry.function, entry.reason
            ));
        }
    }

    if measured == 0 {
        failures.push("no production functions had LCOV executable-line data".to_owned());
    }
    if native.lines_found == 0 {
        failures.push("no native production function ranges had LCOV executable-line data".to_owned());
    } else {
        let native_line_pct = percent(native.lines_hit, native.lines_found);
        let native_branch_pct = percent(native.branches_hit, native.branches_found);
        if native_line_pct + 1e-9 < NATIVE_LINE_MIN {
            failures.push(format!(
                "native aggregate line coverage {native_line_pct:.2}% < {NATIVE_LINE_MIN:.2}%"
            ));
        }
        if native.branches_found > 0 && native_branch_pct + 1e-9 < NATIVE_BRANCH_MIN {
            failures.push(format!(
                "native aggregate branch coverage {native_branch_pct:.2}% < {NATIVE_BRANCH_MIN:.2}%"
            ));
        }
    }

    if let Some(parent) = Path::new(&args[3]).parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(&args[3], report).map_err(|error| format!("{}: {error}", args[3]))?;

    if failures.is_empty() {
        let native_line_pct = percent(native.lines_hit, native.lines_found);
        let native_branch_pct = percent(native.branches_hit, native.branches_found);
        println!(
            "function quality passed: {native_measured} native measured functions at {native_line_pct:.2}% line / {native_branch_pct:.2}% branch aggregate, {adapter_measured} adapter functions delegated to browser/interop evidence, critical crypto 100%, CC <= {MAX_CC}, measured CRAP <= {MAX_CRAP}"
        );
        Ok(())
    } else {
        failures.sort();
        failures.dedup();
        Err(format!(
            "function quality failed ({} issue(s)):\n{}\nreport: {}",
            failures.len(),
            failures.join("\n"),
            args[3]
        ))
    }
}

fn native_coverage_in_scope(relative: &str) -> bool {
    !relative.starts_with("crates/hydra-msg-cli/")
        && !relative.starts_with("crates/hydra-msg-wasm/")
}

fn formatting_only(function: &str) -> bool {
    function == "fmt"
}

fn production_sources() -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for entry in fs::read_dir("crates").map_err(|error| format!("crates: {error}"))? {
        let path = entry.map_err(|error| error.to_string())?.path().join("src");
        if path.is_dir() {
            out.extend(rust_source::rust_sources(&path)?);
        }
    }
    out.sort();
    Ok(out)
}

fn normalize_repo_path(path: &Path) -> Result<String, String> {
    let cwd = env::current_dir().map_err(|error| error.to_string())?;
    let relative = path.strip_prefix(&cwd).unwrap_or(path);
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn parse_critical(contents: &str, label: &str) -> Result<Vec<Critical>, String> {
    let mut out = Vec::new();
    let mut ids = HashSet::new();
    let mut keys = HashSet::new();
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts = line.split('|').map(str::trim).collect::<Vec<_>>();
        if parts.len() != 4 || parts.iter().any(|part| part.is_empty()) {
            return Err(format!(
                "{label}:{}: expected 4 nonempty fields",
                index + 1
            ));
        }
        if !ids.insert(parts[0].to_owned()) {
            return Err(format!(
                "{label}:{}: duplicate id {}",
                index + 1,
                parts[0]
            ));
        }
        let key = (parts[1].replace('\\', "/"), parts[2].to_owned());
        if !keys.insert(key.clone()) {
            return Err(format!(
                "{label}:{}: duplicate function target {}::{}",
                index + 1,
                key.0,
                key.1
            ));
        }
        out.push(Critical {
            id: parts[0].to_owned(),
            source: key.0,
            function: key.1,
            reason: parts[3].to_owned(),
        });
    }
    if out.is_empty() {
        return Err(format!("{label}: no critical functions"));
    }
    Ok(out)
}

fn crap(cc: u32, coverage: f64) -> f64 {
    let uncovered = 1.0 - coverage.clamp(0.0, 1.0);
    let complexity = f64::from(cc);
    complexity * complexity * uncovered * uncovered * uncovered + complexity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crap_is_cc_at_full_coverage_and_penalizes_uncovered_complexity() {
        assert!((crap(12, 1.0) - 12.0).abs() < 1e-9);
        assert!(crap(12, 0.0) > 100.0);
        assert!(crap(12, 0.90) < 13.0);
    }

    #[test]
    fn critical_manifest_rejects_duplicates_and_empty_fields() {
        let good = "a|crates/x.rs|open|AEAD authentication\n";
        assert_eq!(parse_critical(good, "m").unwrap().len(), 1);
        assert!(parse_critical("a|x|f|r\na|y|g|r\n", "m").is_err());
        assert!(parse_critical("a|x||r\n", "m").is_err());
    }

    #[test]
    fn native_coverage_scope_excludes_only_release_gated_adapters() {
        assert!(native_coverage_in_scope("crates/hydra-msg/src/lib.rs"));
        assert!(!native_coverage_in_scope("crates/hydra-msg-cli/src/main.rs"));
        assert!(!native_coverage_in_scope("crates/hydra-msg-wasm/src/lib.rs"));
        assert!(formatting_only("fmt"));
        assert!(!formatting_only("decode"));
    }
}
