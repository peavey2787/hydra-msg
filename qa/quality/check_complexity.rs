#![forbid(unsafe_code)]
#![deny(warnings)]

mod rust_source;

use std::{env, fs, path::{Path, PathBuf}, process::ExitCode};

const MAX_CC: u32 = 12;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("{error}"); ExitCode::FAILURE }
    }
}

fn run() -> Result<(), String> {
    let mut failures = Vec::new();
    let mut functions = 0_u64;
    for path in production_sources()? {
        let relative = normalize_repo_path(&path)?;
        if rust_source::is_test_path(&relative) { continue; }
        let source = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for function in rust_source::functions(&source) {
            functions += 1;
            if function.cc > MAX_CC {
                failures.push(format!("CC {} > {MAX_CC}: {}::{} (lines {}-{})", function.cc, relative, function.name, function.start_line, function.end_line));
            }
        }
    }
    if functions == 0 { return Err("no production Rust functions found".to_owned()); }
    failures.sort();
    if failures.is_empty() {
        println!("cyclomatic complexity passed: {functions} production functions, CC <= {MAX_CC}");
        Ok(())
    } else {
        Err(format!("cyclomatic complexity failed ({} function(s)):\n{}", failures.len(), failures.join("\n")))
    }
}

fn production_sources() -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for entry in fs::read_dir("crates").map_err(|e| format!("crates: {e}"))? {
        let p = entry.map_err(|e| e.to_string())?.path().join("src");
        if p.is_dir() { out.extend(rust_source::rust_sources(&p)?); }
    }
    out.sort();
    Ok(out)
}

fn normalize_repo_path(path: &Path) -> Result<String, String> {
    let cwd = env::current_dir().map_err(|e| e.to_string())?;
    let relative = path.strip_prefix(&cwd).unwrap_or(path);
    Ok(relative.to_string_lossy().replace('\\', "/"))
}
