#![forbid(unsafe_code)]

mod corpus;
mod parsers;
mod state;
mod util;

use util::FuzzResult;

fn main() {
    if let Err(error) = run() {
        eprintln!("HYDRA-MSG fuzz gate failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> FuzzResult<()> {
    let rounds = fuzz_rounds()?;
    let inputs = corpus::corpus(rounds);
    let parser_cases = parsers::run(&inputs)?;
    let state_cases = state::run(&inputs)?;
    println!(
        "HYDRA-MSG fuzz gate passed: inputs={} parser_cases={} state_cases={}",
        inputs.len(),
        parser_cases,
        state_cases
    );
    Ok(())
}

fn fuzz_rounds() -> FuzzResult<usize> {
    match std::env::var("HYDRA_FUZZ_CASES") {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|_| "HYDRA_FUZZ_CASES must be a non-negative integer".to_string()),
        Err(_) => Ok(8),
    }
}
