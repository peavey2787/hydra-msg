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
    let mut inputs = corpus::corpus(rounds);
    if let Some(limit) = fuzz_input_limit()? {
        inputs = evenly_limit_inputs(inputs, limit);
    }
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

fn evenly_limit_inputs(inputs: Vec<corpus::FuzzInput>, limit: usize) -> Vec<corpus::FuzzInput> {
    if inputs.len() <= limit {
        return inputs;
    }
    if limit == 1 {
        return inputs.into_iter().take(1).collect();
    }

    let last_index = inputs.len() - 1;
    let mut next_slot = 0;
    inputs
        .into_iter()
        .enumerate()
        .filter_map(|(index, input)| {
            if next_slot < limit && index == next_slot * last_index / (limit - 1) {
                next_slot += 1;
                Some(input)
            } else {
                None
            }
        })
        .collect()
}

fn fuzz_input_limit() -> FuzzResult<Option<usize>> {
    match std::env::var("HYDRA_FUZZ_INPUT_LIMIT") {
        Ok(value) => {
            let limit = value
                .parse::<usize>()
                .map_err(|_| "HYDRA_FUZZ_INPUT_LIMIT must be a positive integer".to_string())?;
            if limit == 0 {
                return Err("HYDRA_FUZZ_INPUT_LIMIT must be a positive integer".to_string());
            }
            Ok(Some(limit))
        }
        Err(_) => Ok(None),
    }
}

fn fuzz_rounds() -> FuzzResult<usize> {
    match std::env::var("HYDRA_FUZZ_CASES") {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|_| "HYDRA_FUZZ_CASES must be a non-negative integer".to_string()),
        Err(_) => Ok(8),
    }
}

#[cfg(test)]
mod tests {
    use super::evenly_limit_inputs;
    use crate::corpus::FuzzInput;

    #[test]
    fn input_limit_samples_the_full_corpus_range() {
        let inputs = (0..20)
            .map(|index| FuzzInput {
                name: index.to_string(),
                bytes: vec![index],
            })
            .collect();
        let selected = evenly_limit_inputs(inputs, 5);

        assert_eq!(selected.len(), 5);
        assert_eq!(selected.first().unwrap().name, "0");
        assert_eq!(selected.last().unwrap().name, "19");
    }
}
