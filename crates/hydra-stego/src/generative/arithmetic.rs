use crate::{model::TokenCandidate, StegoError};

const TOTAL: u64 = 32_768;
const HALF: u64 = 0x8000_0000;
const QUARTER: u64 = 0x4000_0000;
const THREE_QUARTER: u64 = 0xc000_0000;
const WORD_MASK: u64 = 0xffff_ffff;

#[derive(Debug, Clone)]
pub(super) struct Frequencies {
    cumulative: Vec<u64>,
}

impl Frequencies {
    pub(super) fn from_candidates(
        candidates: &[TokenCandidate],
        temperature: f64,
    ) -> Result<Self, StegoError> {
        validate_candidate_count(candidates.len())?;
        let weights = candidate_weights(candidates, temperature)?;
        let counts = normalized_counts(&weights, candidates.len())?;
        let cumulative = cumulative_counts(counts)?;
        Ok(Self { cumulative })
    }

    fn symbol_for(&self, value: u64) -> usize {
        self.cumulative
            .partition_point(|boundary| *boundary <= value)
            .saturating_sub(1)
            .min(self.cumulative.len() - 2)
    }

    fn interval(&self, symbol: usize) -> (u64, u64) {
        (self.cumulative[symbol], self.cumulative[symbol + 1])
    }
}

fn validate_candidate_count(count: usize) -> Result<(), StegoError> {
    if count < 2 || count as u64 >= TOTAL {
        return Err(StegoError::Model(
            "arithmetic coding requires between 2 and 32,767 candidates".to_owned(),
        ));
    }
    Ok(())
}

fn candidate_weights(
    candidates: &[TokenCandidate],
    temperature: f64,
) -> Result<Vec<f64>, StegoError> {
    let maximum = candidates
        .iter()
        .map(|candidate| candidate.score())
        .reduce(f64::max)
        .ok_or_else(|| StegoError::Model("model returned no candidates".to_owned()))?;
    let weights = candidates
        .iter()
        .map(|candidate| ((candidate.score() - maximum) / temperature).exp())
        .collect::<Vec<_>>();
    if weights.iter().any(|weight| !weight.is_finite()) {
        return Err(StegoError::Model(
            "model scores produced invalid arithmetic weights".to_owned(),
        ));
    }
    Ok(weights)
}

fn normalized_counts(weights: &[f64], candidate_count: usize) -> Result<Vec<u64>, StegoError> {
    let weight_sum = weights.iter().sum::<f64>();
    if !weight_sum.is_finite() || weight_sum <= 0.0 {
        return Err(StegoError::Model(
            "model scores have no usable probability mass".to_owned(),
        ));
    }
    let available = TOTAL - candidate_count as u64;
    let mut counts = vec![1_u64; candidate_count];
    let mut remainders = Vec::with_capacity(candidate_count);
    let mut used = candidate_count as u64;
    for (index, weight) in weights.iter().copied().enumerate() {
        let exact = weight / weight_sum * available as f64;
        let base = exact.floor() as u64;
        counts[index] += base;
        used += base;
        remainders.push((index, exact - base as f64));
    }
    if used > TOTAL {
        remove_excess(&mut counts, &mut remainders, used - TOTAL)?;
    } else {
        distribute_remainder(&mut counts, &mut remainders, TOTAL - used);
    }
    Ok(counts)
}

fn remove_excess(
    counts: &mut [u64],
    remainders: &mut [(usize, f64)],
    mut excess: u64,
) -> Result<(), StegoError> {
    remainders.sort_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| right.0.cmp(&left.0))
    });
    for (index, _) in remainders.iter() {
        let removable = (counts[*index] - 1).min(excess);
        counts[*index] -= removable;
        excess -= removable;
        if excess == 0 {
            return Ok(());
        }
    }
    Err(StegoError::Model(
        "could not normalize arithmetic frequencies".to_owned(),
    ))
}

fn distribute_remainder(counts: &mut [u64], remainders: &mut [(usize, f64)], remaining: u64) {
    remainders.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    for index in 0..remaining as usize {
        counts[remainders[index % remainders.len()].0] += 1;
    }
}

fn cumulative_counts(counts: Vec<u64>) -> Result<Vec<u64>, StegoError> {
    let mut cumulative = Vec::with_capacity(counts.len() + 1);
    cumulative.push(0);
    for count in counts {
        cumulative.push(cumulative.last().copied().unwrap_or(0) + count);
    }
    if cumulative.last().copied() != Some(TOTAL) {
        return Err(StegoError::Model(
            "arithmetic frequencies did not sum to their fixed total".to_owned(),
        ));
    }
    Ok(cumulative)
}

pub(super) struct Decoder<F> {
    low: u64,
    high: u64,
    code: u64,
    read: F,
}

impl<F: FnMut() -> u8> Decoder<F> {
    pub(super) fn new(mut read: F) -> Self {
        let mut code = 0_u64;
        for _ in 0..32 {
            code = (code << 1) | u64::from(read());
        }
        Self {
            low: 0,
            high: WORD_MASK,
            code,
            read,
        }
    }

    pub(super) fn symbol(&mut self, frequencies: &Frequencies) -> usize {
        let range = self.high - self.low + 1;
        let scaled = ((self.code - self.low + 1) * TOTAL - 1) / range;
        let symbol = frequencies.symbol_for(scaled);
        let (lower, upper) = frequencies.interval(symbol);
        self.high = self.low + range * upper / TOTAL - 1;
        self.low += range * lower / TOTAL;

        loop {
            if self.high < HALF {
                // The interval already lies in the lower half.
            } else if self.low >= HALF {
                self.low -= HALF;
                self.high -= HALF;
                self.code -= HALF;
            } else if self.low >= QUARTER && self.high < THREE_QUARTER {
                self.low -= QUARTER;
                self.high -= QUARTER;
                self.code -= QUARTER;
            } else {
                break;
            }
            self.low = (self.low << 1) & WORD_MASK;
            self.high = ((self.high << 1) | 1) & WORD_MASK;
            self.code = ((self.code << 1) | u64::from((self.read)())) & WORD_MASK;
        }
        symbol
    }
}

pub(super) struct Encoder<F> {
    low: u64,
    high: u64,
    pending: usize,
    emit: F,
}

impl<F: FnMut(u8)> Encoder<F> {
    pub(super) fn new(emit: F) -> Self {
        Self {
            low: 0,
            high: WORD_MASK,
            pending: 0,
            emit,
        }
    }

    pub(super) fn symbol(&mut self, symbol: usize, frequencies: &Frequencies) {
        let range = self.high - self.low + 1;
        let (lower, upper) = frequencies.interval(symbol);
        self.high = self.low + range * upper / TOTAL - 1;
        self.low += range * lower / TOTAL;

        loop {
            if self.high < HALF {
                self.output(0);
            } else if self.low >= HALF {
                self.output(1);
                self.low -= HALF;
                self.high -= HALF;
            } else if self.low >= QUARTER && self.high < THREE_QUARTER {
                self.pending += 1;
                self.low -= QUARTER;
                self.high -= QUARTER;
            } else {
                break;
            }
            self.low = (self.low << 1) & WORD_MASK;
            self.high = ((self.high << 1) | 1) & WORD_MASK;
        }
    }

    fn output(&mut self, bit: u8) {
        (self.emit)(bit);
        for _ in 0..self.pending {
            (self.emit)(bit ^ 1);
        }
        self.pending = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantized_frequencies_are_positive_and_exact() {
        let candidates = [
            TokenCandidate::new(1, 0.0),
            TokenCandidate::new(2, -0.5),
            TokenCandidate::new(3, -4.0),
        ];
        let frequencies = Frequencies::from_candidates(&candidates, 0.8).unwrap();
        assert_eq!(frequencies.cumulative[0], 0);
        assert_eq!(frequencies.cumulative.last(), Some(&TOTAL));
        assert!(frequencies
            .cumulative
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
    }
}
