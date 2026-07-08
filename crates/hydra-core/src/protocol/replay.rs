use crate::{MAX_SKIP, REPLAY_WINDOW_WIDTH, REPLAY_WINDOW_WORDS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    Replay,
    TooOld,
}

/// Covers the current accepted index plus all `MAX_SKIP` predecessors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayWindow {
    highest_seen: Option<u64>,
    bits: [u64; REPLAY_WINDOW_WORDS],
}

impl ReplayWindow {
    pub fn check(&self, index: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest_seen else {
            return Ok(());
        };
        if index > highest {
            return Ok(());
        }
        let delta = highest - index;
        if delta >= REPLAY_WINDOW_WIDTH as u64 {
            return Err(ReplayError::TooOld);
        }
        let word = usize::try_from(delta / 64).expect("replay word is bounded");
        let bit = delta % 64;
        if self.bits[word] & (1_u64 << bit) != 0 {
            return Err(ReplayError::Replay);
        }
        Ok(())
    }

    pub fn mark(&mut self, index: u64) -> Result<(), ReplayError> {
        self.check(index)?;
        match self.highest_seen {
            None => {
                self.highest_seen = Some(index);
                self.bits[0] = 1;
            }
            Some(highest) if index > highest => {
                shift_left(&mut self.bits, index - highest);
                self.highest_seen = Some(index);
                self.bits[0] |= 1;
            }
            Some(highest) => {
                let delta = highest - index;
                let word = usize::try_from(delta / 64).expect("replay word is bounded");
                self.bits[word] |= 1_u64 << (delta % 64);
            }
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.highest_seen = None;
        self.bits.fill(0);
    }

    #[doc(hidden)]
    pub fn append_test_commitment(&self, output: &mut Vec<u8>) {
        match self.highest_seen {
            Some(highest) => {
                output.push(1);
                output.extend_from_slice(&highest.to_be_bytes());
            }
            None => output.extend_from_slice(&[0; 9]),
        }
        for word in self.bits {
            output.extend_from_slice(&word.to_be_bytes());
        }
    }
}

impl Drop for ReplayWindow {
    fn drop(&mut self) {
        self.clear();
    }
}

fn shift_left(words: &mut [u64; REPLAY_WINDOW_WORDS], shift: u64) {
    if shift >= REPLAY_WINDOW_WIDTH as u64 {
        words.fill(0);
        return;
    }
    let whole_words = usize::try_from(shift / 64).expect("word shift is bounded");
    let bit_shift = u32::try_from(shift % 64).expect("bit shift is bounded");
    let original = *words;
    words.fill(0);
    for (destination, word) in words.iter_mut().enumerate().skip(whole_words) {
        let source = destination - whole_words;
        *word |= original[source] << bit_shift;
        if bit_shift != 0 && source > 0 {
            *word |= original[source - 1] >> (64 - bit_shift);
        }
    }
    let used_bits = REPLAY_WINDOW_WIDTH % u64::BITS as usize;
    if used_bits != 0 {
        let mask = (1_u64 << used_bits) - 1;
        *words.last_mut().expect("replay window is nonempty") &= mask;
    }
}

const _: () = assert!(REPLAY_WINDOW_WIDTH == MAX_SKIP + 1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_plus_max_skip_predecessors_are_representable() {
        let mut delayed = ReplayWindow::default();
        delayed.mark(MAX_SKIP as u64).unwrap();
        delayed.mark(0).unwrap();
        assert_eq!(delayed.mark(0), Err(ReplayError::Replay));
    }

    #[test]
    fn one_beyond_max_skip_history_is_too_old() {
        let mut window = ReplayWindow::default();
        window.mark((MAX_SKIP + 1) as u64).unwrap();
        assert_eq!(window.check(0), Err(ReplayError::TooOld));
    }
}

/// Exportable replay-window state for encrypted live-state persistence.
///
/// This snapshot contains replay metadata only. Apps must store it inside an
/// authenticated encrypted state store and should pair it with rollback checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayWindowSnapshot {
    pub highest_seen: Option<u64>,
    pub bits: [u64; REPLAY_WINDOW_WORDS],
}

impl ReplayWindow {
    #[must_use]
    pub const fn export_snapshot(&self) -> ReplayWindowSnapshot {
        ReplayWindowSnapshot {
            highest_seen: self.highest_seen,
            bits: self.bits,
        }
    }

    #[must_use]
    pub const fn from_snapshot(snapshot: ReplayWindowSnapshot) -> Self {
        Self {
            highest_seen: snapshot.highest_seen,
            bits: snapshot.bits,
        }
    }
}
