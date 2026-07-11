pub struct FuzzInput {
    pub name: String,
    pub bytes: Vec<u8>,
}

struct Seed {
    name: &'static str,
    bytes: &'static [u8],
}

const EMPTY_STATE: &[u8] =
    include_bytes!("../../../vectors/persistence/positive/TV-PERSIST-EMPTY-000/state_envelope.bin");
const FULL_STATE: &[u8] =
    include_bytes!("../../../vectors/persistence/positive/TV-PERSIST-FULL-000/state_envelope.bin");
const EMPTY_BACKUP: &[u8] =
    include_bytes!("../../../vectors/persistence/positive/TV-PERSIST-EMPTY-000/backup.bin");
const FULL_BACKUP: &[u8] =
    include_bytes!("../../../vectors/persistence/positive/TV-PERSIST-FULL-000/backup.bin");
const BAD_KDF_STATE: &[u8] = include_bytes!(
    "../../../vectors/persistence/negative/TV-PERSIST-BAD-KDF-PARAMS-000/state_envelope.bin"
);
const FLIPPED_STATE: &[u8] = include_bytes!(
    "../../../vectors/persistence/negative/TV-PERSIST-CIPHERTEXT-FLIP-000/state_envelope.bin"
);
const TRUNCATED_STATE: &[u8] = include_bytes!(
    "../../../vectors/persistence/negative/TV-PERSIST-TRUNCATED-000/state_envelope.bin"
);
const BAD_BACKUP_KDF: &[u8] = include_bytes!(
    "../../../vectors/persistence/parser-stress/TV-PERSISTENCE-BACKUP-BAD-KDF/backup.bin"
);
const BAD_BACKUP_NONCE: &[u8] = include_bytes!(
    "../../../vectors/persistence/parser-stress/TV-PERSISTENCE-BACKUP-BAD-NONCE/backup.bin"
);
const DUPLICATE_SNAPSHOT: &[u8] = include_bytes!(
    "../../../vectors/persistence/parser-stress/TV-PERSISTENCE-SNAPSHOT-DUPLICATE-SCALAR/snapshot.bin"
);
const BAD_MAGIC_STATE: &[u8] = include_bytes!(
    "../../../vectors/persistence/parser-stress/TV-PERSISTENCE-STATE-BAD-MAGIC/encrypted_state.bin"
);
const EMPTY_CIPHERTEXT_STATE: &[u8] = include_bytes!(
    "../../../vectors/persistence/parser-stress/TV-PERSISTENCE-STATE-EMPTY-CIPHERTEXT/encrypted_state.bin"
);

const SEEDS: &[Seed] = &[
    Seed {
        name: "empty",
        bytes: b"",
    },
    Seed {
        name: "single-zero",
        bytes: &[0],
    },
    Seed {
        name: "ascii-contact-magic",
        bytes: b"HYDRA-MSG-CONTACT\n",
    },
    Seed {
        name: "ascii-offer-magic",
        bytes: b"HYDRA-MSG-OFFER\n",
    },
    Seed {
        name: "ascii-answer-magic",
        bytes: b"HYDRA-MSG-ANSWER\n",
    },
    Seed {
        name: "ascii-fragment-magic",
        bytes: b"HYDRA-MSG-FRAGMENT\n",
    },
    Seed {
        name: "positive-empty-state",
        bytes: EMPTY_STATE,
    },
    Seed {
        name: "positive-full-state",
        bytes: FULL_STATE,
    },
    Seed {
        name: "positive-empty-backup",
        bytes: EMPTY_BACKUP,
    },
    Seed {
        name: "positive-full-backup",
        bytes: FULL_BACKUP,
    },
    Seed {
        name: "negative-bad-kdf-state",
        bytes: BAD_KDF_STATE,
    },
    Seed {
        name: "negative-flipped-state",
        bytes: FLIPPED_STATE,
    },
    Seed {
        name: "negative-truncated-state",
        bytes: TRUNCATED_STATE,
    },
    Seed {
        name: "parser-bad-backup-kdf",
        bytes: BAD_BACKUP_KDF,
    },
    Seed {
        name: "parser-bad-backup-nonce",
        bytes: BAD_BACKUP_NONCE,
    },
    Seed {
        name: "parser-duplicate-snapshot",
        bytes: DUPLICATE_SNAPSHOT,
    },
    Seed {
        name: "parser-bad-magic-state",
        bytes: BAD_MAGIC_STATE,
    },
    Seed {
        name: "parser-empty-ciphertext-state",
        bytes: EMPTY_CIPHERTEXT_STATE,
    },
];

pub fn corpus(rounds: usize) -> Vec<FuzzInput> {
    let mut inputs = Vec::new();
    for seed in SEEDS {
        inputs.push(FuzzInput {
            name: seed.name.to_string(),
            bytes: seed.bytes.to_vec(),
        });
        for round in 0..rounds {
            inputs.push(FuzzInput {
                name: format!("{}-mut-{round}", seed.name),
                bytes: mutate(seed.bytes, round as u64),
            });
        }
    }
    inputs.push(FuzzInput {
        name: "ascending-512".to_string(),
        bytes: (0..512).map(|value| value as u8).collect(),
    });
    inputs.push(FuzzInput {
        name: "zero-4096".to_string(),
        bytes: vec![0_u8; 4096],
    });
    inputs
}

fn mutate(seed: &[u8], round: u64) -> Vec<u8> {
    let mut rng = Rng::new(round ^ ((seed.len() as u64) << 17) ^ 0x9e37_79b9_7f4a_7c15);
    let mut out = seed.to_vec();
    match round % 8 {
        0 => flip_one(&mut out, &mut rng),
        1 => truncate(&mut out, &mut rng),
        2 => append_noise(&mut out, &mut rng),
        3 => insert_noise(&mut out, &mut rng),
        4 => overwrite_run(&mut out, &mut rng),
        5 => duplicate_prefix(&mut out, &mut rng),
        6 => reverse_window(&mut out, &mut rng),
        _ => splice_magic(&mut out, &mut rng),
    }
    out.truncate(128 * 1024);
    out
}

fn flip_one(bytes: &mut [u8], rng: &mut Rng) {
    if bytes.is_empty() {
        return;
    }
    let index = rng.index(bytes.len());
    bytes[index] ^= 1_u8 << (rng.next_u64() % 8);
}

fn truncate(bytes: &mut Vec<u8>, rng: &mut Rng) {
    if bytes.is_empty() {
        return;
    }
    let new_len = rng.index(bytes.len());
    bytes.truncate(new_len);
}

fn append_noise(bytes: &mut Vec<u8>, rng: &mut Rng) {
    let count = 1 + rng.index(64);
    for _ in 0..count {
        bytes.push(rng.next_u8());
    }
}

fn insert_noise(bytes: &mut Vec<u8>, rng: &mut Rng) {
    let index = if bytes.is_empty() {
        0
    } else {
        rng.index(bytes.len())
    };
    let count = 1 + rng.index(32);
    let noise: Vec<u8> = (0..count).map(|_| rng.next_u8()).collect();
    bytes.splice(index..index, noise);
}

fn overwrite_run(bytes: &mut [u8], rng: &mut Rng) {
    if bytes.is_empty() {
        return;
    }
    let index = rng.index(bytes.len());
    let count = 1 + rng.index((bytes.len() - index).min(32));
    for byte in &mut bytes[index..index + count] {
        *byte = rng.next_u8();
    }
}

fn duplicate_prefix(bytes: &mut Vec<u8>, rng: &mut Rng) {
    if bytes.is_empty() {
        bytes.extend_from_slice(b"HYDRA");
        return;
    }
    let count = 1 + rng.index(bytes.len().min(64));
    let prefix = bytes[..count].to_vec();
    bytes.extend_from_slice(&prefix);
}

fn reverse_window(bytes: &mut [u8], rng: &mut Rng) {
    if bytes.len() < 2 {
        return;
    }
    let start = rng.index(bytes.len() - 1);
    let end = start + 1 + rng.index(bytes.len() - start);
    bytes[start..end].reverse();
}

fn splice_magic(bytes: &mut Vec<u8>, rng: &mut Rng) {
    const MAGIC: &[u8] = b"HYDRA-MSG-FRAGMENT\n";
    let index = if bytes.is_empty() {
        0
    } else {
        rng.index(bytes.len())
    };
    bytes.splice(index..index, MAGIC.iter().copied());
}

struct Rng {
    state: u64,
}

impl Rng {
    const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            (self.next_u64() as usize) % len
        }
    }
}
