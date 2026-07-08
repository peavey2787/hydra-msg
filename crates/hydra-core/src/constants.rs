//! Normative HYDRA-MSG v1 byte sizes and suite identifiers.

pub const MAGIC: [u8; 4] = *b"HYD1";
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const SUITE_ID: [u8; 16] = *b"HYDRA1-MK768-M65";

pub const OUTER_HEADER_SIZE: usize = 64;
pub const AEAD_TAG_SIZE: usize = 16;
pub const INNER_HEADER_SIZE: usize = 96;

pub const LITE_ENVELOPE_SIZE: usize = 4_096;
pub const STANDARD_ENVELOPE_SIZE: usize = 32_768;
pub const FULL_ENVELOPE_SIZE: usize = 147_456;

pub const LITE_MAX_CONTENT_SIZE: usize = 3_920;
pub const STANDARD_MAX_CONTENT_SIZE: usize = 32_592;
pub const FULL_MAX_CONTENT_SIZE: usize = 147_280;

pub const X25519_SIZE: usize = 32;
pub const ML_KEM_768_EK_SIZE: usize = 1_184;
pub const ML_KEM_768_CT_SIZE: usize = 1_088;
pub const ML_KEM_SHARED_SECRET_SIZE: usize = 32;
pub const ML_DSA_65_VK_SIZE: usize = 1_952;
pub const ML_DSA_65_SIG_SIZE: usize = 3_309;
pub const HASH_SIZE: usize = 32;
pub const TRANSCRIPT_HASH_SIZE: usize = 64;
pub const SESSION_ID_SIZE: usize = 32;
pub const GROUP_ID_SIZE: usize = 32;
pub const ROUTE_TAG_SIZE: usize = 16;
pub const AEAD_KEY_SIZE: usize = 32;
pub const AEAD_NONCE_SIZE: usize = 12;

pub const MAX_SKIP: usize = 256;
pub const REPLAY_WINDOW_WIDTH: usize = MAX_SKIP + 1;
pub const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_WIDTH.div_ceil(u64::BITS as usize);
pub const MAX_GOVERNANCE_SIGNERS: usize = 16;
pub const MAX_COMMIT_SIGNATURES: usize = 17;
pub const MAX_INTERACTIVE_MEMBERS: usize = 256;
pub const MAX_BROADCAST_MEMBERS: usize = 8_192;
pub const MAX_BROADCAST_PRESENTERS: usize = 16;
pub const MAX_LITE_MEMBERS: usize = 64;

pub const LABEL_MESSAGE_KEY: &[u8] = b"HYDRA-MSG/v1/message-key";
pub const LABEL_CHAIN_STEP: &[u8] = b"HYDRA-MSG/v1/chain-advance";

const _: () = assert!(
    LITE_MAX_CONTENT_SIZE
        == LITE_ENVELOPE_SIZE - OUTER_HEADER_SIZE - AEAD_TAG_SIZE - INNER_HEADER_SIZE
);
const _: () = assert!(
    STANDARD_MAX_CONTENT_SIZE
        == STANDARD_ENVELOPE_SIZE - OUTER_HEADER_SIZE - AEAD_TAG_SIZE - INNER_HEADER_SIZE
);
const _: () = assert!(
    FULL_MAX_CONTENT_SIZE
        == FULL_ENVELOPE_SIZE - OUTER_HEADER_SIZE - AEAD_TAG_SIZE - INNER_HEADER_SIZE
);
