#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

handshake_file="crates/hydra-msg/src/codec/handshake.rs"
handshake_api_file="crates/hydra-msg/src/handshake.rs"
storage_file="crates/hydra-msg/src/storage.rs"
storage_codec_file="crates/hydra-msg/src/codec/storage.rs"
identity_codec_file="crates/hydra-msg/src/codec/identity.rs"
kdf_codec_file="crates/hydra-msg/src/codec/kdf.rs"
lib_file="crates/hydra-msg/src/lib.rs"
contact_file="crates/hydra-msg/src/contacts.rs"
contact_codec_file="crates/hydra-msg/src/codec/contacts.rs"
lobby_file="crates/hydra-msg/src/lobbies.rs"
lobby_codec_file="crates/hydra-msg/src/codec/lobbies.rs"

if [ ! -f "$handshake_file" ] || [ ! -f "$handshake_api_file" ]; then
  echo "hydra-msg handshake files missing" >&2
  exit 1
fi
if [ ! -f "$storage_file" ] || [ ! -f "$storage_codec_file" ] || [ ! -f "$identity_codec_file" ] || [ ! -f "$kdf_codec_file" ] || [ ! -f "$lib_file" ]; then
  echo "hydra-msg storage/KDF files missing" >&2
  exit 1
fi
if [ ! -f "$contact_file" ] || [ ! -f "$contact_codec_file" ] || [ ! -f "$lobby_file" ] || [ ! -f "$lobby_codec_file" ]; then
  echo "hydra-msg metadata privacy files missing" >&2
  exit 1
fi

require_source_text() {
  file=$1
  text=$2
  description=$3
  if ! grep -Fq "$text" "$file"; then
    echo "privacy invariant missing: $description" >&2
    echo "expected text: $text" >&2
    echo "file: $file" >&2
    exit 1
  fi
}

forbidden_source_text() {
  file=$1
  text=$2
  description=$3
  if grep -Fq "$text" "$file"; then
    echo "privacy invariant forbidden pattern found: $description" >&2
    echo "forbidden text: $text" >&2
    echo "file: $file" >&2
    exit 1
  fi
}

require_source_text "$handshake_file" "RustCryptoBackend::mldsa65_sign" "facade handshake offer/answer transcript signing"
require_source_text "$handshake_file" "RustCryptoBackend::mldsa65_verify" "facade handshake transcript signature verification"
require_source_text "$handshake_file" "x25519_secret.expose_secret()" "ephemeral X25519 shared secret included in facade handshake secret"
require_source_text "$handshake_file" "kem_secret.expose_secret()" "ephemeral ML-KEM shared secret included in facade handshake secret"
require_source_text "$handshake_file" "answer_confirmation_tag" "answer confirmation tag before initiator session installation"
require_source_text "$handshake_file" "verify_answer_confirmation" "initiator/responder confirmation verification helper"
require_source_text "$handshake_file" "HYDRA-MSG/facade-handshake/hybrid-secret" "domain-separated hybrid facade secret derivation"
require_source_text "$handshake_api_file" "verify_answer_signature(&parsed_answer, &pending.offer)?" "initiator verifies answer signature against pending offer"
require_source_text "$handshake_api_file" "verify_answer_confirmation(" "initiator/responder verify derived hybrid material before session install"
require_source_text "$handshake_api_file" "pending.contact_id != ContactId(parsed_answer.peer_id.0)" "initiator rejects answers from swapped identities"

forbidden_source_text "$handshake_file" "derive_facade_handshake_material" "removed public transcript-only facade secret derivation helper"
forbidden_source_text "$handshake_file" "public transcript" "facade secret must not be documented as public-transcript derived"

require_source_text "$lib_file" "STATE_MAGIC" "encrypted local state format constant"
require_source_text "$lib_file" 'const STATE_FILE_NAME: &str = "state.hydra"' "normal local state file uses encrypted current path"
require_source_text "$storage_file" "pub fn open(data_dir: impl AsRef<Path>, state_password: impl AsRef<str>)" "state password is required when opening local state"
require_source_text "$storage_file" "encode_encrypted_state" "normal state is sealed before writing"
require_source_text "$storage_file" "decode_encrypted_state" "normal state is opened with authentication"
require_source_text "$storage_file" "reject_state_rollback" "local replay rollback guard is enforced"
require_source_text "$storage_codec_file" "RustCryptoBackend::aead_seal" "encrypted state uses AEAD sealing"
require_source_text "$storage_codec_file" "RustCryptoBackend::aead_open" "encrypted state uses AEAD opening"
require_source_text "$storage_codec_file" "parse_state_kdf" "encrypted state reads stored KDF parameters before deriving the state key"
require_source_text "$storage_codec_file" "encode_kdf_fields" "encrypted state stores explicit KDF parameters"
require_source_text "$kdf_codec_file" "scrypt::" "memory-hard scrypt KDF implementation is used"
require_source_text "$kdf_codec_file" "KDF_ALGORITHM_SCRYPT" "current memory-hard KDF algorithm id"
require_source_text "$kdf_codec_file" "kdf_log_n" "explicit scrypt log_n parameter is stored"
require_source_text "$kdf_codec_file" "kdf_salt" "per-record random KDF salt is stored"
require_source_text "$identity_codec_file" "PasswordKdfRecord::new_interactive()?" "identity password records use per-record KDF parameters"
require_source_text "$identity_codec_file" "derive_password_key" "identity seed wrapping uses memory-hard password derivation"
forbidden_source_text "$storage_codec_file" "hkdf-sha3-256" "encrypted state must not use the cheap KDF profile"
forbidden_source_text "$storage_codec_file" "hkdf_extract" "encrypted state password key must not use HKDF directly"
forbidden_source_text "$identity_codec_file" "sha3_256(password" "identity password tag must not be direct SHA3 over the password"
forbidden_source_text "$lib_file" 'STATE_V' "normal local state must not use numbered state constants"

if grep -RIn "derive_facade_handshake_material" crates/hydra-msg/src; then
  echo "removed public transcript-only facade helper was reintroduced" >&2
  exit 1
fi

forbidden_source_text "$storage_file" "load_state_without_password" "state must never open without a state password"
forbidden_source_text "$storage_file" "state_key: Option" "state encryption must not be optional"
forbidden_source_text "$storage_file" "state_v1" "current state path must not include plaintext alternate-format helpers"
forbidden_source_text "$storage_file" "remove_file" "current state path must not delete plaintext files"


require_source_text "$lib_file" 'CONTACT_CARD_MAGIC: &str = "HYDRA-MSG-CONTACT"' "current minimized contact-card format"
require_source_text "$lib_file" 'LOBBY_INVITE_MAGIC: &str = "HYDRA-MSG-LOBBY-INVITE"' "current minimized lobby-invite format"
require_source_text "$contact_file" "pub fn create_labeled_contact_card" "explicit labeled contact-card API"
require_source_text "$contact_file" "pub fn create_one_time_contact_card" "first-class one-time contact-card API"
require_source_text "$contact_file" "identity_record_from_seed(String::new()" "one-time contact cards use empty local label by default"
require_source_text "$contact_codec_file" "pub(crate) fn encode_contact_card(" "current contact-card encoder exists"
require_source_text "$contact_codec_file" "public_key:" "contact cards carry public verification key"
forbidden_source_text "$contact_codec_file" "id:{}" "default contact cards must not encode contact id as a field"
forbidden_source_text "$contact_codec_file" "safety:{}" "default contact cards must not encode safety code as a field"
require_source_text "$lobby_file" "pub fn create_labeled_lobby_invite" "explicit labeled lobby-invite API"
require_source_text "$lobby_file" "pub fn create_lobby_member_invite" "explicit member-list lobby-invite API"
require_source_text "$lobby_file" "pub fn create_one_time_lobby_invite" "first-class one-time lobby-invite API"
require_source_text "$lobby_codec_file" "include_label: bool" "lobby invite label exposure is explicit"
require_source_text "$lobby_codec_file" "members: Option<&[ContactId]>" "lobby invite member exposure is explicit"
forbidden_source_text "$lobby_codec_file" "placeholder invite" "lobby invite current decoder must not include placeholder alternate-format handling"

if grep -RInE "HYDRA-MSG-[A-Z0-9-]*-V[0-9]|state-v[0-9]|scrypt-v[0-9]|hydra-msg-[a-z0-9-]*-v[0-9]|/v[0-9]" \
  crates/hydra-msg examples/hydra-app examples/hydra-app-core README.md crates/hydra-msg/README.md \
  docs/roadmap.md docs/impl/message-flow docs/project/audit/privacy-baseline-invariant-map.md docs/validation/benchmark-results.md; then
  echo "privacy invariant forbidden pattern found: facade/app format labels must not carry version tags" >&2
  exit 1
fi

echo "privacy invariant checks passed"
