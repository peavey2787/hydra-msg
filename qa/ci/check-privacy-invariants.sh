#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

handshake_file="crates/hydra-msg/src/codec/handshake.rs"
handshake_api_file="crates/hydra-msg/src/handshake.rs"
storage_file="crates/hydra-msg/src/storage.rs"
storage_codec_file="crates/hydra-msg/src/codec/storage.rs"
lib_file="crates/hydra-msg/src/lib.rs"

if [ ! -f "$handshake_file" ] || [ ! -f "$handshake_api_file" ]; then
  echo "hydra-msg handshake files missing" >&2
  exit 1
fi
if [ ! -f "$storage_file" ] || [ ! -f "$storage_codec_file" ] || [ ! -f "$lib_file" ]; then
  echo "hydra-msg storage files missing" >&2
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
require_source_text "$handshake_file" "HYDRA-MSG/v1/facade-handshake/hybrid-secret" "domain-separated hybrid facade secret derivation"
require_source_text "$handshake_api_file" "verify_answer_signature(&parsed_answer, &pending.offer)?" "initiator verifies answer signature against pending offer"
require_source_text "$handshake_api_file" "verify_answer_confirmation(" "initiator/responder verify derived hybrid material before session install"
require_source_text "$handshake_api_file" "pending.contact_id != ContactId(parsed_answer.peer_id.0)" "initiator rejects answers from swapped identities"

forbidden_source_text "$handshake_file" "derive_facade_handshake_material" "removed public transcript-only facade secret derivation helper"
forbidden_source_text "$handshake_file" "public transcript" "facade secret must not be documented as public-transcript derived"

require_source_text "$lib_file" "STATE_V2_MAGIC" "encrypted local state v2 format constant"
require_source_text "$lib_file" 'const STATE_FILE_NAME: &str = "state-v2.hydra"' "normal local state file uses encrypted v2 path"
require_source_text "$storage_file" "pub fn open(data_dir: impl AsRef<Path>, state_password: impl AsRef<str>)" "state password is required when opening local state"
require_source_text "$storage_file" "encode_encrypted_state_v2" "normal state is sealed before writing"
require_source_text "$storage_file" "decode_encrypted_state_v2" "normal state is opened with authentication"
require_source_text "$storage_file" "reject_state_rollback" "local replay rollback guard is enforced"
require_source_text "$storage_codec_file" "RustCryptoBackend::aead_seal" "encrypted state uses AEAD sealing"
require_source_text "$storage_codec_file" "RustCryptoBackend::aead_open" "encrypted state uses AEAD opening"
require_source_text "$storage_codec_file" "STATE_V2_KDF_PROFILE" "encrypted state stores versioned KDF profile"
forbidden_source_text "$lib_file" 'STATE_V1' "normal local state must not use plaintext v1 constants"

if grep -RIn "derive_facade_handshake_material" crates/hydra-msg/src; then
  echo "removed public transcript-only facade helper was reintroduced" >&2
  exit 1
fi

forbidden_source_text "$storage_file" "load_state_without_password" "state must never open without a state password"
forbidden_source_text "$storage_file" "state_key: Option" "state encryption must not be optional"
forbidden_source_text "$storage_file" "state_v1" "current state path must not include plaintext migration helpers"
forbidden_source_text "$storage_file" "remove_file" "current state path must not delete plaintext migration files"

echo "privacy invariant checks passed"
