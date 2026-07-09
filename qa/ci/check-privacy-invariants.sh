#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

handshake_file="crates/hydra-msg/src/codec/handshake.rs"
handshake_api_file="crates/hydra-msg/src/handshake.rs"

if [ ! -f "$handshake_file" ] || [ ! -f "$handshake_api_file" ]; then
  echo "hydra-msg handshake files missing" >&2
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

if grep -RIn "derive_facade_handshake_material" crates/hydra-msg/src; then
  echo "removed public transcript-only facade helper was reintroduced" >&2
  exit 1
fi

echo "privacy invariant checks passed"
