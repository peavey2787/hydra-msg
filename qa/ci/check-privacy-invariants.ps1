# HYDRA-MSG implementation privacy invariant checks.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

$HandshakeFile = "crates/hydra-msg/src/codec/handshake.rs"
$HandshakeApiFile = "crates/hydra-msg/src/handshake.rs"
$StorageFile = "crates/hydra-msg/src/storage.rs"
$StorageCodecFile = "crates/hydra-msg/src/codec/storage.rs"
$LibFile = "crates/hydra-msg/src/lib.rs"

if (!(Test-Path $HandshakeFile) -or !(Test-Path $HandshakeApiFile)) {
    throw "hydra-msg handshake files missing"
}
if (!(Test-Path $StorageFile) -or !(Test-Path $StorageCodecFile) -or !(Test-Path $LibFile)) {
    throw "hydra-msg storage files missing"
}

function Assert-SourceText {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $content = Get-Content $File -Raw
    if (!$content.Contains($Text)) {
        throw "privacy invariant missing: $Description; expected text '$Text' in $File"
    }
}

function Assert-NoSourceText {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $content = Get-Content $File -Raw
    if ($content.Contains($Text)) {
        throw "privacy invariant forbidden pattern found: $Description; forbidden text '$Text' in $File"
    }
}

Assert-SourceText $HandshakeFile "RustCryptoBackend::mldsa65_sign" "facade handshake offer/answer transcript signing"
Assert-SourceText $HandshakeFile "RustCryptoBackend::mldsa65_verify" "facade handshake transcript signature verification"
Assert-SourceText $HandshakeFile "x25519_secret.expose_secret()" "ephemeral X25519 shared secret included in facade handshake secret"
Assert-SourceText $HandshakeFile "kem_secret.expose_secret()" "ephemeral ML-KEM shared secret included in facade handshake secret"
Assert-SourceText $HandshakeFile "answer_confirmation_tag" "answer confirmation tag before initiator session installation"
Assert-SourceText $HandshakeFile "verify_answer_confirmation" "initiator/responder confirmation verification helper"
Assert-SourceText $HandshakeFile "HYDRA-MSG/v1/facade-handshake/hybrid-secret" "domain-separated hybrid facade secret derivation"
Assert-SourceText $HandshakeApiFile "verify_answer_signature(&parsed_answer, &pending.offer)?" "initiator verifies answer signature against pending offer"
Assert-SourceText $HandshakeApiFile "verify_answer_confirmation(" "initiator/responder verify derived hybrid material before session install"
Assert-SourceText $HandshakeApiFile "pending.contact_id != ContactId(parsed_answer.peer_id.0)" "initiator rejects answers from swapped identities"

Assert-NoSourceText $HandshakeFile "derive_facade_handshake_material" "removed public transcript-only facade secret derivation helper"
Assert-NoSourceText $HandshakeFile "public transcript" "facade secret must not be documented as public-transcript derived"

Assert-SourceText $LibFile "STATE_V2_MAGIC" "encrypted local state v2 format constant"
Assert-SourceText $LibFile "const STATE_FILE_NAME: &str = `"state-v2.hydra`"" "normal local state file uses encrypted v2 path"
Assert-SourceText $StorageFile "pub fn open(data_dir: impl AsRef<Path>, state_password: impl AsRef<str>)" "state password is required when opening local state"
Assert-SourceText $StorageFile "encode_encrypted_state_v2" "normal state is sealed before writing"
Assert-SourceText $StorageFile "decode_encrypted_state_v2" "normal state is opened with authentication"
Assert-SourceText $StorageFile "reject_state_rollback" "local replay rollback guard is enforced"
Assert-SourceText $StorageCodecFile "RustCryptoBackend::aead_seal" "encrypted state uses AEAD sealing"
Assert-SourceText $StorageCodecFile "RustCryptoBackend::aead_open" "encrypted state uses AEAD opening"
Assert-SourceText $StorageCodecFile "STATE_V2_KDF_PROFILE" "encrypted state stores versioned KDF profile"
Assert-NoSourceText $LibFile "STATE_V1" "normal local state must not use plaintext v1 constants"

Assert-NoSourceText $StorageFile "load_state_without_password" "state must never open without a state password"
Assert-NoSourceText $StorageFile "state_key: Option" "state encryption must not be optional"
Assert-NoSourceText $StorageFile "state_v1" "current state path must not include plaintext migration helpers"
Assert-NoSourceText $StorageFile "remove_file" "current state path must not delete plaintext migration files"

$reintroduced = Select-String -Path "crates/hydra-msg/src/*.rs", "crates/hydra-msg/src/codec/*.rs" -Pattern "derive_facade_handshake_material" -ErrorAction SilentlyContinue
if ($reintroduced) {
    $reintroduced | ForEach-Object { Write-Host $_ }
    throw "removed public transcript-only facade helper was reintroduced"
}

Write-Host "privacy invariant checks passed" -ForegroundColor Green
