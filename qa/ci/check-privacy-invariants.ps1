# HYDRA-MSG implementation privacy invariant checks.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

$HandshakeFile = "crates/hydra-msg/src/codec/handshake.rs"
$HandshakeApiFile = "crates/hydra-msg/src/handshake.rs"

if (!(Test-Path $HandshakeFile) -or !(Test-Path $HandshakeApiFile)) {
    throw "hydra-msg handshake files missing"
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

$reintroduced = Select-String -Path "crates/hydra-msg/src/*.rs", "crates/hydra-msg/src/codec/*.rs" -Pattern "derive_facade_handshake_material" -ErrorAction SilentlyContinue
if ($reintroduced) {
    $reintroduced | ForEach-Object { Write-Host $_ }
    throw "removed public transcript-only facade helper was reintroduced"
}

Write-Host "privacy invariant checks passed" -ForegroundColor Green
