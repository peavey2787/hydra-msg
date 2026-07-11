# HYDRA-MSG implementation privacy invariant checks.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$HandshakeFile = "crates/hydra-msg/src/codec/handshake.rs"
$HandshakeApiFile = "crates/hydra-msg/src/handshake/mod.rs"
$StorageFile = "crates/hydra-msg/src/api/storage.rs"
$StorageCodecFile = "crates/hydra-msg/src/codec/storage.rs"
$EncryptedSnapshotFile = "crates/hydra-msg/src/persistence/encrypted_snapshot.rs"
$SnapshotFile = "crates/hydra-msg/src/persistence/snapshot.rs"
$IdentityCodecFile = "crates/hydra-msg/src/codec/identity.rs"
$KdfCodecFile = "crates/hydra-msg/src/codec/kdf.rs"
$LibFile = "crates/hydra-msg/src/lib.rs"
$ContactFile = "crates/hydra-msg/src/api/contacts.rs"
$ContactCodecFile = "crates/hydra-msg/src/codec/contacts.rs"
$LobbyFile = "crates/hydra-msg/src/api/lobbies.rs"
$LobbyDeliveryFile = "crates/hydra-msg/src/lobby/delivery.rs"
$LobbyRoutingFile = "crates/hydra-msg/src/lobby/routing.rs"
$LobbyCodecFile = "crates/hydra-msg/src/codec/lobbies.rs"
$AuthFile = "crates/hydra-msg/src/api/anonymous_auth.rs"
$AuthCodecFile = "crates/hydra-msg/src/codec/auth.rs"
$AuthTestsFile = "crates/hydra-msg/src/tests/anonymous_auth.rs"

if (!(Test-Path $HandshakeFile) -or !(Test-Path $HandshakeApiFile)) {
    throw "hydra-msg handshake files missing"
}
if (!(Test-Path $StorageFile) -or !(Test-Path $StorageCodecFile) -or !(Test-Path $EncryptedSnapshotFile) -or !(Test-Path $SnapshotFile) -or !(Test-Path $IdentityCodecFile) -or !(Test-Path $KdfCodecFile) -or !(Test-Path $LibFile)) {
    throw "hydra-msg storage/KDF files missing"
}
if (!(Test-Path $ContactFile) -or !(Test-Path $ContactCodecFile) -or !(Test-Path $LobbyFile) -or !(Test-Path $LobbyDeliveryFile) -or !(Test-Path $LobbyRoutingFile) -or !(Test-Path $LobbyCodecFile)) {
    throw "hydra-msg metadata privacy files missing"
}
if (!(Test-Path $AuthFile) -or !(Test-Path $AuthCodecFile) -or !(Test-Path $AuthTestsFile)) {
    throw "hydra-msg anonymous authorization files missing"
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
Assert-SourceText $HandshakeFile "HYDRA-MSG/facade-handshake/hybrid-secret" "domain-separated hybrid facade secret derivation"
Assert-SourceText $HandshakeApiFile "verify_answer_signature(&parsed_answer, &pending.offer)?" "initiator verifies answer signature against pending offer"
Assert-SourceText $HandshakeApiFile "verify_answer_confirmation(" "initiator/responder verify derived hybrid material before session install"
Assert-SourceText $HandshakeApiFile "pending.contact_id != ContactId(parsed_answer.peer_id.0)" "initiator rejects answers from swapped identities"

Assert-NoSourceText $HandshakeFile "derive_facade_handshake_material" "removed public transcript-only facade secret derivation helper"
Assert-NoSourceText $HandshakeFile "public transcript" "facade secret must not be documented as public-transcript derived"

Assert-SourceText $LibFile "STATE_MAGIC" "encrypted local state format constant"
Assert-SourceText $LibFile "const STATE_FILE_NAME: &str = `"state.hydra`"" "normal local state file uses encrypted current path"
Assert-SourceText $StorageFile "pub fn open(data_dir: impl AsRef<Path>, state_password: impl AsRef<str>)" "state password is required when opening local state"
Assert-SourceText $EncryptedSnapshotFile "encode_encrypted_state" "normal state is sealed before writing"
Assert-SourceText $EncryptedSnapshotFile "decode_encrypted_state" "normal state is opened with authentication"
Assert-SourceText $StorageFile "reject_state_rollback" "local replay rollback guard is enforced"
Assert-SourceText $StorageCodecFile "RustCryptoBackend::aead_seal" "encrypted state uses AEAD sealing"
Assert-SourceText $StorageCodecFile "RustCryptoBackend::aead_open" "encrypted state uses AEAD opening"
Assert-SourceText $StorageCodecFile "parse_state_kdf" "encrypted state reads stored KDF parameters before deriving the state key"
Assert-SourceText $StorageCodecFile "encode_kdf_fields" "encrypted state stores explicit KDF parameters"
Assert-SourceText $KdfCodecFile "scrypt::" "memory-hard scrypt KDF implementation is used"
Assert-SourceText $KdfCodecFile "KDF_ALGORITHM_SCRYPT" "current memory-hard KDF algorithm id"
Assert-SourceText $KdfCodecFile "kdf_log_n" "explicit scrypt log_n parameter is stored"
Assert-SourceText $KdfCodecFile "kdf_salt" "per-record random KDF salt is stored"
Assert-SourceText $IdentityCodecFile "PasswordKdfRecord::new_interactive()?" "identity password records use per-record KDF parameters"
Assert-SourceText $IdentityCodecFile "derive_password_key" "identity seed wrapping uses memory-hard password derivation"
Assert-NoSourceText $StorageCodecFile "hkdf-sha3-256" "encrypted state must not use the cheap KDF profile"
Assert-NoSourceText $StorageCodecFile "hkdf_extract" "encrypted state password key must not use HKDF directly"
Assert-NoSourceText $IdentityCodecFile "sha3_256(password" "identity password tag must not be direct SHA3 over the password"
Assert-NoSourceText $LibFile "STATE_V" "normal local state must not use numbered state constants"

Assert-NoSourceText $StorageFile "load_state_without_password" "state must never open without a state password"
Assert-NoSourceText $StorageFile "state_key: Option" "state encryption must not be optional"
Assert-NoSourceText $StorageFile "state_v1" "current state path must not include plaintext alternate-format helpers"
Assert-NoSourceText $StorageFile "remove_file" "current state path must not delete plaintext files"

$reintroduced = Select-String -Path "crates/hydra-msg/src/*.rs", "crates/hydra-msg/src/codec/*.rs" -Pattern "derive_facade_handshake_material" -ErrorAction SilentlyContinue
if ($reintroduced) {
    $reintroduced | ForEach-Object { Write-Host $_ }
    throw "removed public transcript-only facade helper was reintroduced"
}


Assert-SourceText $LibFile 'CONTACT_CARD_MAGIC: &str = "HYDRA-MSG-CONTACT"' "current minimized contact-card format"
Assert-SourceText $LibFile 'LOBBY_INVITE_MAGIC: &str = "HYDRA-MSG-LOBBY-INVITE"' "current minimized lobby-invite format"
Assert-SourceText $ContactFile "pub fn create_labeled_contact_card" "explicit labeled contact-card API"
Assert-SourceText $ContactFile "pub fn create_one_time_contact_card" "first-class one-time contact-card API"
Assert-SourceText $ContactFile "identity_record_from_seed(String::new()" "one-time contact cards use empty local label by default"
Assert-SourceText $ContactCodecFile "pub(crate) fn encode_contact_card(" "current contact-card encoder exists"
Assert-SourceText $ContactCodecFile "public_key:" "contact cards carry public verification key"
Assert-NoSourceText $ContactCodecFile "id:{}" "default contact cards must not encode contact id as a field"
Assert-NoSourceText $ContactCodecFile "safety:{}" "default contact cards must not encode safety code as a field"
Assert-SourceText $LobbyFile "pub fn create_labeled_lobby_invite" "explicit labeled lobby-invite API"
Assert-SourceText $LobbyFile "pub fn create_lobby_member_invite" "explicit member-list lobby-invite API"
Assert-SourceText $LobbyFile "pub fn create_one_time_lobby_invite" "first-class one-time lobby-invite API"
Assert-SourceText $LobbyDeliveryFile "let routing_hint = HydraLobbyRoutingHint::from_bytes(random_array::<32>()?)" "lobby routing hints are randomized per encrypted copy"
Assert-SourceText $LobbyRoutingFile "pub struct HydraLobbyRoutingHint" "opaque lobby routing hint type"
Assert-SourceText $LobbyRoutingFile "pub const fn routing_hint(&self) -> HydraLobbyRoutingHint" "lobby envelopes expose randomized carrier routing hints"
Assert-SourceText $LobbyRoutingFile "not anonymous routing" "direct recipient hint privacy boundary is documented in code"
Assert-SourceText $LobbyCodecFile "include_label: bool" "lobby invite label exposure is explicit"
Assert-SourceText $LobbyCodecFile "members: Option<&[ContactId]>" "lobby invite member exposure is explicit"
Assert-NoSourceText $LobbyCodecFile "placeholder invite" "lobby invite current decoder must not include placeholder alternate-format handling"

Assert-SourceText $LibFile 'AUTH_TOKEN_MAGIC: &str = "HYDRA-MSG-AUTH-TOKEN"' "current anonymous authorization token format"
Assert-SourceText $LibFile "anonymous_auth_secret: SecretBytes<32>" "anonymous auth issuer secret is state-owned, not contact-owned"
Assert-SourceText $LibFile "anonymous_auth_spent: Vec<HydraAnonymousAuthNullifier>" "spent anonymous auth nullifiers are tracked"
Assert-SourceText $AuthFile "pub fn issue_anonymous_auth_token" "anonymous auth token issuance API"
Assert-SourceText $AuthFile "pub fn accept_anonymous_auth_token" "anonymous auth token acceptance API"
Assert-SourceText $AuthFile "pub fn revoke_anonymous_auth_token" "anonymous auth token revocation API"
Assert-SourceText $AuthFile "reject_expired_policy" "anonymous auth expiry is checked"
Assert-SourceText $AuthFile "reject_spent_anonymous_auth_nullifier" "anonymous auth replay/double-spend is rejected"
Assert-SourceText $AuthCodecFile "RustCryptoBackend::hmac_sha3_256" "anonymous auth tokens are issuer-secret authenticated"
Assert-SourceText $AuthCodecFile "HYDRA-MSG/facade/anonymous-auth/nullifier" "anonymous auth nullifiers are domain-separated"
Assert-SourceText $SnapshotFile "anonymous_auth_secret" "anonymous auth issuer secret is stored inside encrypted state snapshot"
Assert-SourceText $SnapshotFile "anonymous_auth_spent" "anonymous auth spent nullifiers are stored inside encrypted state snapshot"
Assert-SourceText $AuthTestsFile "assert_ne!(token_a.as_bytes(), token_b.as_bytes())" "same policy issues unlinkable fresh tokens"
Assert-SourceText $AuthTestsFile "anonymous_auth_token_from_other_issuer_is_not_valid" "tokens from other issuers are rejected"
Assert-NoSourceText $AuthCodecFile "contact_id" "anonymous auth token codec must not encode contact ids"
Assert-NoSourceText $AuthCodecFile "identity_id" "anonymous auth token codec must not encode identity ids"
Assert-NoSourceText $AuthCodecFile "session_id" "anonymous auth token codec must not encode session ids"

$versionTagSearchPaths = @(
    "crates/hydra-msg",
    "examples/hydra-gui/hydra-app",
    "examples/hydra-gui/hydra-app-core",
    "README.md",
    "crates/hydra-msg/README.md",
    "docs/spec/public-developer-api.md",
    "docs/impl/message-flow",
    "docs/validation/benchmark-results.md"
)
$versionTagFiles = @()
foreach ($searchPath in $versionTagSearchPaths) {
    if (Test-Path $searchPath -PathType Container) {
        $versionTagFiles += Get-ChildItem -Path $searchPath -Recurse -File | ForEach-Object { $_.FullName }
    } elseif (Test-Path $searchPath -PathType Leaf) {
        $versionTagFiles += (Resolve-Path $searchPath).Path
    }
}
$versionTagMatches = Select-String -Path $versionTagFiles -Pattern "HYDRA-MSG-[A-Z0-9-]*-V[0-9]|state-v[0-9]|scrypt-v[0-9]|hydra-msg-[a-z0-9-]*-v[0-9]|/v[0-9]" -ErrorAction SilentlyContinue
if ($versionTagMatches) {
    $versionTagMatches | ForEach-Object { Write-Host $_ }
    throw "facade/app format labels must not carry version tags"
}

Write-Host "privacy invariant checks passed" -ForegroundColor Green
