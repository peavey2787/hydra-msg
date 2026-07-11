# HYDRA-MSG persistence public API shape checks.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$WasmFile = "crates/hydra-msg-wasm/src/lib.rs"
$WasmDocs = @(
    "crates/hydra-msg-wasm/README.md",
    "docs/impl/wasm-javascript-bindings.md",
    "docs/spec/public-developer-api.md"
)
$ProductRoots = @(
    "crates/hydra-msg-wasm",
    "examples",
    "docs/spec",
    "docs/impl",
    "docs/validation",
    "README.md"
)

function Assert-SourceText {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $content = Get-Content $File -Raw
    if (!$content.Contains($Text)) {
        throw "persistence API shape missing: $Description; expected text '$Text' in $File"
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
        throw "persistence API shape forbidden pattern found: $Description; forbidden text '$Text' in $File"
    }
}

function Get-SearchFiles {
    param([Parameter(Mandatory = $true)][string[]]$Roots)
    foreach ($root in $Roots) {
        if (Test-Path $root -PathType Leaf) {
            Get-Item $root
        } elseif (Test-Path $root -PathType Container) {
            Get-ChildItem $root -Recurse -File |
                Where-Object {
                    $_.FullName -notmatch '[\\/]target[\\/]' -and
                    $_.FullName -notmatch '[\\/]\.git[\\/]'
                }
        }
    }
}

if (!(Test-Path $WasmFile)) {
    throw "missing WASM binding file: $WasmFile"
}

Assert-SourceText $WasmFile "js_name = openPersistent" "explicit async durable browser open"
Assert-SourceText $WasmFile "pub async fn open_persistent" "async persistent open implementation"
Assert-SourceText $WasmFile "js_name = openEphemeral" "explicit in-memory browser open"
Assert-SourceText $WasmFile "pub fn open_ephemeral" "sync ephemeral open implementation"
Assert-SourceText $WasmFile "js_name = flush" "explicit durable browser commit API"
Assert-SourceText $WasmFile "pub async fn flush" "async flush implementation"
Assert-SourceText $WasmFile "js_name = deletePersistent" "explicit persistent reset API"
Assert-SourceText $WasmFile "js_name = verifyBackup" "passworded backup verification binding"
Assert-SourceText $WasmFile "verify_backup(bytes, password)" "WASM backup verification authenticates with password"
Assert-SourceText $WasmFile "dirty: bool" "explicit dirty-state tracking"
Assert-SourceText $WasmFile "self.mark_dirty();" "mutating calls mark dirty instead of pretending synchronous IndexedDB durability"

Assert-NoSourceText $WasmFile "js_name = openDefault" "durable-looking WASM default open alias"
Assert-NoSourceText $WasmFile "pub fn open_default" "durable-looking WASM default open implementation"
Assert-NoSourceText $WasmFile "js_name = open)]" "ambiguous WASM open alias"

Assert-SourceText $WasmFile "js_name = setPacketSize" "simple WASM packet sizing control"
Assert-NoSourceText $WasmFile "js_name = setMinEnvelopeSize" "removed WASM min envelope sizing control"
Assert-NoSourceText $WasmFile "js_name = setMaxEnvelopeSize" "removed WASM max envelope sizing control"
Assert-NoSourceText $WasmFile "js_name = maxEnvelopeSize" "extra WASM envelope sizing getter"
Assert-NoSourceText $WasmFile "js_name = effectiveMaxEnvelopeSize" "extra WASM effective envelope getter"
Assert-NoSourceText $WasmFile "js_name = minSupportedMaxEnvelopeSize" "extra WASM envelope lower-bound getter"
Assert-NoSourceText $WasmFile "js_name = protocolMaxEnvelopeSize" "extra WASM protocol max getter"
Assert-NoSourceText $WasmFile "js_name = sendEnvelopes" "extra WASM batch send API"
Assert-NoSourceText $WasmFile "js_name = sendTextEnvelopes" "extra WASM batch text send API"
Assert-NoSourceText $WasmFile "js_name = receiveEnvelopes" "extra WASM batch receive API"
Assert-NoSourceText $WasmFile "js_name = sendLobbyEnvelopes" "extra WASM lobby batch send API"
Assert-NoSourceText $WasmFile "js_name = receiveLobbyEnvelopes" "extra WASM lobby batch receive API"
Assert-NoSourceText $WasmFile "js_name = sendTo" "extra WASM transport callback send API"
Assert-NoSourceText $WasmFile "js_name = sendTextTo" "extra WASM transport callback text send API"
Assert-NoSourceText $WasmFile "js_name = receiveNext" "extra WASM incremental receive API"
Assert-NoSourceText $WasmFile "js_name = receiveLobbyNext" "extra WASM incremental lobby receive API"

$overexposedEnvelopeMatches = Get-SearchFiles @("crates", "docs/spec", "docs/impl", "docs/validation", "README.md") |
    Select-String -Pattern 'send_envelopes|receive_envelopes|send_lobby_envelopes|receive_lobby_envelopes|sendEnvelopes|sendTextEnvelopes|receiveEnvelopes|sendLobbyEnvelopes|receiveLobbyEnvelopes|send_to\(|receive_next\(|send_lobby_to\(|receive_lobby_next\(|sendTo|sendTextTo|receiveNext|receiveLobbyNext|minSupportedMaxEnvelopeSize|protocolMaxEnvelopeSize|effectiveMaxEnvelopeSize|maxEnvelopeSize|setMinEnvelopeSize|setMaxEnvelopeSize|set_min_envelope_size|set_max_envelope_size|send_batch|sendBatch|send_packets|sendPackets' -ErrorAction SilentlyContinue
if ($overexposedEnvelopeMatches) {
    $overexposedEnvelopeMatches | ForEach-Object { Write-Host $_ }
    throw "overexposed envelope sizing, batching, or packet-fragment API reference found"
}

$durableLookingMatches = Get-SearchFiles $ProductRoots | Select-String -Pattern 'WasmHydra\.open(Default)?\s*\(' -ErrorAction SilentlyContinue
if ($durableLookingMatches) {
    $durableLookingMatches | ForEach-Object { Write-Host $_ }
    throw "durable-looking WASM open/openDefault reference found in product source/docs"
}

foreach ($doc in $WasmDocs) {
    Assert-SourceText $doc "openPersistent" "persistent WASM API documentation"
    Assert-SourceText $doc "openEphemeral" "ephemeral WASM API documentation"
    Assert-SourceText $doc "flush" "explicit WASM flush documentation"
    Assert-SourceText $doc "no ambiguous" "documentation calls out removed ambiguous WASM open aliases"
}

$staleVerifyMatches = Get-SearchFiles @("crates", "docs/spec", "docs/impl", "docs/validation", "README.md") |
    Select-String -Pattern 'verify_backup\([^,)]*\)|verifyBackup\([^,)]*\)' -ErrorAction SilentlyContinue
if ($staleVerifyMatches) {
    $staleVerifyMatches | ForEach-Object { Write-Host $_ }
    throw "stale one-argument backup verification reference found"
}

$hiddenHookMatches = Get-SearchFiles @("README.md", "docs/spec", "docs/impl", "docs/validation", "crates/hydra-msg-wasm/README.md") |
    Select-String -Pattern 'open_with_encrypted_state_snapshot|flush_encrypted_state_snapshot' -ErrorAction SilentlyContinue
if ($hiddenHookMatches) {
    $hiddenHookMatches | ForEach-Object { Write-Host $_ }
    throw "hidden encrypted snapshot hooks leaked into public docs"
}

$docHiddenMatches = Get-SearchFiles @("crates/hydra-msg/src") |
    Select-String -Pattern '#\[doc\(hidden\)\]' -ErrorAction SilentlyContinue
if ($docHiddenMatches) {
    $docHiddenMatches | ForEach-Object { Write-Host $_ }
    throw "doc-hidden APIs are forbidden in the hydra-msg v1 facade"
}

Write-Host "persistence API shape checks passed" -ForegroundColor Green
