[CmdletBinding()]
param(
    [switch]$SkipWasm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}


$CheckedManifests = @(
    "examples/attachment_roundtrip/Cargo.toml",
    "examples/contact_card/Cargo.toml",
    "examples/handshake_roundtrip/Cargo.toml",
    "examples/hydra-app-core/Cargo.toml",
    "examples/hydra-app/Cargo.toml",
    "examples/lobby_roundtrip/Cargo.toml",
    "examples/manual_file_carrier/Cargo.toml",
    "examples/mobile_perf_web/Cargo.toml",
    "examples/webrtc_manual_carrier/Cargo.toml"
)

function Assert-AllExampleManifestsCovered {
    $covered = @{}
    foreach ($manifest in $CheckedManifests) {
        $covered[$manifest] = $true
    }

    $found = Get-ChildItem -Path examples -Filter Cargo.toml -Recurse | ForEach-Object {
        $relative = Resolve-Path -Relative $_.FullName
        $relative = $relative -replace '^\.[/\\]', ''
        $relative.Replace('\', '/')
    }
    foreach ($manifest in $found) {
        if (!$covered.ContainsKey($manifest)) {
            throw "Example manifest is not covered by check-examples.ps1: $manifest"
        }
    }
}

Assert-AllExampleManifestsCovered

function Invoke-WebHostStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [string]$Address,
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    $process = Start-Process `
        -FilePath "cargo" `
        -ArgumentList @("run", "--manifest-path", $ManifestPath, "--", $Address) `
        -PassThru `
        -NoNewWindow
    try {
        $deadline = (Get-Date).AddSeconds(60)
        $lastError = $null
        while ((Get-Date) -lt $deadline) {
            try {
                $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
                if ($response.StatusCode -eq 200) {
                    return
                }
                $lastError = "unexpected HTTP status $($response.StatusCode)"
            } catch {
                $lastError = $_.Exception.Message
                Start-Sleep -Milliseconds 500
            }
        }
        throw "web host did not respond at ${Url}: ${lastError}"
    } finally {
        if (!$process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        $process.WaitForExit()
    }
}

Invoke-Step "handshake_roundtrip example package" {
    cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
}
Invoke-Step "contact_card example package" {
    cargo run --manifest-path examples/contact_card/Cargo.toml
}
Invoke-Step "attachment_roundtrip example package" {
    cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
}
Invoke-Step "lobby_roundtrip example package" {
    cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
}
Invoke-Step "manual_file_carrier example package" {
    cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
}

Invoke-Step "hydra-app-core package check" {
    cargo check --manifest-path examples/hydra-app-core/Cargo.toml --all-targets --all-features
}
Invoke-Step "hydra-app-core create_identity example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example create_identity
}
Invoke-Step "hydra-app-core start_session_send_receive example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --features test-support --example start_session_send_receive
}
Invoke-Step "hydra-app-core group_create_join example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example group_create_join
}
Invoke-Step "hydra-app-core identity_store example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example identity_store
}
Invoke-Step "hydra-app-core message_store example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example message_store
}
Invoke-Step "hydra-app-core transport_relay example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example transport_relay
}
Invoke-Step "hydra-app-core recovery_export_import example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example recovery_export_import
}
Invoke-Step "hydra-app-core device_linking example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example device_linking
}
Invoke-Step "hydra-app-core attachment_handling example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example attachment_handling
}
Invoke-Step "hydra-app-core abuse_failure_tests example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example abuse_failure_tests
}
Invoke-Step "hydra-app-core live_state_store example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --features test-support --example live_state_store
}
Invoke-Step "hydra-app-core signed_backup_history example" {
    cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example signed_backup_history
}

Invoke-Step "hydra-app example package" {
    cargo run --manifest-path examples/hydra-app/Cargo.toml -- help
}

Invoke-Step "mobile_perf_web host compile" {
    cargo check --manifest-path examples/mobile_perf_web/Cargo.toml
}
Invoke-Step "webrtc_manual_carrier host compile" {
    cargo check --manifest-path examples/webrtc_manual_carrier/Cargo.toml
}
Invoke-WebHostStep `
    -Name "mobile_perf_web example package smoke run" `
    -ManifestPath "examples/mobile_perf_web/Cargo.toml" `
    -Address "127.0.0.1:18788" `
    -Url "http://127.0.0.1:18788/"
Invoke-WebHostStep `
    -Name "webrtc_manual_carrier example package smoke run" `
    -ManifestPath "examples/webrtc_manual_carrier/Cargo.toml" `
    -Address "127.0.0.1:18789" `
    -Url "http://127.0.0.1:18789/"

if (!$SkipWasm) {
    if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
        Write-Host "wasm-pack is required for browser example packages." -ForegroundColor Red
        Write-Host "Install with: cargo install wasm-pack --locked" -ForegroundColor Yellow
        exit 1
    }

    Invoke-Step "mobile_perf_web WASM package" {
        examples\mobile_perf_web\scripts\build-wasm.ps1
    }
    Invoke-Step "webrtc_manual_carrier WASM package" {
        examples\webrtc_manual_carrier\scripts\build-wasm.ps1
    }
} else {
    Write-Host "WASM browser package checks skipped by -SkipWasm." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "HYDRA-MSG example checks passed." -ForegroundColor Green
