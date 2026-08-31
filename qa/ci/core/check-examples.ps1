[CmdletBinding()]
param(
    [switch]$SkipWasm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
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
    # PowerShell-only steps may not set the native-process automatic variable at all,
    # especially when this runner starts at a resumed static gate under StrictMode.
    # Reset it for each step; native commands still overwrite it with their exit code.
    $global:LASTEXITCODE = 0
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}


Invoke-Step "shared example static policy" {
    python qa/ci/core/check_examples_policy.py
}

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

if ($env:HYDRA_WORKSPACE_TESTS_ALREADY_RAN -eq "1") {
    Write-Host "Workspace --all-targets tests already compiled/tested example targets; skipping duplicate compile/test-only example invocations." -ForegroundColor DarkGray
} else {
    Invoke-Step "HYDRA GUI host compile" {
        cargo check --manifest-path examples/hydra-gui/Cargo.toml --all-targets
    }
    Invoke-Step "HYDRA GUI tests" {
        cargo test --manifest-path examples/hydra-gui/Cargo.toml
    }
    Invoke-Step "mobile_perf_web host compile" {
        cargo check --manifest-path examples/mobile_perf_web/Cargo.toml
    }
    Invoke-Step "webrtc_manual_carrier host compile" {
        cargo check --manifest-path examples/webrtc_manual_carrier/Cargo.toml
    }
    Invoke-Step "stego_lan_chat host compile" {
        cargo check --manifest-path examples/stego_lan_chat/Cargo.toml
    }
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
Invoke-WebHostStep `
    -Name "stego_lan_chat example package smoke run" `
    -ManifestPath "examples/stego_lan_chat/Cargo.toml" `
    -Address "127.0.0.1:18790" `
    -Url "http://127.0.0.1:18790/"
Invoke-WebHostStep `
    -Name "HYDRA GUI example package smoke run" `
    -ManifestPath "examples/hydra-gui/Cargo.toml" `
    -Address "127.0.0.1:18791" `
    -Url "http://127.0.0.1:18791/"

if (!$SkipWasm) {
    if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
        Write-Host "wasm-pack is required for browser example packages." -ForegroundColor Red
        Write-Host "Install with: cargo install wasm-pack --locked" -ForegroundColor Yellow
        Write-Host "or run: .\scripts\setup-dev-env.ps1" -ForegroundColor Yellow
        exit 1
    }

    Invoke-Step "mobile_perf_web WASM package" {
        examples\mobile_perf_web\scripts\build-wasm.ps1
    }
    Invoke-Step "webrtc_manual_carrier WASM package" {
        examples\webrtc_manual_carrier\scripts\build-wasm.ps1
    }
    Invoke-Step "stego_lan_chat WASM package" {
        examples\stego_lan_chat\scripts\build-wasm.ps1
    }
    Invoke-Step "HYDRA GUI WASM package" {
        examples\hydra-gui\scripts\build-wasm.ps1
    }
} else {
    Write-Host "WASM browser package checks skipped by -SkipWasm." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "HYDRA-MSG example checks passed." -ForegroundColor Green
