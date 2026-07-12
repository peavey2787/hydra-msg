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
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}


$CheckedManifests = @(
    "examples/attachment_roundtrip/Cargo.toml",
    "examples/contact_card/Cargo.toml",
    "examples/handshake_roundtrip/Cargo.toml",
    "examples/hydra-gui/hydra-app-core/Cargo.toml",
    "examples/hydra-gui/hydra-app/Cargo.toml",
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

function Assert-ReferenceAppSdkBoundary {
    if ((Test-Path "examples/hydra-app") -or (Test-Path "examples/hydra-app-core")) {
        throw "Old hydra-app example paths must not exist outside examples/hydra-gui."
    }

    $referenceFiles = Get-ChildItem -Path @(
        "examples/hydra-gui/hydra-app-core",
        "examples/hydra-gui/hydra-app"
    ) -Recurse -File
    $directProtocolMatches = $referenceFiles | Select-String -Pattern 'hydra-(core|crypto|group|session)|hydra_(core|crypto|group|session)'
    if ($directProtocolMatches) {
        $directProtocolMatches | ForEach-Object { Write-Host $_ }
        throw "Reference app must depend only on the public hydra-msg SDK boundary."
    }

    $removedSurfaceMatches = $referenceFiles | Select-String -Pattern 'ContactTrustStore|IdentityVault|IdentityStore|IdentityUnlockSession|MessageStore|LiveStateStore|ChatShell|AppSession|AppGroup|RecoveryManifest|SignedBackup|TransportApi|DeviceRegistry'
    if ($removedSurfaceMatches) {
        $removedSurfaceMatches | ForEach-Object { Write-Host $_ }
        throw "Removed app-owned protocol/storage implementations must not return."
    }

    $suppressionMatches = $referenceFiles | Select-String -Pattern '#\[allow\((dead_code|deprecated|unused|unused_imports|unused_must_use)'
    if ($suppressionMatches) {
        $suppressionMatches | ForEach-Object { Write-Host $_ }
        throw "Reference app must not suppress dead, deprecated, or unused-code diagnostics."
    }
}

Assert-ReferenceAppSdkBoundary

function Assert-WasmPackageMetadata {
    $manifest = "crates/hydra-msg-wasm/Cargo.toml"
    $license = "crates/hydra-msg-wasm/LICENSE"
    $readme = "crates/hydra-msg-wasm/README.md"

    foreach ($file in @($manifest, $license, $readme)) {
        if (!(Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "WASM package metadata file missing: $file"
        }
    }
    if (!(Select-String -LiteralPath $manifest -SimpleMatch 'description = "WebAssembly and JavaScript bindings' -Quiet)) {
        throw "hydra-msg-wasm package description is missing"
    }
    if (!(Select-String -LiteralPath $manifest -SimpleMatch 'readme = "README.md"' -Quiet)) {
        throw "hydra-msg-wasm package README declaration is missing"
    }
    $rootLicenseHash = (Get-FileHash -Algorithm SHA256 -LiteralPath "LICENSE").Hash
    $wasmLicenseHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $license).Hash
    if ($rootLicenseHash -ne $wasmLicenseHash) {
        throw "hydra-msg-wasm package-local LICENSE must match the repository LICENSE"
    }
}

Assert-WasmPackageMetadata

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
    cargo check --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --all-targets --all-features
}
Invoke-Step "hydra-app-core reference tests" {
    cargo test --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --all-features
}
Invoke-Step "hydra-app-core identity and contacts example" {
    cargo run --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --example identity_contacts
}
Invoke-Step "hydra-app-core direct message example" {
    cargo run --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --example direct_message
}
Invoke-Step "hydra-app-core lobby and backup example" {
    cargo run --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --example lobby_backup
}

Invoke-Step "hydra-app package check" {
    cargo check --manifest-path examples/hydra-gui/hydra-app/Cargo.toml --all-targets
}
Invoke-Step "hydra-app tests" {
    cargo test --manifest-path examples/hydra-gui/hydra-app/Cargo.toml
}
Invoke-Step "hydra-app command model" {
    cargo run --manifest-path examples/hydra-gui/hydra-app/Cargo.toml -- help
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
        Write-Host "or run: .\scripts\setup-dev-env.ps1" -ForegroundColor Yellow
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
