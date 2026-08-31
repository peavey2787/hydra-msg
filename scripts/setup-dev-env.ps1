$ErrorActionPreference = "Stop"

$Banner = @'

 _   _ __   ______  ____      _
| | | |\ \ / /  _ \|  _ \    / \
| |_| | \ V /| | | | |_) |  / _ \
|  _  |  | | | |_| |  _ <  / ___ \
|_| |_|  |_| |____/|_| \_\/_/   \_\

        ASIC-grade dev environment bootstrap
'@
Write-Host $Banner

function Assert-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "missing required command: $Name. Install Rust with rustup first if cargo/rustup is missing: https://rustup.rs/"
    }
}

function Install-CargoCrate($Crate) {
    $installed = cargo install --list | Select-String -Pattern "^$Crate v" -Quiet
    if ($installed) {
        Write-Host "[OK] $Crate already installed"
    } else {
        Write-Host "==> installing $Crate"
        cargo install $Crate --locked
    }
}

Assert-Command rustup
Assert-Command cargo

Write-Host "`n==> Rust stable components"
rustup component add rustfmt clippy
rustup target add wasm32-unknown-unknown

Write-Host "`n==> Rust nightly components for Miri/sanitizer/branch-coverage/fuzz gates"
if ($env:HYDRA_SKIP_NIGHTLY -eq "1") {
    Write-Host "Skipping nightly setup because HYDRA_SKIP_NIGHTLY=1"
} else {
    rustup toolchain install nightly
    rustup +nightly component add miri rust-src llvm-tools-preview
}

Write-Host "`n==> Cargo QA tools"
Install-CargoCrate cargo-audit
Install-CargoCrate cargo-deny
Install-CargoCrate wasm-pack
Install-CargoCrate cargo-llvm-cov
Install-CargoCrate cargo-mutants
Install-CargoCrate cargo-fuzz

Write-Host "`n==> Host tool reminders"
if (Get-Command node -ErrorAction SilentlyContinue) {
    Write-Host "[OK] node found: $(node --version)"
} else {
    Write-Host "[WARN] node is not installed. Browser/example checks use node --check. Install Node.js 20+ or newer."
}
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "[OK] npm found: $(npm --version)"
    if ($env:HYDRA_SKIP_PLAYWRIGHT -eq "1") {
        Write-Host "Skipping Playwright install because HYDRA_SKIP_PLAYWRIGHT=1"
    } else {
        Write-Host "==> installing Playwright browser test dependencies and browser binaries"
        Push-Location "qa/browser/playwright"
        npm ci
        npm run install:browsers
        Pop-Location
    }
} else {
    Write-Host "[WARN] npm is not installed. Real-browser Playwright evidence requires npm."
}
if (Get-Command python3 -ErrorAction SilentlyContinue) {
    Write-Host "[OK] python3 found: $(python3 --version)"
} else {
    Write-Host "[WARN] python3 is not installed. Release SBOM generation, interop fixture checks, and web-host smoke tests require python3."
}
if (Get-Command gpg -ErrorAction SilentlyContinue) {
    $GpgVersion = (& gpg --version | Select-Object -First 1)
    Write-Host "[OK] gpg found: $GpgVersion"
} else {
    Write-Host "[WARN] gpg is not installed. Release signing requires gpg for signed tags and checksum signatures."
}

$CompletionMessage = @'

HYDRA dev environment setup complete.

Suggested first validation run:
  .\qa\ci\check-all.ps1

Optional release-candidate evidence:
  $env:HYDRA_RUN_COVERAGE=1; .\qa\ci\quality\check-coverage.ps1
  $env:HYDRA_RUN_MUTATION=1; .\qa\ci\quality\check-mutation.ps1
  $env:HYDRA_RUN_MIRI=1; .\qa\ci\reliability\check-memory-safety.ps1
  $env:HYDRA_RUN_SANITIZERS=1; .\qa\ci\reliability\check-memory-safety.ps1
  $env:HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1; .\qa\ci\fuzz\check-fuzz.ps1

Release package/signing helpers:
  .\scripts\release\create-signed-tag.ps1 v0.1.0
  .\scripts\release\create-release-package.ps1 v0.1.0
  .\scripts\release\sign-release-artifacts.ps1 v0.1.0
  .\scripts\release\verify-release-artifacts.ps1 v0.1.0
'@
Write-Host $CompletionMessage
