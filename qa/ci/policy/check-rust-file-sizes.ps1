# Thin Windows adapter. Shared source-size policy lives in check_rust_file_sizes.py.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$Python3 = Get-Command python3 -ErrorAction SilentlyContinue
if ($Python3) {
    & $Python3.Source "qa\ci\policy\check_rust_file_sizes.py"
    exit $LASTEXITCODE
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if ($Python) {
    & $Python.Source "qa\ci\policy\check_rust_file_sizes.py"
    exit $LASTEXITCODE
}

$Py = Get-Command py -ErrorAction SilentlyContinue
if ($Py) {
    & $Py.Source -3 "qa\ci\policy\check_rust_file_sizes.py"
    exit $LASTEXITCODE
}

throw "HYDRA Rust source-size policy requires Python 3 on PATH."
