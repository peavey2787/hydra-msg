# Thin Windows adapter. Shared interop policy lives in check_interop.py.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$Python3 = Get-Command python3 -ErrorAction SilentlyContinue
if ($Python3) {
    & $Python3.Source "qa\ci\reliability\check_interop.py"
    exit $LASTEXITCODE
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if ($Python) {
    & $Python.Source "qa\ci\reliability\check_interop.py"
    exit $LASTEXITCODE
}

$Py = Get-Command py -ErrorAction SilentlyContinue
if ($Py) {
    & $Py.Source -3 "qa\ci\reliability\check_interop.py"
    exit $LASTEXITCODE
}

throw "HYDRA interop harness requires Python 3 on PATH."
