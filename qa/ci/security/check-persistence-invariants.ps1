# Thin Windows adapter. Shared persistence policy lives in check_persistence_invariants.py.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$Python3 = Get-Command python3 -ErrorAction SilentlyContinue
if ($Python3) {
    & $Python3.Source "qa\ci\security\check_persistence_invariants.py"
    exit $LASTEXITCODE
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if ($Python) {
    & $Python.Source "qa\ci\security\check_persistence_invariants.py"
    exit $LASTEXITCODE
}

$Py = Get-Command py -ErrorAction SilentlyContinue
if ($Py) {
    & $Py.Source -3 "qa\ci\security\check_persistence_invariants.py"
    exit $LASTEXITCODE
}

throw "HYDRA persistence invariant policy requires Python 3 on PATH."
