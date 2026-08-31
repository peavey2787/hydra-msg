# Thin Windows adapter. Shared release-governance policy lives in Python.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot
$Python = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command python -ErrorAction SilentlyContinue }
if ($Python) { & $Python.Source "qa\ci\release\check_release_governance.py"; exit $LASTEXITCODE }
$Py = Get-Command py -ErrorAction SilentlyContinue
if ($Py) { & $Py.Source -3 "qa\ci\release\check_release_governance.py"; exit $LASTEXITCODE }
throw "release governance checks require Python 3 on PATH"
