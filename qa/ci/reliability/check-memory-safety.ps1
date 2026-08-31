# Thin Windows adapter for the shared memory-safety release gate.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot
$Python = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { throw "Python 3 is required" }
& $Python "qa\ci\reliability\check_memory_safety.py"
if ($LASTEXITCODE -ne 0) { throw "shared memory-safety gate failed with exit code $LASTEXITCODE" }
