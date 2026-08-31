# Native Windows adapter for the shared mobile/browser persistence benchmark checks.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

& python ".\qa\ci\reliability\check_mobile_perf_web.py"
if ($LASTEXITCODE -ne 0) {
    throw "mobile perf web checks failed with exit code $LASTEXITCODE"
}
