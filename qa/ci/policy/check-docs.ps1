Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

python3 .\qa\ci\policy\check_docs.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

.\qa\ci\policy\check-markdown-links.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "docs checks passed" -ForegroundColor Green
