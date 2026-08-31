# Windows-only parser preflight for repository PowerShell QA/helper scripts.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ParseFailures = @()
$Scripts = Get-ChildItem -Path "qa", "scripts" -Filter "*.ps1" -Recurse -File -ErrorAction SilentlyContinue
foreach ($Script in $Scripts) {
    $Bytes = [System.IO.File]::ReadAllBytes($Script.FullName)
    if ($Bytes | Where-Object { $_ -gt 127 } | Select-Object -First 1) {
        $ParseFailures += "$($Script.FullName): non-ASCII PowerShell source is not permitted; keep Windows PowerShell 5.1 scripts ASCII-safe"
        continue
    }
    $Tokens = $null
    $Errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Script.FullName, [ref]$Tokens, [ref]$Errors)
    foreach ($ParseError in $Errors) {
        $ParseFailures += "$($Script.FullName):$($ParseError.Extent.StartLineNumber): $($ParseError.Message)"
    }
}
if ($ParseFailures.Count -ne 0) {
    $ParseFailures | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    throw "PowerShell syntax preflight failed."
}
