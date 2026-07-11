param(
    [Parameter(Mandatory = $true)] [string] $Version
)

$ErrorActionPreference = "Stop"
$ReleaseDir = Join-Path "release-artifacts" $Version
if (-not (Test-Path $ReleaseDir)) { throw "missing release directory: $ReleaseDir" }
if (-not (Test-Path "$ReleaseDir/SHA256SUMS.txt.asc")) { throw "missing signature: $ReleaseDir/SHA256SUMS.txt.asc" }

Push-Location $ReleaseDir
Get-Content SHA256SUMS.txt | ForEach-Object {
    if (-not $_.Trim()) { return }
    $parts = $_ -split '\s+', 2
    $expected = $parts[0].ToLower()
    $file = $parts[1]
    $actual = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
    if ($actual -ne $expected) { throw "hash mismatch: $file" }
}
Pop-Location

gpg --verify "$ReleaseDir/SHA256SUMS.txt.asc" "$ReleaseDir/SHA256SUMS.txt"
Write-Host "Release artifacts verified: $ReleaseDir"
