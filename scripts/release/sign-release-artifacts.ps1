param(
    [Parameter(Mandatory = $true)] [string] $Version,
    [string] $GpgKeyId
)

$ErrorActionPreference = "Stop"
$ReleaseDir = Join-Path "release-artifacts" $Version
if (-not (Test-Path $ReleaseDir)) { throw "missing release directory: $ReleaseDir" }
if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) { throw "missing required signing tool: gpg" }

Push-Location $ReleaseDir
Get-ChildItem -Recurse -File |
    Where-Object { $_.Name -notin @("SHA256SUMS.txt", "SHA256SUMS.txt.asc") -and $_.Extension -ne ".asc" } |
    Sort-Object FullName |
    ForEach-Object {
        $relative = Resolve-Path -Relative $_.FullName
        $relative = $relative.TrimStart('.', '\', '/') -replace '\\','/'
        "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower())  $relative"
    } | Set-Content -Encoding ascii SHA256SUMS.txt
Pop-Location

$args = @("--armor", "--detach-sign", "--output", "$ReleaseDir/SHA256SUMS.txt.asc")
if ($GpgKeyId) { $args += @("--local-user", $GpgKeyId) }
$args += "$ReleaseDir/SHA256SUMS.txt"
& gpg @args
Write-Host "Signed checksum manifest: $ReleaseDir/SHA256SUMS.txt.asc"
