# HYDRA-MSG Rust source-size ownership check.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot
Write-Host "HYDRA-MSG repo root: $RepoRoot"

$Threshold = 400
$ScanRoots = @("crates/hydra-group/src", "crates/hydra-msg/src")
$AllowList = "qa/ci/rust-size-allowlist.txt"

if (!(Test-Path $AllowList)) {
    throw "missing Rust source-size allow-list: $AllowList"
}

function Get-RelativeRepoPath {
    param([Parameter(Mandatory = $true)][string]$FullName)
    $root = (Resolve-Path $RepoRoot).Path.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $relative = $FullName.Substring($root.Length + 1)
    $relative.Replace('\', '/')
}

function Get-LineCount {
    param([Parameter(Mandatory = $true)][string]$Path)
    (Get-Content -Path $Path | Measure-Object -Line).Lines
}

$largeFiles = @{}
foreach ($ScanRoot in $ScanRoots) {
    Get-ChildItem $ScanRoot -Recurse -File -Filter *.rs |
        Where-Object { $_.FullName -notmatch "[\\/]target[\\/]" } |
        ForEach-Object {
            $relative = Get-RelativeRepoPath $_.FullName
            $lines = Get-LineCount $relative
            if ($lines -gt $Threshold) {
                $largeFiles[$relative] = $lines
            }
        }
}

$allowedPaths = @{}
$failure = $false

foreach ($entry in Get-Content $AllowList) {
    if ([string]::IsNullOrWhiteSpace($entry) -or $entry.TrimStart().StartsWith("#")) {
        continue
    }

    $parts = $entry -split '\|', 3
    if ($parts.Count -ne 3 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1]) -or [string]::IsNullOrWhiteSpace($parts[2])) {
        Write-Host "invalid allow-list entry: $entry" -ForegroundColor Red
        $failure = $true
        continue
    }

    $path = $parts[0]
    $maxText = $parts[1]
    $reason = $parts[2]
    $maxLines = 0
    if (![int]::TryParse($maxText, [ref]$maxLines)) {
        Write-Host "invalid max line count in allow-list entry: $entry" -ForegroundColor Red
        $failure = $true
        continue
    }

    if (!(Test-Path $path)) {
        Write-Host "allow-list entry points to missing file: $path" -ForegroundColor Red
        $failure = $true
        continue
    }

    $lines = Get-LineCount $path
    if ($lines -le $Threshold) {
        Write-Host "stale allow-list entry no longer exceeds $Threshold lines: $path ($lines lines)" -ForegroundColor Red
        $failure = $true
    }
    if ($lines -gt $maxLines) {
        Write-Host "allow-listed file exceeded documented max: $path ($lines > $maxLines lines)" -ForegroundColor Red
        $failure = $true
    }

    $allowedPaths[$path] = $true
}

foreach ($item in $largeFiles.GetEnumerator()) {
    if (!$allowedPaths.ContainsKey($item.Key)) {
        Write-Host "Rust file exceeds $Threshold lines without documented ownership exception: $($item.Key) ($($item.Value) lines)" -ForegroundColor Red
        $failure = $true
    }
}

if ($failure) {
    throw "Rust source-size ownership check failed"
}

Write-Host "Rust source-size ownership checks passed." -ForegroundColor Green
