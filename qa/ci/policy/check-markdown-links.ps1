# HYDRA-MSG local Markdown link resolver.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot
Write-Host "HYDRA-MSG repo root: $RepoRoot"

$roots = @("README.md", "docs", "qa", "crates", "examples")
$markdownFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
foreach ($root in $roots) {
    if (!(Test-Path $root)) { continue }
    $item = Get-Item $root
    if ($item.PSIsContainer) {
        Get-ChildItem $item.FullName -Recurse -File -Filter *.md |
            Where-Object { $_.FullName -notmatch "[\/]target[\/]" -and $_.FullName -notmatch "[\/]\.git[\/]" -and $_.FullName -notmatch "[\/]node_modules[\/]" -and $_.FullName -notmatch "[\/]test-results[\/]" -and $_.FullName -notmatch "[\/]playwright-report[\/]" -and $_.FullName -notmatch "(^|[\/])examples[\/][^\/]+[\/]web[\/]pkg[\/]" } |
            ForEach-Object { $markdownFiles.Add($_) }
    } else {
        $markdownFiles.Add($item)
    }
}

$pattern = '\[[^\]]+\]\(([^)]*)\)'
$failure = $false

foreach ($file in $markdownFiles | Sort-Object FullName -Unique) {
    $content = Get-Content $file.FullName -Raw
    foreach ($match in [regex]::Matches($content, $pattern)) {
        $target = $match.Groups[1].Value.Trim()
        $target = $target -replace '\s+"[^"]*"$', ''
        $target = $target -replace "\s+'[^']*'$", ''

        if ([string]::IsNullOrWhiteSpace($target) -or $target.StartsWith("#") -or $target.StartsWith("http://") -or $target.StartsWith("https://") -or $target.StartsWith("mailto:") -or $target.StartsWith("tel:")) {
            continue
        }

        $target = ($target -split '#', 2)[0]
        $target = ($target -split '\?', 2)[0]
        if ([string]::IsNullOrWhiteSpace($target)) { continue }

        if ([IO.Path]::IsPathRooted($target)) {
            $resolved = Join-Path $RepoRoot ($target.TrimStart('/', '\'))
        } else {
            $resolved = Join-Path $file.DirectoryName $target
        }

        if (!(Test-Path $resolved)) {
            Write-Host "unresolved Markdown link: $($file.FullName) -> $target" -ForegroundColor Red
            $failure = $true
        }
    }
}

if ($failure) {
    throw "Markdown link check failed"
}

Write-Host "Markdown link checks passed." -ForegroundColor Green
