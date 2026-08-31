# HYDRA-MSG cyclomatic-complexity gate.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot
$OutDir = "target/qa-tools/complexity"
$Tool = Join-Path $OutDir "check-complexity.exe"
$ParserTests = Join-Path $OutDir "rust-source-tests.exe"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
& rustc --edition=2021 -D warnings --test qa/quality/rust_source.rs -o $ParserTests
if ($LASTEXITCODE -ne 0) { throw "Rust source quality parser tests failed to compile" }
& $ParserTests
if ($LASTEXITCODE -ne 0) { throw "Rust source quality parser tests failed" }
& rustc --edition=2021 -D warnings qa/quality/check_complexity.rs -o $Tool
if ($LASTEXITCODE -ne 0) { throw "cyclomatic complexity checker failed to compile" }
& $Tool
if ($LASTEXITCODE -ne 0) { throw "cyclomatic complexity CC <= 12 gate failed" }
