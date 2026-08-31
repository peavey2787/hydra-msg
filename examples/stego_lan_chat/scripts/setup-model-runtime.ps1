$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path "$PSScriptRoot\..\..\.."
$RuntimeDir = Join-Path $RepoRoot "target\stego-model-runtime"
$RuntimePython = Join-Path $RuntimeDir "Scripts\python.exe"

if (-not (Test-Path $RuntimePython)) {
    python -m venv $RuntimeDir
    if ($LASTEXITCODE -ne 0) { throw "could not create the Python virtual environment" }
}

& $RuntimePython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
& $RuntimePython -m pip install "torch>=2.4,<3" "transformers>=4.45,<6" "huggingface-hub>=0.25,<2" "safetensors>=0.4,<1"
if ($LASTEXITCODE -ne 0) { throw "model runtime installation failed" }

Write-Host "Model runtime ready at $RuntimePython" -ForegroundColor Green
Write-Host "Model weights are downloaded when you select a model in the browser demo."
