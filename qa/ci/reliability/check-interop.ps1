# HYDRA-MSG cross-runtime interop harness gate.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Require-File($Path) {
    if (-not (Test-Path $Path)) { throw "required interop file missing: $Path" }
}
function Require-Text($Path, $Text) {
    if (-not (Select-String -Path $Path -SimpleMatch $Text -Quiet)) {
        throw "interop invariant missing from ${Path}: $Text"
    }
}

@(
  "qa/fixtures/interop/manifest.sha3-256",
  "qa/tests/interop/Cargo.toml",
  "qa/tests/interop/src/lib.rs",
  "qa/tests/interop/src/candidate_vectors.rs",
  "crates/hydra-msg/src/packet_fragments/tests.rs",
  "qa/fixtures/interop/browser/wasm-fixture-probe.js",
  "docs/validation/evidence/interop-test-harness.md",
  "examples/mobile_perf_web/web/app.js",
  "examples/mobile_perf_web/src/main.rs"
) | ForEach-Object { Require-File $_ }

python3 - <<'PY'
from pathlib import Path
import hashlib
manifest = Path('qa/fixtures/interop/manifest.sha3-256')
for line in manifest.read_text().splitlines():
    if not line.strip():
        continue
    expected, path = line.split(None, 1)
    actual = hashlib.sha3_256(Path(path).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f'interop fixture hash mismatch: {path}: expected {expected}, got {actual}')
PY
if ($LASTEXITCODE -ne 0) { throw "interop manifest verification failed" }

cargo test -p hydra-interop-tests
if ($LASTEXITCODE -ne 0) { throw "hydra-interop-tests failed" }

$CliDir = Join-Path ([System.IO.Path]::GetTempPath()) ("hydra-interop-cli-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $CliDir | Out-Null
try {
    cargo run -p hydra-msg-cli -- generate-id $CliDir state-pw id-pw | Out-Null
    $CliOutput = cargo run -p hydra-msg-cli -- doctor $CliDir state-pw
    if ($CliOutput -notmatch "identities=1") { throw "CLI doctor identity count mismatch" }
    if ($CliOutput -notmatch "contacts=0") { throw "CLI doctor contact count mismatch" }
    if ($CliOutput -notmatch "messages=0") { throw "CLI doctor message count mismatch" }
    if ($CliOutput -notmatch "lobbies=0") { throw "CLI doctor lobby count mismatch" }
} finally {
    Remove-Item -Recurse -Force $CliDir -ErrorAction SilentlyContinue
}

Require-Text "qa/tests/interop/src/lib.rs" "frozen_protocol_packet_opens_in_current_session_runtime"
Require-Text "qa/tests/interop/src/lib.rs" "native_runtime_accepts_the_same_snapshot_bytes_wasm_persists"
Require-Text "qa/tests/interop/src/lib.rs" "pre_v1_and_future_fixture_contracts_fail_closed"
Require-Text "qa/tests/interop/src/candidate_vectors.rs" "candidate_negative_handshake_vectors_fail_closed"
Require-Text "qa/tests/interop/src/candidate_vectors.rs" "candidate_ratchet_vectors_execute_current_session_runtime"
Require-Text "qa/tests/interop/src/candidate_vectors.rs" "candidate_group_rejection_vectors_preserve_parent_state"
Require-Text "crates/hydra-msg/src/packet_fragments/tests.rs" "candidate_direct_fragment_vectors_decode_and_reassemble"
Require-Text "crates/hydra-msg/src/packet_fragments/tests.rs" "candidate_negative_fragment_vectors_fail_closed"
Require-Text "examples/mobile_perf_web/web/app.js" "runWasmInteropFixtureProbe"
Require-Text "examples/mobile_perf_web/web/app.js" "browser-wasm-frozen-fixture-interop"
Require-Text "docs/validation/evidence/interop-test-harness.md" "CLI ↔ WASM compatibility"

Write-Host "interop harness checks passed." -ForegroundColor Green
