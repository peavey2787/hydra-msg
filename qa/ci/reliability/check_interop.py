#!/usr/bin/env python3
"""Cross-platform HYDRA cross-runtime interoperability harness gate."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[3]

REQUIRED_FILES = (
    "qa/fixtures/interop/manifest.sha3-256",
    "qa/tests/interop/Cargo.toml",
    "qa/tests/interop/src/lib.rs",
    "qa/tests/interop/src/candidate_vectors.rs",
    "crates/hydra-msg/src/packet_fragments/tests.rs",
    "qa/fixtures/interop/browser/wasm-fixture-probe.js",
    "docs/validation/evidence/interop-test-harness.md",
    "examples/mobile_perf_web/web/app.js",
    "examples/mobile_perf_web/src/main.rs",
)

REQUIRED_TEXT = (
    ("qa/tests/interop/src/lib.rs", "frozen_protocol_packet_opens_in_current_session_runtime"),
    ("qa/tests/interop/src/lib.rs", "native_runtime_accepts_the_same_snapshot_bytes_wasm_persists"),
    ("qa/tests/interop/src/lib.rs", "pre_v1_and_future_fixture_contracts_fail_closed"),
    ("crates/hydra-msg/src/packet_fragments/tests.rs", "candidate_direct_fragment_vectors_decode_and_reassemble"),
    ("crates/hydra-msg/src/packet_fragments/tests.rs", "candidate_negative_fragment_vectors_fail_closed"),
    ("examples/mobile_perf_web/web/app.js", "runWasmInteropFixtureProbe"),
    ("examples/mobile_perf_web/web/app.js", "browser-wasm-frozen-fixture-interop"),
    ("docs/validation/evidence/interop-test-harness.md", "CLI ↔ WASM compatibility"),
)

REQUIRED_MODULE_TEXT = (
    ("qa/tests/interop/src/candidate_vectors.rs", "candidate_negative_handshake_vectors_fail_closed"),
    ("qa/tests/interop/src/candidate_vectors.rs", "candidate_ratchet_vectors_execute_current_session_runtime"),
    ("qa/tests/interop/src/candidate_vectors.rs", "candidate_group_rejection_vectors_preserve_parent_state"),
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def require_files() -> None:
    for relative in REQUIRED_FILES:
        if not (REPO_ROOT / relative).is_file():
            fail(f"required interop file missing: {relative}")


def verify_manifest() -> None:
    manifest = REPO_ROOT / "qa/fixtures/interop/manifest.sha3-256"
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split(None, 1)
        path = REPO_ROOT / relative
        actual = hashlib.sha3_256(path.read_bytes()).hexdigest()
        if actual != expected:
            fail(
                f"interop fixture hash mismatch: {relative}: "
                f"expected {expected}, got {actual}"
            )


def run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, object] = {
        "cwd": REPO_ROOT,
        "check": False,
        "text": True,
    }
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    result = subprocess.run(command, **kwargs)  # type: ignore[arg-type]
    if result.returncode != 0:
        if capture:
            if result.stdout:
                sys.stdout.write(result.stdout)
            if result.stderr:
                sys.stderr.write(result.stderr)
        fail(f"{' '.join(command)} failed with exit code {result.returncode}")
    return result


def run_rust_interop_tests() -> None:
    if os.environ.get("HYDRA_WORKSPACE_TESTS_ALREADY_RAN") == "1":
        print(
            "hydra-interop-tests already executed by cargo test "
            "--workspace --all-targets; not repeating."
        )
        return
    run(["cargo", "test", "-p", "hydra-interop-tests"])


def verify_cli_round_trip() -> None:
    with tempfile.TemporaryDirectory(prefix="hydra-interop-cli-") as temp_dir:
        run(
            [
                "cargo",
                "run",
                "-p",
                "hydra-msg-cli",
                "--",
                "generate-id",
                temp_dir,
                "state-pw",
                "id-pw",
            ]
        )
        result = run(
            [
                "cargo",
                "run",
                "-p",
                "hydra-msg-cli",
                "--",
                "doctor",
                temp_dir,
                "state-pw",
            ],
            capture=True,
        )
        output = result.stdout or ""
        for expected in ("identities=1", "contacts=0", "messages=0", "lobbies=0"):
            if expected not in output:
                fail(f"CLI doctor output missing expected value: {expected}")


def rust_module_text(relative: str) -> str:
    path = REPO_ROOT / relative
    texts = [path.read_text(encoding="utf-8")]
    parts_dir = path.with_name(f"{path.stem}_parts")
    if parts_dir.is_dir():
        texts.extend(
            part.read_text(encoding="utf-8")
            for part in sorted(parts_dir.rglob("*.rs"))
        )
    return "\n".join(texts)


def require_text_contracts() -> None:
    cache: dict[str, str] = {}
    for relative, expected in REQUIRED_TEXT:
        text = cache.get(relative)
        if text is None:
            text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            cache[relative] = text
        if expected not in text:
            fail(f"interop invariant missing from {relative}: {expected}")

    module_cache: dict[str, str] = {}
    for relative, expected in REQUIRED_MODULE_TEXT:
        text = module_cache.get(relative)
        if text is None:
            text = rust_module_text(relative)
            module_cache[relative] = text
        if expected not in text:
            fail(f"interop invariant missing from module {relative}: {expected}")


def main() -> int:
    require_files()
    verify_manifest()
    run_rust_interop_tests()
    verify_cli_round_trip()
    require_text_contracts()
    print("interop harness checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
