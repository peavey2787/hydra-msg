#!/usr/bin/env python3
"""Shared cross-platform static policy for HYDRA example packages."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = REPO_ROOT / "examples"
REFERENCE_APP = EXAMPLES / "hydra-gui"

CHECKED_MANIFESTS = {
    "examples/attachment_roundtrip/Cargo.toml",
    "examples/contact_card/Cargo.toml",
    "examples/handshake_roundtrip/Cargo.toml",
    "examples/hydra-gui/Cargo.toml",
    "examples/lobby_roundtrip/Cargo.toml",
    "examples/manual_file_carrier/Cargo.toml",
    "examples/mobile_perf_web/Cargo.toml",
    "examples/stego_lan_chat/Cargo.toml",
    "examples/webrtc_manual_carrier/Cargo.toml",
}

DIRECT_PROTOCOL_RE = re.compile(r"hydra-(?:core|crypto|group|session)|hydra_(?:core|crypto|group|session)")
REMOVED_APP_SURFACE_RE = re.compile(
    r"ContactTrustStore|IdentityVault|IdentityStore|IdentityUnlockSession|MessageStore|"
    r"LiveStateStore|ChatShell|AppSession|AppGroup|RecoveryManifest|SignedBackup|"
    r"TransportApi|DeviceRegistry"
)
SUPPRESSION_RE = re.compile(r"#\[allow\((?:dead_code|deprecated|unused|unused_imports|unused_must_use)")
TEXT_SUFFIXES = {
    ".css", ".html", ".js", ".json", ".md", ".ps1", ".rs", ".sh", ".toml", ".txt", ".webmanifest"
}


def fail(message: str) -> None:
    raise SystemExit(message)


def repo_relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "target" in path.parts or "pkg" in path.parts:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"LICENSE"}:
            yield path


def matching_lines(pattern: re.Pattern[str], root: Path):
    for path in source_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                yield f"{repo_relative(path)}:{line_number}:{line.strip()}"


def check_manifest_coverage() -> None:
    found = {repo_relative(path) for path in EXAMPLES.rglob("Cargo.toml")}
    missing = sorted(found - CHECKED_MANIFESTS)
    stale = sorted(CHECKED_MANIFESTS - found)
    if missing:
        fail("Example manifest is not covered by example validation: " + ", ".join(missing))
    if stale:
        fail("Stale example manifest policy entry: " + ", ".join(stale))


def check_reference_app_boundary() -> None:
    for retired in (EXAMPLES / "hydra-app", EXAMPLES / "hydra-app-core"):
        if retired.exists():
            fail("Old hydra-app example paths must not exist outside examples/hydra-gui.")

    direct = list(matching_lines(DIRECT_PROTOCOL_RE, REFERENCE_APP))
    if direct:
        fail(
            "Reference app must depend only on the public hydra-msg SDK boundary:\n"
            + "\n".join(direct)
        )

    removed = list(matching_lines(REMOVED_APP_SURFACE_RE, REFERENCE_APP))
    if removed:
        fail(
            "Removed app-owned protocol/storage implementations must not return:\n"
            + "\n".join(removed)
        )

    suppressions = list(matching_lines(SUPPRESSION_RE, REFERENCE_APP))
    if suppressions:
        fail(
            "Reference app must not suppress dead, deprecated, or unused-code diagnostics:\n"
            + "\n".join(suppressions)
        )


def check_wasm_package_metadata() -> None:
    manifest = REPO_ROOT / "crates/hydra-msg-wasm/Cargo.toml"
    package_license = REPO_ROOT / "crates/hydra-msg-wasm/LICENSE"
    readme = REPO_ROOT / "crates/hydra-msg-wasm/README.md"
    for path in (manifest, package_license, readme):
        if not path.is_file():
            fail(f"WASM package metadata file missing: {repo_relative(path)}")

    manifest_text = manifest.read_text(encoding="utf-8")
    if 'description = "WebAssembly and JavaScript bindings' not in manifest_text:
        fail("hydra-msg-wasm package description is missing")
    if 'readme = "README.md"' not in manifest_text:
        fail("hydra-msg-wasm package README declaration is missing")
    if (REPO_ROOT / "LICENSE").read_bytes() != package_license.read_bytes():
        fail("hydra-msg-wasm package-local LICENSE must match the repository LICENSE")


def main() -> None:
    check_manifest_coverage()
    check_reference_app_boundary()
    check_wasm_package_metadata()
    print("HYDRA-MSG shared example static policy passed.")


if __name__ == "__main__":
    main()
