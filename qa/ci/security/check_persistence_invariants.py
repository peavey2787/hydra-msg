#!/usr/bin/env python3
"""Cross-platform HYDRA persistence invariant checks.

All persistence policy logic lives here so Windows and Linux enforce identical
semantics. Native PowerShell/shell files are launch adapters only.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sys
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[3]
os.chdir(REPO_ROOT)

SNAPSHOT_FILE = Path("crates/hydra-msg/src/persistence/snapshot.rs")
STORAGE_FILE = Path("crates/hydra-msg/src/api/storage.rs")
CODEC_STORAGE_FILE = Path("crates/hydra-msg/src/codec/storage.rs")
WASM_PERSISTENCE_FILE = Path("crates/hydra-msg/src/browser/persistence.rs")
WASM_PERSISTENCE_JS_FILE = Path("crates/hydra-msg/src/browser/persistence_js.rs")
STORAGE_TESTS_FILE = Path("crates/hydra-msg/src/tests/storage.rs")
PERSISTENCE_TESTS_FILE = Path("crates/hydra-msg/src/tests/persistence.rs")
PARSER_VECTOR_ROOT = Path("qa/vectors/persistence/parser-stress")
POSITIVE_VECTOR_ROOT = Path("qa/vectors/persistence/positive")
NEGATIVE_VECTOR_ROOT = Path("qa/vectors/persistence/negative")
PERSISTENCE_VECTOR_ROOT = Path("qa/vectors/persistence")
GIT_ATTRIBUTES_FILE = Path(".gitattributes")
NATIVE_STORE_FILE = Path("crates/hydra-msg/src/persistence/native_store.rs")
PLATFORM_FILE = Path("crates/hydra-platform/src/lib.rs")
KDF_FILE = Path("crates/hydra-msg/src/codec/kdf.rs")

SKIP_SUFFIXES = {".bin", ".hex", ".png", ".jpg", ".jpeg", ".gif", ".zip"}


def fail(message: str) -> None:
    raise SystemExit(message)


def require_file(path: Path) -> None:
    if not path.is_file():
        fail(f"persistence invariant required file missing: {path.as_posix()}")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require_source_text(path: Path, text: str, description: str) -> None:
    if text not in read_text(path):
        fail(
            f"persistence invariant missing: {description}; expected {text!r} "
            f"in {path.as_posix()}"
        )


def require_tree_text(root: Path, text: str, description: str) -> None:
    for path in root.rglob("*.rs"):
        if text in read_text(path):
            return
    fail(
        f"persistence invariant missing: {description}; expected {text!r} "
        f"under {root.as_posix()}"
    )


def search_files(roots: Iterable[Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for root in roots:
        if root.is_file():
            candidates = (root,)
        elif root.is_dir():
            candidates = root.rglob("*")
        else:
            continue
        for path in candidates:
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            if any(part in {"target", ".git"} for part in path.parts):
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            yield path


def assert_no_search_match(roots: Iterable[Path], pattern: str, description: str) -> None:
    regex = re.compile(pattern)
    matches: list[str] = []
    for path in search_files(roots):
        for line_number, line in enumerate(read_text(path).splitlines(), 1):
            if regex.search(line):
                matches.append(f"{path.as_posix()}:{line_number}:{line}")
    if matches:
        print("\n".join(matches), file=sys.stderr)
        fail(f"persistence invariant forbidden pattern found: {description}")


def verify_vector_magic_and_manifests() -> None:
    magic = b"HYDRA-MSG-STATE-SNAPSHOT\n"
    for snapshot in (
        POSITIVE_VECTOR_ROOT / "TV-PERSIST-EMPTY-000/snapshot.bin",
        POSITIVE_VECTOR_ROOT / "TV-PERSIST-FULL-000/snapshot.bin",
    ):
        require_file(snapshot)
        if not snapshot.read_bytes().startswith(magic):
            fail(f"persistence vector snapshot magic/EOL changed: {snapshot.as_posix()}")

    for manifest in (
        PERSISTENCE_VECTOR_ROOT / "manifest.sha3-256",
        POSITIVE_VECTOR_ROOT / "manifest.sha3-256",
        NEGATIVE_VECTOR_ROOT / "manifest.sha3-256",
        PARSER_VECTOR_ROOT / "manifest.sha3-256",
    ):
        require_file(manifest)
        for line_number, line in enumerate(read_text(manifest).splitlines(), 1):
            if not line.strip():
                continue
            try:
                expected, path_text = line.split("  ", 1)
            except ValueError:
                fail(f"invalid persistence vector manifest entry: {manifest}:{line_number}")
            payload = Path(path_text)
            require_file(payload)
            actual = hashlib.sha3_256(payload.read_bytes()).hexdigest()
            if actual != expected:
                fail(
                    f"persistence vector manifest mismatch: {manifest}:{line_number}: "
                    f"{payload}: expected {expected}, got {actual}"
                )


def verify_parser_ownership() -> None:
    """Require exactly one definition for each canonical persistence parser helper.

    The two helpers parse different layers. `parse_chunked_storage` owns the
    encrypted/chunked storage envelope; `state_snapshot_text` owns snapshot text
    validation. This checks symbol ownership directly instead of relying on
    platform-specific path separator matching.
    """
    expected = {
        "parse_chunked_storage": Path("crates/hydra-msg/src/codec/storage.rs"),
        "state_snapshot_text": Path(
            "crates/hydra-msg/src/persistence/snapshot/helpers.rs"
        ),
    }
    definitions: dict[str, list[tuple[Path, int, str]]] = {name: [] for name in expected}
    root = Path("crates/hydra-msg/src")
    pattern = re.compile(r"\bfn\s+(parse_chunked_storage|state_snapshot_text)\b")
    for path in root.rglob("*.rs"):
        for line_number, line in enumerate(read_text(path).splitlines(), 1):
            match = pattern.search(line)
            if match:
                definitions[match.group(1)].append((path, line_number, line))

    errors: list[str] = []
    for name, owner in expected.items():
        found = definitions[name]
        if len(found) != 1 or found[0][0] != owner:
            for path, line_number, line in found:
                errors.append(f"{path.as_posix()}:{line_number}:{line}")
            locations = ", ".join(path.as_posix() for path, _, _ in found) or "<none>"
            errors.append(
                f"persistence parser ownership mismatch for {name}: "
                f"expected exactly {owner.as_posix()}, found {locations}"
            )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        fail("duplicate snapshot/envelope parser found outside canonical owners")


def require_vector_metadata(root: Path, vector_ids: Iterable[str], expected_text: str) -> None:
    for vector_id in vector_ids:
        metadata = root / vector_id / "metadata.json"
        require_file(metadata)
        require_source_text(metadata, expected_text, f"{vector_id} metadata")


def main() -> int:
    required = (
        SNAPSHOT_FILE,
        STORAGE_FILE,
        CODEC_STORAGE_FILE,
        WASM_PERSISTENCE_FILE,
        WASM_PERSISTENCE_JS_FILE,
        STORAGE_TESTS_FILE,
        PERSISTENCE_TESTS_FILE,
        NATIVE_STORE_FILE,
        PLATFORM_FILE,
        KDF_FILE,
        GIT_ATTRIBUTES_FILE,
        PARSER_VECTOR_ROOT / "manifest.sha3-256",
        POSITIVE_VECTOR_ROOT / "manifest.sha3-256",
        NEGATIVE_VECTOR_ROOT / "manifest.sha3-256",
        PERSISTENCE_VECTOR_ROOT / "manifest.sha3-256",
    )
    for path in required:
        require_file(path)

    for text, description in (
        ("MAX_IDENTITIES", "snapshot collection-count guardrail"),
        ("MAX_CONTACTS", "contact collection-count guardrail"),
        ("MAX_MESSAGES", "message collection-count guardrail"),
        ("MAX_LOBBIES", "lobby collection-count guardrail"),
        ("MAX_ANONYMOUS_AUTH_SPENT", "anonymous-auth collection-count guardrail"),
        ("HashSet", "duplicate collection record detection"),
        ("reject_duplicate_collection_record", "duplicate collection record rejection helper"),
        ("reject_collection_limit", "collection limit rejection helper"),
        ("state record kind", "unknown snapshot record rejection"),
    ):
        require_source_text(SNAPSHOT_FILE, text, description)

    for text, description in (
        ("persistence_parser_stress_vectors_reject_malformed_containers", "parser-stress fixture regression test"),
        ("state_snapshot_validation_rejects_duplicates_unknowns_and_collection_replays", "snapshot duplicate/unknown regression test"),
        ("current_persistence_vectors_use_chunked_storage_and_round_trip", "current chunked persistence regression test"),
        ("old_format_persistence_envelopes_fail_closed", "old-format persistence fail-closed regression test"),
        ("frozen_persistence_stale_generation_and_restore_floor_vectors_hold", "stale-generation and restore-floor vector regression test"),
    ):
        require_tree_text(Path("crates/hydra-msg/src/tests"), text, description)

    require_source_text(STORAGE_FILE, "verify_backup(", "passworded backup verification facade retained")
    require_source_text(
        STORAGE_FILE,
        "open_verified_backup_snapshot(bytes.as_ref(), password.as_ref())",
        "backup verification authenticates with supplied password",
    )
    require_source_text(CODEC_STORAGE_FILE, "reject_oversize_envelope", "encrypted envelope size limit retained")
    require_source_text(CODEC_STORAGE_FILE, "reject_long_envelope_lines", "encrypted envelope line-length limit retained")
    require_source_text(WASM_PERSISTENCE_JS_FILE, "indexedDB", "WASM persistence uses IndexedDB")
    require_source_text(WASM_PERSISTENCE_FILE, "opaque", "WASM persistence adapter documents opaque encrypted bytes")
    require_source_text(GIT_ATTRIBUTES_FILE, "qa/vectors/** -text", "frozen vector tree disables Git line-ending conversion")
    require_source_text(GIT_ATTRIBUTES_FILE, "*.bin -text", "binary artifacts disable Git line-ending conversion")
    require_source_text(
        NATIVE_STORE_FILE,
        "hydra_platform::atomic_replace_file(tmp, path)?",
        "native persistence delegates replacement to the audited platform boundary",
    )
    require_source_text(
        PLATFORM_FILE,
        "MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH",
        "Windows replacement uses native replace-existing plus write-through flags",
    )
    require_source_text(
        PLATFORM_FILE,
        "windows_atomic_replace_replaces_existing_destination_without_delete_gap",
        "Windows native replacement regression test",
    )
    if "remove_file(path)" in read_text(NATIVE_STORE_FILE):
        fail("persistence invariant forbidden: delete-before-rename replacement path returned")
    require_source_text(KDF_FILE, "Ok((17, 8, 1))", "current scrypt baseline is at least N=2^17, r=8, p=1")
    require_source_text(KDF_FILE, "needs_upgrade", "legacy KDF records are explicitly migration-detectable")
    require_source_text(STORAGE_FILE, "upgrade_state_kdf", "native state transparently migrates legacy KDF records")
    require_source_text(
        STORAGE_FILE,
        "let revision = if migrate_kdf",
        "browser open detects and commits legacy state KDF migration",
    )
    require_source_text(
        STORAGE_FILE,
        "persistent_snapshot.revision,",
        "browser KDF migration uses the existing IndexedDB compare-and-swap revision",
    )
    require_tree_text(
        Path("crates/hydra-msg/src/tests"),
        "legacy_scrypt_state_is_transparently_upgraded_on_open",
        "legacy KDF transparent migration regression test",
    )
    require_source_text(
        Path("crates/hydra-msg/src/api/identity.rs"),
        "previous.password_kdf.needs_upgrade()?",
        "legacy identity KDF is migration-detected only after password verification",
    )
    require_tree_text(
        Path("crates/hydra-msg/src/tests"),
        "legacy_identity_kdf_is_transparently_upgraded_on_unlock",
        "legacy identity KDF transparent migration regression test",
    )

    verify_vector_magic_and_manifests()

    assert_no_search_match(
        (Path("crates"), Path("examples")),
        r"localStorage[.\[]",
        "direct localStorage use for HYDRA state",
    )
    assert_no_search_match(
        (Path("crates"), Path("examples")),
        r"state\.(json|txt)|plaintext_state|HYDRA-MSG-STATE-V[0-9]+|STATE_V[0-9]+",
        "legacy plaintext or numbered state format resurrection",
    )
    assert_no_search_match(
        (
            Path("crates/hydra-msg-wasm"),
            Path("examples"),
            Path("docs/spec"),
            Path("docs/impl"),
            Path("docs/validation"),
            Path("README.md"),
        ),
        r"WasmHydra\.open(Default)?\s*\(",
        "durable-looking WASM no-op open path",
    )
    assert_no_search_match(
        (
            Path("crates"),
            Path("docs/spec"),
            Path("docs/impl"),
            Path("docs/validation"),
            Path("README.md"),
        ),
        r"verify_backup\([^,)]*\)|verifyBackup\([^,)]*\)",
        "stale one-argument backup verification reference",
    )
    assert_no_search_match(
        (Path("crates/hydra-msg-wasm"), Path("examples/mobile_perf_web")),
        r"openDatabase|sql\.js|sqlite|localforage",
        "browser SQLite/WebSQL/localForage persistence detour",
    )

    verify_parser_ownership()

    counts = (
        (PARSER_VECTOR_ROOT, 5, "persistence parser-stress"),
        (POSITIVE_VECTOR_ROOT, 2, "positive persistence"),
        (NEGATIVE_VECTOR_ROOT, 6, "negative persistence"),
    )
    for root, minimum, description in counts:
        count = sum(1 for _ in root.rglob("metadata.json"))
        if count < minimum:
            fail(f"expected at least {minimum} {description} vectors, found {count}")

    require_vector_metadata(
        PARSER_VECTOR_ROOT,
        (
            "TV-PERSISTENCE-STATE-BAD-MAGIC",
            "TV-PERSISTENCE-STATE-EMPTY-CIPHERTEXT",
            "TV-PERSISTENCE-BACKUP-BAD-KDF",
            "TV-PERSISTENCE-BACKUP-BAD-NONCE",
            "TV-PERSISTENCE-SNAPSHOT-DUPLICATE-SCALAR",
        ),
        '"expected_result":"reject"',
    )
    require_vector_metadata(
        POSITIVE_VECTOR_ROOT,
        ("TV-PERSIST-EMPTY-000", "TV-PERSIST-FULL-000"),
        '"expected_result"',
    )
    require_vector_metadata(
        NEGATIVE_VECTOR_ROOT,
        (
            "TV-PERSIST-WRONG-PASSWORD-000",
            "TV-PERSIST-BAD-KDF-PARAMS-000",
            "TV-PERSIST-CIPHERTEXT-FLIP-000",
            "TV-PERSIST-TRUNCATED-000",
            "TV-PERSIST-BAD-SNAPSHOT-000",
            "TV-PERSIST-STALE-GENERATION-000",
        ),
        '"expected_result":"reject"',
    )

    print("persistence invariant checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
