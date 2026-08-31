#!/usr/bin/env python3
"""Cross-platform Rust source-size ownership policy.

The shared policy counts non-blank physical source lines so Windows and Linux
apply the same LOC definition. Native shell/PowerShell files are only launch
adapters for this implementation.
"""
from __future__ import annotations

from pathlib import Path
import sys

THRESHOLD = 300
SCAN_ROOTS = ("crates", "examples")
ALLOWLIST = Path("qa/ci/policy/rust-size-allowlist.txt")
TEST_NAMES = {"tests.rs", "test_support.rs"}


def source_loc(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def is_production_source(path: Path) -> bool:
    parts = path.parts
    if "target" in parts or "tests" in parts:
        return False
    if path.name in TEST_NAMES or path.name.endswith("_tests.rs"):
        return False
    return True


def parse_allowlist() -> tuple[dict[str, tuple[int, str]], list[str]]:
    allowed: dict[str, tuple[int, str]] = {}
    errors: list[str] = []
    if not ALLOWLIST.is_file():
        return allowed, [f"missing Rust source-size allow-list: {ALLOWLIST.as_posix()}"]

    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        parts = entry.split("|", 2)
        if len(parts) != 3 or not all(part.strip() for part in parts):
            errors.append(f"invalid allow-list entry: {raw}")
            continue
        path_text, max_text, reason = (part.strip() for part in parts)
        try:
            max_lines = int(max_text)
        except ValueError:
            errors.append(f"invalid max line count in allow-list entry: {raw}")
            continue
        if max_lines <= THRESHOLD:
            errors.append(
                f"allow-list max must exceed the default {THRESHOLD}-LOC threshold: {raw}"
            )
            continue
        if path_text in allowed:
            errors.append(f"duplicate allow-list entry: {path_text}")
            continue
        allowed[path_text] = (max_lines, reason)
    return allowed, errors


def main() -> int:
    repo_root = Path(__file__).resolve().parents[3]
    # Keep output stable and paths repository-relative on every OS.
    import os

    os.chdir(repo_root)
    print(f"HYDRA-MSG repo root: {repo_root}")

    allowed, errors = parse_allowlist()
    observed: dict[str, int] = {}

    for root_name in SCAN_ROOTS:
        root = Path(root_name)
        for path in sorted(root.rglob("*.rs")):
            if not is_production_source(path):
                continue
            loc = source_loc(path)
            if loc > THRESHOLD:
                observed[path.as_posix()] = loc

    for path_text, (max_lines, _reason) in allowed.items():
        path = Path(path_text)
        if not path.is_file():
            errors.append(f"allow-list entry points to missing file: {path_text}")
            continue
        loc = source_loc(path)
        if loc <= THRESHOLD:
            errors.append(
                f"stale allow-list entry no longer exceeds {THRESHOLD} LOC: "
                f"{path_text} ({loc} LOC)"
            )
        elif loc > max_lines:
            errors.append(
                f"allow-listed file exceeded documented max: "
                f"{path_text} ({loc} > {max_lines} LOC)"
            )

    for path_text, loc in observed.items():
        if path_text not in allowed:
            errors.append(
                f"Rust file exceeds {THRESHOLD} LOC without documented ownership exception: "
                f"{path_text} ({loc} LOC)"
            )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print("Rust source-size ownership check failed", file=sys.stderr)
        return 1

    print("Rust source-size ownership checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
