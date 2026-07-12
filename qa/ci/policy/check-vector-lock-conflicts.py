#!/usr/bin/env python3
"""Validate shared package versions between independent Cargo.lock files.

The root workspace lock and qa/tools/vector-gen/Cargo.lock are intentionally
independent locks. Tool-only dependencies are allowed. A failure means a package
name appears in both locks but the two locks have no version in common for that
name, which would make the vector tool use a different version of a shared
package than the production workspace.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def parse_lock(path: Path) -> dict[str, set[str]]:
    packages: dict[str, set[str]] = {}
    current_name: str | None = None
    current_version: str | None = None
    in_package = False

    def flush() -> None:
        nonlocal current_name, current_version
        if current_name and current_version:
            packages.setdefault(current_name, set()).add(current_version)
        current_name = None
        current_version = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            if in_package:
                flush()
            in_package = True
            continue
        if not in_package or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if key == "name":
            current_name = value.strip('"')
        elif key == "version":
            current_version = value.strip('"')

    if in_package:
        flush()
    return packages


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root_lock", type=Path)
    parser.add_argument("vector_lock", type=Path)
    args = parser.parse_args()

    root_versions = parse_lock(args.root_lock)
    vector_versions = parse_lock(args.vector_lock)
    vector_versions.pop("hydra-vector-gen", None)

    conflicts: list[str] = []
    for name in sorted(set(root_versions) & set(vector_versions)):
        root = root_versions[name]
        vector = vector_versions[name]
        if root.isdisjoint(vector):
            conflicts.append(
                f"{name}: root={','.join(sorted(root))} vector={','.join(sorted(vector))}"
            )

    if conflicts:
        print("vector tool lock conflicts with main workspace package versions:", file=sys.stderr)
        for conflict in conflicts:
            print(f"  {conflict}", file=sys.stderr)
        print(
            "Regenerate both Cargo.lock files on a machine that can fetch crates, then commit them together.",
            file=sys.stderr,
        )
        return 1

    print("vector tool shared lock versions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
