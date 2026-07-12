#!/usr/bin/env python3
"""Verify that Cargo.lock represents every package in the root workspace."""

from __future__ import annotations

import pathlib
import sys
import tomllib


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def package_version(package: dict[str, object], workspace_version: str) -> str:
    version = package.get("version")
    if isinstance(version, str):
        return version
    if isinstance(version, dict) and version.get("workspace") is True:
        return workspace_version
    fail("workspace package has no resolvable version")
    raise AssertionError("unreachable")


def main() -> None:
    repo_root = pathlib.Path(__file__).resolve().parents[3]
    workspace_manifest = tomllib.loads((repo_root / "Cargo.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((repo_root / "Cargo.lock").read_text(encoding="utf-8"))

    workspace = workspace_manifest.get("workspace")
    if not isinstance(workspace, dict):
        fail("root Cargo.toml has no [workspace] table")

    members = workspace.get("members")
    if not isinstance(members, list) or not all(isinstance(member, str) for member in members):
        fail("root Cargo.toml has no valid workspace.members list")

    workspace_package = workspace_manifest.get("workspace", {}).get("package", {})
    workspace_version = workspace_package.get("version")
    if not isinstance(workspace_version, str):
        fail("root Cargo.toml has no workspace.package.version")

    expected: set[tuple[str, str]] = set()
    for member in members:
        manifest_path = repo_root / member / "Cargo.toml"
        if not manifest_path.is_file():
            fail(f"workspace member manifest is missing: {manifest_path.relative_to(repo_root)}")
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        package = manifest.get("package")
        if not isinstance(package, dict):
            fail(f"workspace member has no [package] table: {manifest_path.relative_to(repo_root)}")
        name = package.get("name")
        if not isinstance(name, str):
            fail(f"workspace member has no package name: {manifest_path.relative_to(repo_root)}")
        expected.add((name, package_version(package, workspace_version)))

    locked_local = {
        (package["name"], package["version"])
        for package in lock.get("package", [])
        if isinstance(package, dict)
        and "source" not in package
        and isinstance(package.get("name"), str)
        and isinstance(package.get("version"), str)
    }

    missing = sorted(expected - locked_local)
    if missing:
        print("Cargo.lock is missing root workspace packages:", file=sys.stderr)
        for name, version in missing:
            print(f"  {name} {version}", file=sys.stderr)
        print("Run `cargo generate-lockfile` at the repository root and commit Cargo.lock.", file=sys.stderr)
        raise SystemExit(1)

    print(f"workspace lock coverage passed ({len(expected)} packages)")


if __name__ == "__main__":
    main()
