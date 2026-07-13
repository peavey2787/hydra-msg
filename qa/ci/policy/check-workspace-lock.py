#!/usr/bin/env python3
"""Verify that Cargo.lock exactly represents the root workspace graph."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib
from collections.abc import Iterable


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


def dependency_selector(dependency: str) -> tuple[str, str | None, str | None]:
    parts = dependency.split(maxsplit=2)
    name = parts[0]
    version = parts[1] if len(parts) >= 2 and re.match(r"^[0-9]", parts[1]) else None
    source = None
    if len(parts) == 3:
        source = parts[2]
        if source.startswith("(") and source.endswith(")"):
            source = source[1:-1]
    return name, version, source


def package_label(package: dict[str, object]) -> str:
    name = package.get("name", "<unknown>")
    version = package.get("version", "<unknown>")
    source = package.get("source")
    return f"{name} {version}" + (f" ({source})" if isinstance(source, str) else "")


def resolve_dependency(
    dependency: str,
    packages: list[dict[str, object]],
    by_name: dict[str, list[int]],
) -> int:
    name, version, source = dependency_selector(dependency)
    candidates = list(by_name.get(name, []))
    if version is not None:
        candidates = [index for index in candidates if packages[index].get("version") == version]
    if source is not None:
        candidates = [index for index in candidates if packages[index].get("source") == source]
    if len(candidates) != 1:
        rendered = ", ".join(package_label(packages[index]) for index in candidates) or "none"
        fail(f"Cargo.lock dependency cannot be resolved uniquely: {dependency!r}; candidates: {rendered}")
    return candidates[0]


def reachable_packages(
    packages: list[dict[str, object]],
    root_indices: Iterable[int],
) -> set[int]:
    by_name: dict[str, list[int]] = {}
    for index, package in enumerate(packages):
        name = package.get("name")
        if isinstance(name, str):
            by_name.setdefault(name, []).append(index)

    reachable = set(root_indices)
    pending = list(root_indices)
    while pending:
        index = pending.pop()
        dependencies = packages[index].get("dependencies", [])
        if not isinstance(dependencies, list):
            fail(f"Cargo.lock package has invalid dependencies: {package_label(packages[index])}")
        for dependency in dependencies:
            if not isinstance(dependency, str):
                fail(f"Cargo.lock package has a non-string dependency: {package_label(packages[index])}")
            dependency_index = resolve_dependency(dependency, packages, by_name)
            if dependency_index not in reachable:
                reachable.add(dependency_index)
                pending.append(dependency_index)
    return reachable


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

    workspace_package = workspace.get("package", {})
    workspace_version = workspace_package.get("version") if isinstance(workspace_package, dict) else None
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

    raw_packages = lock.get("package", [])
    if not isinstance(raw_packages, list) or not all(isinstance(package, dict) for package in raw_packages):
        fail("Cargo.lock has no valid package list")
    packages: list[dict[str, object]] = raw_packages

    local_indices: dict[tuple[str, str], int] = {}
    for index, package in enumerate(packages):
        name = package.get("name")
        version = package.get("version")
        if "source" not in package and isinstance(name, str) and isinstance(version, str):
            key = (name, version)
            if key in local_indices:
                fail(f"Cargo.lock contains duplicate local package: {name} {version}")
            local_indices[key] = index

    missing = sorted(expected - set(local_indices))
    if missing:
        print("Cargo.lock is missing root workspace packages:", file=sys.stderr)
        for name, version in missing:
            print(f"  {name} {version}", file=sys.stderr)
        print("Run `cargo generate-lockfile` at the repository root and commit Cargo.lock.", file=sys.stderr)
        raise SystemExit(1)

    unexpected_local = sorted(set(local_indices) - expected)
    if unexpected_local:
        print("Cargo.lock contains local packages outside the root workspace:", file=sys.stderr)
        for name, version in unexpected_local:
            print(f"  {name} {version}", file=sys.stderr)
        raise SystemExit(1)

    root_indices = [local_indices[key] for key in sorted(expected)]
    reachable = reachable_packages(packages, root_indices)
    unreachable = [package for index, package in enumerate(packages) if index not in reachable]
    if unreachable:
        print("Cargo.lock contains packages unreachable from the root workspace:", file=sys.stderr)
        for package in sorted(unreachable, key=lambda item: (str(item.get("name")), str(item.get("version")))):
            print(f"  {package_label(package)}", file=sys.stderr)
        print("Regenerate Cargo.lock with Cargo and commit the cleaned lockfile.", file=sys.stderr)
        raise SystemExit(1)

    print(f"workspace lock graph passed ({len(expected)} workspace packages, {len(packages)} total packages)")


if __name__ == "__main__":
    main()
