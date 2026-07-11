#!/usr/bin/env python3
"""Generate a deterministic CycloneDX JSON SBOM from Cargo.lock metadata.

This script intentionally depends only on Python's standard library and `cargo metadata`.
It is used by the HYDRA-MSG release package flow so SBOM generation does not depend
on a third-party cargo plugin being installed.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def run_metadata(repo: Path) -> dict:
    proc = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(proc.stdout)


def spdx_license(value: str | None) -> list[dict]:
    if not value:
        return []
    return [{"license": {"id": value}}]


def package_ref(package: dict) -> str:
    source = package.get("source")
    name = package["name"]
    version = package["version"]
    if source and "crates.io" in source:
        return f"pkg:cargo/{name}@{version}"
    return f"pkg:cargo/{name}@{version}?type=workspace"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HYDRA-MSG CycloneDX SBOM JSON")
    parser.add_argument("--repo", default=".", help="Repository root")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--version", required=True, help="Release version, for example v0.1.0")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    metadata = run_metadata(repo)
    packages = sorted(metadata["packages"], key=lambda p: (p["name"], p["version"], p.get("source") or ""))
    workspace_ids = set(metadata.get("workspace_members", []))
    package_by_id = {p["id"]: p for p in packages}

    components = []
    dependencies = []
    for package in packages:
        ref = package_ref(package)
        purl = ref
        component = {
            "type": "library",
            "bom-ref": ref,
            "name": package["name"],
            "version": package["version"],
            "purl": purl,
            "scope": "required",
        }
        if package.get("license"):
            component["licenses"] = spdx_license(package.get("license"))
        if package["id"] in workspace_ids:
            component["properties"] = [{"name": "hydra-msg:workspace-member", "value": "true"}]
        components.append(component)

        dep_refs = []
        for dep in package.get("dependencies", []):
            # cargo metadata dependencies may include aliases; resolve by package name/version/source when possible.
            name = dep.get("name")
            matches = [p for p in packages if p["name"] == name]
            if len(matches) == 1:
                dep_refs.append(package_ref(matches[0]))
        dependencies.append({"ref": ref, "dependsOn": sorted(set(dep_refs))})

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    ).stdout.strip()

    created = os.environ.get("SOURCE_DATE_EPOCH")
    if created:
        timestamp = _dt.datetime.fromtimestamp(int(created), tz=_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    else:
        timestamp = _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + hashlib.sha256((args.version + commit).encode()).hexdigest()[0:32],
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "application",
                "name": "hydra-msg",
                "version": args.version.lstrip("v"),
                "bom-ref": f"pkg:generic/hydra-msg@{args.version.lstrip('v')}",
                "purl": f"pkg:generic/hydra-msg@{args.version.lstrip('v')}",
            },
            "properties": [
                {"name": "hydra-msg:git-commit", "value": commit},
                {"name": "hydra-msg:git-dirty", "value": "true" if dirty else "false"},
                {"name": "hydra-msg:source", "value": "cargo metadata --locked"},
            ],
        },
        "components": components,
        "dependencies": sorted(dependencies, key=lambda d: d["ref"]),
    }

    output.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
