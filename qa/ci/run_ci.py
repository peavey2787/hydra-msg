#!/usr/bin/env python3
"""Run the same bounded validation sections used by GitHub Actions."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import subprocess
from typing import Iterator, Mapping, Sequence


SECTIONS = ("core", "browser", "fuzz")
ROOT = Path(__file__).resolve().parents[2]


def native_script(relative_base: str, args: Sequence[str] = ()) -> list[str]:
    if os.name != "nt":
        return ["sh", str(ROOT / f"{relative_base}.sh"), *args]

    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidate = (
            Path(system_root)
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        if candidate.is_file():
            powershell = str(candidate)
    if not powershell:
        raise SystemExit("Windows bounded CI requires Windows PowerShell")
    return [
        powershell,
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ROOT / f"{relative_base}.ps1"),
        *args,
    ]


def run(name: str, command: Sequence[str], extra_env: Mapping[str, str]) -> None:
    print(f"\n==> {name}", flush=True)
    child_env = os.environ.copy()
    child_env.update(extra_env)
    result = subprocess.run(command, cwd=ROOT, env=child_env, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


@contextmanager
def ephemeral_lockfile() -> Iterator[None]:
    """Give local runs the disposable-lock behavior of a fresh CI checkout."""
    lock = ROOT / "Cargo.lock"
    original = lock.read_bytes()
    try:
        yield
    finally:
        if lock.read_bytes() != original:
            lock.write_bytes(original)


def run_core() -> None:
    env = {"HYDRA_CI_EPHEMERAL_LOCK_REFRESH": "1"}
    test_args = (
        ("-SkipVectors", "-SkipReleaseStatic")
        if os.name == "nt"
        else ("--skip-vectors", "--skip-release-static")
    )
    with ephemeral_lockfile():
        run("prepare bounded CI dependency graph", ("cargo", "fetch"), env)
        run(
            "workspace and static validation",
            native_script("qa/ci/core/check-tests", test_args),
            env,
        )
        run(
            "maintained example validation",
            native_script("qa/ci/core/check-examples"),
            env,
        )


def run_browser() -> None:
    env = {
        "HYDRA_BROWSER_WORKERS": "1",
        "HYDRA_PLAYWRIGHT_INSTALL_DEPS": "1",
        "HYDRA_RUN_BROWSER_E2E": "1",
    }
    run(
        "browser lifecycle evidence",
        native_script("qa/ci/reliability/check-browser-e2e"),
        env,
    )


def run_fuzz() -> None:
    env = {"HYDRA_CI_EPHEMERAL_LOCK_REFRESH": "1"}
    with ephemeral_lockfile():
        run("prepare deterministic fuzz dependency graph", ("cargo", "fetch"), env)
        run(
            "deterministic fuzz regression",
            native_script("qa/ci/fuzz/check-fuzz"),
            env,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the exact bounded validation sections used by GitHub CI."
    )
    parser.add_argument("--only", choices=SECTIONS, help="run one GitHub CI job")
    args = parser.parse_args()

    selected = (args.only,) if args.only else SECTIONS
    runners = {"core": run_core, "browser": run_browser, "fuzz": run_fuzz}
    for section in selected:
        runners[section]()
    print("\nHYDRA-MSG bounded GitHub-equivalent CI passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
