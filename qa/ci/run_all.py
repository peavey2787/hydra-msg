#!/usr/bin/env python3
"""Shared cross-platform HYDRA release validation orchestrator."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterable

from lib.run_all_cli import SECTIONS, build_parser, fuzz_config, selected_range


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]

def native_command(relative_base: str, args: Iterable[str] = ()) -> list[str]:
    root = repo_root()
    if os.name == "nt":
        script = root / f"{relative_base}.ps1"
        if not script.is_file():
            raise SystemExit(f"required Windows validation script missing: {script.relative_to(root)}")
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if not powershell:
            system_root = os.environ.get("SystemRoot", r"C:\Windows")
            candidate = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            if candidate.is_file():
                powershell = str(candidate)
        if not powershell:
            raise SystemExit("Windows validation requires Windows PowerShell (powershell.exe)")
        return [powershell, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args]

    script = root / f"{relative_base}.sh"
    if not script.is_file():
        raise SystemExit(f"required Unix validation script missing: {script.relative_to(root)}")
    return ["sh", str(script), *args]


def run_step(name: str, relative_base: str, args: Iterable[str] = (), extra_env: dict[str, str] | None = None) -> None:
    print(f"\n==> {name}", flush=True)
    command = native_command(relative_base, args)
    child_env = os.environ.copy()
    if extra_env:
        child_env.update(extra_env)
    completed = subprocess.run(command, cwd=repo_root(), env=child_env, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def skip_set(args: argparse.Namespace) -> set[str]:
    return {name for name in SECTIONS if getattr(args, f"skip_{name}")}


def selected_range(args: argparse.Namespace, p: argparse.ArgumentParser) -> tuple[int, int]:
    if args.only_section:
        # argparse cannot directly distinguish a default --from/--through from an
        # explicitly supplied one, so reject only when the raw argv contains both.
        selectors = set(sys.argv[1:])
        if any(x in selectors for x in ("--from", "--resume-from", "--start-at", "-From", "-ResumeFrom", "--through", "--stop-after", "-Through")):
            p.error("--only cannot be combined with --from or --through")
        index = SECTIONS.index(args.only_section)
        return index, index
    start = SECTIONS.index(args.from_section)
    end = SECTIONS.index(args.through_section)
    if start > end:
        p.error(f"--from {args.from_section} occurs after --through {args.through_section}")
    return start, end


def configure_fuzz(args: argparse.Namespace, p: argparse.ArgumentParser) -> tuple[str, int | None, int | None, int | None, int | None]:
    explicit_modes = sum((bool(args.overnight), bool(args.deep_fuzz)))
    if explicit_modes > 1:
        p.error("--overnight and --deep-fuzz cannot be combined")
    mode = "overnight" if args.overnight else "deep" if args.deep_fuzz else args.fuzz_mode
    if mode not in ("smoke", "overnight", "deep"):
        p.error(f"HYDRA_FUZZ_MODE must be smoke, overnight, or deep; got: {mode}")

    runs = args.fuzz_runs
    stateful_runs = args.stateful_fuzz_runs
    fuzz_seconds = None
    stateful_seconds = None
    if mode == "smoke":
        runs = runs or env_int("HYDRA_COVERAGE_FUZZ_RUNS", 256)
        stateful_runs = stateful_runs or env_int("HYDRA_STATEFUL_FUZZ_RUNS", 256)
    elif mode == "overnight":
        fuzz_seconds = env_int("HYDRA_COVERAGE_FUZZ_SECONDS", 900)
        stateful_seconds = env_int("HYDRA_STATEFUL_FUZZ_SECONDS", 300)
    else:
        runs = runs or env_int("HYDRA_COVERAGE_FUZZ_RUNS", 100000)
        stateful_runs = stateful_runs or env_int("HYDRA_STATEFUL_FUZZ_RUNS", 1000)
    return mode, runs, stateful_runs, fuzz_seconds, stateful_seconds


def main() -> int:
    p = build_parser()
    args = p.parse_args()
    if args.from_privacy:
        selectors = set(sys.argv[1:])
        if args.only_section or any(x in selectors for x in ("--from", "--resume-from", "--start-at", "-From", "-ResumeFrom")):
            p.error("--from-privacy cannot be combined with --only or --from")
        args.from_section = "tests"
    if args.list_sections:
        print("\n".join(SECTIONS))
        return 0

    start, end = selected_range(args, p)
    skipped = skip_set(args)
    mode, fuzz_runs, stateful_runs, fuzz_seconds, stateful_seconds = fuzz_config(args, p)

    def should_run(name: str) -> bool:
        rank = SECTIONS.index(name)
        return name not in skipped and start <= rank <= end

    ran_any = False
    release_header_printed = False

    def release_header() -> None:
        nonlocal release_header_printed
        if not release_header_printed:
            print("\n==> release evidence gates", flush=True)
            print("Supply-chain evidence is included by the tests section when selected.", flush=True)
            release_header_printed = True

    if should_run("permissions"):
        ran_any = True
        if os.name == "nt":
            print("\n==> Linux executable permissions", flush=True)
            print("Skipping Unix execute-bit repair on Windows.", flush=True)
        else:
            run_step("Linux executable permissions", "qa/ci/core/linux-permissions")

    if should_run("tests"):
        ran_any = True
        test_args: list[str] = []
        if os.name == "nt":
            test_args.append("-SkipReleaseStatic")
            if args.skip_vectors:
                test_args.append("-SkipVectors")
            if args.from_privacy:
                test_args.append("-FromPrivacy")
        else:
            test_args.append("--skip-release-static")
            if args.skip_vectors:
                test_args.append("--skip-vectors")
            if args.from_privacy:
                test_args.append("--from-privacy")
        run_step("tests/static validation", "qa/ci/core/check-tests", test_args)
        # Child process environment changes do not propagate upward; publish the
        # successful workspace baseline for later example/interop gates here.
        os.environ["HYDRA_WORKSPACE_TESTS_ALREADY_RAN"] = "1"

    if should_run("examples"):
        ran_any = True
        example_args: list[str] = []
        if args.skip_wasm:
            example_args.append("-SkipWasm" if os.name == "nt" else "--skip-wasm")
        run_step("example validation", "qa/ci/core/check-examples", example_args)

    miri_ran = False
    if should_run("miri"):
        ran_any = True
        release_header()
        run_step("Miri release evidence", "qa/ci/reliability/check-memory-safety", extra_env={"HYDRA_RUN_MIRI": "1"})
        miri_ran = True

    if should_run("sanitizers"):
        ran_any = True
        release_header()
        sanitizer_env = {"HYDRA_RUN_SANITIZERS": "1"}
        if miri_ran:
            sanitizer_env.update(HYDRA_RUN_MIRI="0", HYDRA_MIRI_ALREADY_RAN="1")
        run_step("sanitizer release evidence", "qa/ci/reliability/check-memory-safety", extra_env=sanitizer_env)

    if should_run("browser"):
        ran_any = True
        release_header()
        browser_env = {"HYDRA_RUN_BROWSER_E2E": "1"}
        if args.skip_browser_install:
            browser_env["HYDRA_SKIP_PLAYWRIGHT_INSTALL"] = "1"
        run_step("real browser Playwright lifecycle evidence", "qa/ci/reliability/check-browser-e2e", extra_env=browser_env)

    if should_run("coverage"):
        ran_any = True
        release_header()
        run_step("LCOV + 100% critical / 85% line + 65% branch native aggregate + CC/CRAP evidence", "qa/ci/quality/check-coverage", extra_env={"HYDRA_RUN_COVERAGE": "1"})

    if should_run("mutation"):
        ran_any = True
        release_header()
        mutation_env = {
            "HYDRA_RUN_MUTATION": "1",
            "HYDRA_MUTATION_JOBS": str(args.mutation_jobs),
        }
        if args.skip_mutation_baseline:
            mutation_env.update(
                HYDRA_MUTATION_BASELINE="skip",
                HYDRA_MUTATION_TIMEOUT=str(args.mutation_timeout),
            )
        else:
            mutation_env.update(
                HYDRA_MUTATION_BASELINE="run",
                HYDRA_MUTATION_TIMEOUT_MULTIPLIER=str(args.mutation_timeout_multiplier),
                HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT=str(args.mutation_minimum_timeout),
            )
        run_step("mutation testing release evidence", "qa/ci/quality/check-mutation", extra_env=mutation_env)

    if should_run("fuzz"):
        ran_any = True
        release_header()
        fuzz_env = {
            "HYDRA_RUN_COVERAGE_GUIDED_FUZZ": "1",
            "HYDRA_FUZZ_MODE": mode,
        }
        if mode == "overnight":
            assert fuzz_seconds is not None and stateful_seconds is not None
            fuzz_env["HYDRA_COVERAGE_FUZZ_SECONDS"] = str(fuzz_seconds)
            fuzz_env["HYDRA_STATEFUL_FUZZ_SECONDS"] = str(stateful_seconds)
            title = "overnight coverage-guided fuzz evidence"
        else:
            assert fuzz_runs is not None and stateful_runs is not None
            fuzz_env["HYDRA_COVERAGE_FUZZ_RUNS"] = str(fuzz_runs)
            fuzz_env["HYDRA_STATEFUL_FUZZ_RUNS"] = str(stateful_runs)
            title = "deep coverage-guided fuzz evidence" if mode == "deep" else "bounded coverage-guided fuzz evidence"
        run_step(title, "qa/ci/fuzz/check-fuzz", extra_env=fuzz_env)

    print()
    if ran_any:
        print("HYDRA-MSG selected release validation sections passed.")
    else:
        print("No validation sections were selected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
