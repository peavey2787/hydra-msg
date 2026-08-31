"""Argument parsing and validation for the shared HYDRA validation runner."""

from __future__ import annotations

import argparse
import os

SECTIONS = (
    "permissions", "tests", "examples", "miri", "sanitizers",
    "browser", "coverage", "mutation", "fuzz",
)
SECTION_ALIASES = {
    "permission": "permissions", "test": "tests", "static": "tests",
    "example": "examples", "sanitizer": "sanitizers", "browsers": "browser",
    "playwright": "browser", "browser-e2e": "browser", "llvm-cov": "coverage",
    "mutants": "mutation", "fuzzing": "fuzz",
}


def section(value: str) -> str:
    normalized = SECTION_ALIASES.get(value.strip().lower(), value.strip().lower())
    if normalized not in SECTIONS:
        raise argparse.ArgumentTypeError(
            f"unknown validation section: {value}; valid sections: {', '.join(SECTIONS)}"
        )
    return normalized


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got: {value}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got: {value}")
    return parsed


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a positive number, got: {value}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive number, got: {value}")
    return parsed


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return positive_int(raw) if raw else default


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return positive_float(raw) if raw else default


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Run the complete HYDRA validation pipeline using one shared cross-platform orchestrator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Sections, in order:
  permissions, tests, examples, miri, sanitizers, browser, coverage, mutation, fuzz

Examples:
  qa/ci/check-all.sh --from coverage --through mutation
  qa/ci/check-all.sh --only fuzz --deep-fuzz
  qa\\ci\\check-all.ps1 -From browser
  qa\\ci\\check-all.ps1 -FromPrivacy -DeepFuzz
  qa\\ci\\check-all.ps1 -Only coverage
""",
        allow_abbrev=False,
    )
    p.add_argument("--from", "--resume-from", "--start-at", "-From", "-ResumeFrom", dest="from_section", type=section, default="permissions")
    p.add_argument("--through", "--stop-after", "-Through", dest="through_section", type=section, default="fuzz")
    p.add_argument("--only", "--section", "-Only", dest="only_section", type=section)
    p.add_argument("--list-sections", "-ListSections", action="store_true")
    p.add_argument("--from-privacy", "-FromPrivacy", dest="from_privacy", action="store_true", help="resume the tests/static section at privacy invariant checks")
    for name in SECTIONS:
        ps_name = "".join(part.capitalize() for part in name.split("-"))
        p.add_argument(f"--skip-{name}", f"-Skip{ps_name}", dest=f"skip_{name}", action="store_true")
    p.add_argument("--skip-vectors", "-SkipVectors", action="store_true")
    p.add_argument("--skip-wasm", "-SkipWasm", action="store_true")
    p.add_argument("--skip-browser-install", "-SkipBrowserInstall", action="store_true")
    p.add_argument("--skip-mutation-baseline", "-SkipMutationBaseline", action="store_true")
    p.add_argument("--check-format-only", "-CheckFormatOnly", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--mutation-timeout", "-MutationTimeout", type=positive_int, default=env_int("HYDRA_MUTATION_TIMEOUT", 1200))
    p.add_argument("--mutation-timeout-multiplier", "-MutationTimeoutMultiplier", type=positive_float, default=env_float("HYDRA_MUTATION_TIMEOUT_MULTIPLIER", 2.0))
    p.add_argument("--mutation-minimum-timeout", "-MutationMinimumTimeout", type=positive_int, default=env_int("HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT", 120))
    p.add_argument("--mutation-jobs", "-MutationJobs", type=positive_int, default=env_int("HYDRA_MUTATION_JOBS", 1))
    p.add_argument("--fuzz-runs", "-FuzzRuns", type=positive_int)
    p.add_argument("--stateful-fuzz-runs", "-StatefulFuzzRuns", type=positive_int)
    p.add_argument("--overnight", "-Overnight", action="store_true")
    p.add_argument("--deep-fuzz", "-DeepFuzz", action="store_true")
    p.add_argument("--fuzz-mode", "-FuzzMode", choices=("smoke", "overnight", "deep"), default=os.environ.get("HYDRA_FUZZ_MODE", "smoke"))
    return p


def selected_range(args: argparse.Namespace, p: argparse.ArgumentParser) -> tuple[int, int]:
    if args.only_section:
        index = SECTIONS.index(args.only_section)
        return index, index
    start = SECTIONS.index(args.from_section)
    end = SECTIONS.index(args.through_section)
    if start > end:
        p.error(f"--from {args.from_section} occurs after --through {args.through_section}")
    return start, end


def fuzz_config(args: argparse.Namespace, p: argparse.ArgumentParser) -> tuple[str, int | None, int | None, int | None, int | None]:
    if args.overnight and args.deep_fuzz:
        p.error("--overnight and --deep-fuzz cannot be combined")
    mode = "overnight" if args.overnight else "deep" if args.deep_fuzz else args.fuzz_mode
    runs = args.fuzz_runs
    stateful_runs = args.stateful_fuzz_runs
    fuzz_seconds = stateful_seconds = None
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
