#!/usr/bin/env python3
"""Cross-platform release-governance checks for HYDRA-MSG."""

from __future__ import annotations

import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REQUIRED_FILES = (
    "CHANGELOG.md",
    "SECURITY.md",
    ".github/workflows/ci.yml",
    ".github/workflows/release-validation.yml",
    ".github/dependabot.yml",
    "docs/validation/release/release-checklist.md",
    "docs/validation/release/release-artifacts.md",
    "docs/validation/release/release-signing.md",
    "docs/validation/release/sbom.md",
    "docs/validation/release/reproducible-builds.md",
    "docs/validation/release/supported-platforms.md",
    "docs/validation/release/msrv-policy.md",
    "docs/validation/release/dependency-update-policy.md",
    "docs/validation/release/security-advisory-policy.md",
    "docs/validation/release/responsible-disclosure.md",
    "docs/validation/release/external-review-status.md",
    "scripts/release/generate-sbom.py",
    "scripts/release/create-release-package.sh",
    "scripts/release/sign-release-artifacts.sh",
    "scripts/release/verify-release-artifacts.sh",
    "scripts/release/create-signed-tag.sh",
    "scripts/release/create-release-package.ps1",
    "scripts/release/sign-release-artifacts.ps1",
    "scripts/release/verify-release-artifacts.ps1",
    "scripts/release/create-signed-tag.ps1",
)

FUZZ_ENV = (
    "HYDRA_FUZZ_MODE",
    "HYDRA_COVERAGE_FUZZ_RUNS",
    "HYDRA_STATEFUL_FUZZ_RUNS",
    "HYDRA_COVERAGE_FUZZ_SECONDS",
    "HYDRA_STATEFUL_FUZZ_SECONDS",
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require_file(path: str) -> None:
    full = ROOT / path
    if not full.is_file() or full.stat().st_size == 0:
        fail(f"release-governance file missing or empty: {path}")


def require_text(path: str, needle: str) -> None:
    if needle not in text(path):
        fail(f"required text missing in {path}: {needle}")


def iter_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    if not root.exists():
        return []
    return [p for p in root.rglob("*") if p.is_file() and p.suffix in suffixes]


@contextmanager
def cleared_env(names: tuple[str, ...]):
    saved = {name: os.environ.get(name) for name in names}
    try:
        for name in names:
            os.environ.pop(name, None)
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def check_shared_runner_policy() -> None:
    from qa.ci.lib.run_all_cli import build_parser, fuzz_config

    with cleared_env(FUZZ_ENV):
        parser = build_parser()
        smoke = fuzz_config(parser.parse_args([]), parser)
        deep = fuzz_config(parser.parse_args(["--deep-fuzz"]), parser)
        overnight = fuzz_config(parser.parse_args(["--overnight"]), parser)

    if smoke != ("smoke", 256, 256, None, None):
        fail(f"shared run-all smoke fuzz defaults changed unexpectedly: {smoke}")
    if deep != ("deep", 100000, 1000, None, None):
        fail(f"shared run-all deep fuzz defaults changed unexpectedly: {deep}")
    if overnight != ("overnight", None, None, 900, 300):
        fail(f"shared run-all overnight fuzz defaults changed unexpectedly: {overnight}")

    require_text("qa/ci/check-all.sh", "qa/ci/run_all.py")
    require_text("qa/ci/check-all.ps1", '"qa\\ci\\run_all.py"')


def check_manifest_metadata() -> None:
    candidates = [ROOT / "Cargo.toml"]
    for pattern in (
        "crates/*/Cargo.toml",
        "examples/*/Cargo.toml",
        "qa/fuzz/*/Cargo.toml",
        "qa/tests/*/Cargo.toml",
        "qa/tools/vector-gen/Cargo.toml",
    ):
        candidates.extend(ROOT.glob(pattern))
    for manifest in candidates:
        if not manifest.is_file():
            continue
        body = manifest.read_text(encoding="utf-8")
        rel = manifest.relative_to(ROOT).as_posix()
        if not re.search(r"rust-version(?:\.workspace)?\s*=", body):
            fail(f"Cargo manifest missing rust-version metadata: {rel}")
        if not re.search(r"repository(?:\.workspace)?\s*=", body):
            fail(f"Cargo manifest missing repository metadata: {rel}")


def check_lock_integrity_policy() -> None:
    mutation_re = re.compile(r"rm -f Cargo\.lock|Remove-Item.*Cargo\.lock|cargo generate-lockfile")
    offenders: list[str] = []
    for path in iter_files(ROOT / "qa/ci", (".sh", ".ps1")):
        if path.name in {"check-release-governance.sh", "check-release-governance.ps1"}:
            continue
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if mutation_re.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{line_no}:{line}")
    for path in iter_files(ROOT / ".github/workflows", (".yml", ".yaml")):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if mutation_re.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{line_no}:{line}")
    if offenders:
        print("\n".join(offenders), file=sys.stderr)
        fail("CI must validate the committed Cargo.lock with --locked; workflows and local QA scripts must not rewrite it.")


def check_actions_pinned() -> None:
    use_re = re.compile(r"^\s*uses:\s+\S+@", re.MULTILINE)
    sha_re = re.compile(r"@[0-9a-fA-F]{40}(?:\s|#|$)")
    offenders: list[str] = []
    for path in iter_files(ROOT / ".github/workflows", (".yml", ".yaml")):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if use_re.match(line) and not sha_re.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{line_no}:{line}")
    if offenders:
        print("\n".join(offenders), file=sys.stderr)
        fail("GitHub Actions must be pinned to immutable 40-character commit SHAs")


def main() -> int:
    os.chdir(ROOT)
    for path in REQUIRED_FILES:
        require_file(path)

    check_manifest_metadata()
    check_shared_runner_policy()

    fixed_requirements = {
        "Cargo.toml": (
            'repository = "https://github.com/peavey2787/hydra-msg"',
            'rust-version = "1.88"',
            "check-cfg = ['cfg(fuzzing)']",
        ),
        "SECURITY.md": ("https://github.com/peavey2787/hydra-msg/security/advisories/new",),
        "docs/validation/release/release-artifacts.md": ("scripts/release/create-release-package.sh",),
        "docs/validation/release/release-signing.md": ("scripts/release/sign-release-artifacts.sh",),
        "docs/validation/release/sbom.md": ("scripts/release/generate-sbom.py",),
        "docs/validation/release/reproducible-builds.md": ("SOURCE_DATE_EPOCH",),
        "docs/validation/release/msrv-policy.md": ('rust-version = "1.88"',),
        ".github/workflows/ci.yml": (
            "push:", "pull_request:", "workflow_dispatch:", "Core bounded CI",
            "./qa/ci/core/check-tests.sh --skip-vectors --skip-release-static",
            "./qa/ci/core/check-examples.sh", "Browser lifecycle", 'HYDRA_RUN_BROWSER_E2E: "1"',
            "./qa/ci/reliability/check-browser-e2e.sh", "Deterministic fuzz regression",
            "./qa/ci/fuzz/check-fuzz.sh", 'HYDRA_CI_EPHEMERAL_LOCK_REFRESH: "1"', "cargo fetch",
            "target/ci-logs/core.log", "target/ci-logs/browser-lifecycle.log", "target/ci-logs/fuzz-regression.log",
            'tee -a "$log_file"', "GITHUB_STEP_SUMMARY",
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
            "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0",
        ),
        ".github/workflows/release-validation.yml": (
            "workflow_dispatch:", "./qa/ci/check-all.sh", "target/ci-logs/release-check-all.log",
            "Full sequential release check-all", "cargo install cargo-mutants --locked",
            "cargo install cargo-fuzz --locked", 'tee -a "$log_file"', "HYDRA_RELEASE_FUZZ_RUNS",
            "--deep-fuzz", "HYDRA_RELEASE_MUTATION_JOBS", "GITHUB_STEP_SUMMARY",
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
            "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0",
        ),
        ".github/dependabot.yml": ("package-ecosystem: github-actions",),
        "qa/ci/core/check-rust.sh": ("cargo metadata --locked",),
        "qa/ci/security/check-supply-chain.sh": ("cargo fetch --locked",),
        "qa/ci/fuzz/check-fuzz.sh": (
            "cargo run --locked -p hydra-fuzz-gate --", "HYDRA_RUN_COVERAGE_GUIDED_FUZZ",
            "message_stateful_flow", 'cargo fuzz build --fuzz-dir "$FUZZ_DIR"',
            'FAST_BUDGET="${HYDRA_COVERAGE_FUZZ_RUNS:-256}"',
            'FAST_BUDGET="${HYDRA_COVERAGE_FUZZ_RUNS:-100000}"',
        ),
        "qa/ci/fuzz/check-fuzz.ps1": ("cargo fuzz build --fuzz-dir $FuzzDir",),
        "qa/fuzz/cargo-fuzz/fuzz_targets/group_commit_message_parser.rs": ("encode_roster(GroupMode::Lite, &roster)",),
        "crates/hydra-msg/src/lib.rs": ("#[cfg(fuzzing)]",),
        "qa/fuzz/cargo-fuzz/Cargo.toml": ('hydra-msg = { version = "0.1.0", path = "../../../crates/hydra-msg" }',),
        "qa/fuzz/cargo-fuzz/fuzz_targets/message_codec.rs": ("fuzzing::decode_message_payload",),
        "qa/fuzz/cargo-fuzz/fuzz_targets/message_stateful_flow.rs": ("common::paired",),
    }
    for path, needles in fixed_requirements.items():
        for needle in needles:
            require_text(path, needle)

    if "fuzzing = []" in text("crates/hydra-msg/Cargo.toml"):
        fail("cargo-fuzz hooks must not be exposed as a hydra-msg Cargo feature")
    if 'features = ["fuzzing"]' in text("qa/fuzz/cargo-fuzz/Cargo.toml"):
        fail("cargo-fuzz must use --cfg fuzzing, not a public hydra-msg feature")
    if "#[doc(hidden)]" in text("crates/hydra-msg/src/lib.rs"):
        fail("hydra-msg fuzz support must not create doc-hidden facade APIs")
    if re.search(r"common::(paired|fresh|temp_case_dir)|import_messages", text("qa/fuzz/cargo-fuzz/fuzz_targets/message_codec.rs")):
        fail("fast message_codec fuzz target must remain in-memory and stateless")

    for path in iter_files(ROOT / ".github/workflows", (".yml", ".yaml")):
        if "${{ runner.temp }}/hydra-ci-logs" in path.read_text(encoding="utf-8"):
            fail("GitHub artifact logs must stay under github.workspace, not runner.temp")

    check_lock_integrity_policy()
    check_actions_pinned()

    stale_re = re.compile(
        r"example\.invalid|fake security email|Production release blocker until verified|"
        r"must be verified before production release|public production release remains blocked until.*private reporting|"
        r"GitHub Private Vulnerability Reporting availability is unverified"
    )
    doc_roots = [ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "docs", ROOT / "CHANGELOG.md"]
    for root in doc_roots:
        paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.exists() else []
        for path in paths:
            try:
                body = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if stale_re.search(body):
                fail("stale release-governance blocker or placeholder wording found")

    project_docs = ROOT / "docs/project"
    if project_docs.exists() and any(p.is_file() for p in project_docs.rglob("*")):
        fail("long-lived docs still present under docs/project")

    print("release governance checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
