#!/usr/bin/env python3
"""Cross-platform HYDRA documentation/path/stale-term policy.

All text reads use Python universal-newline handling so CRLF/LF differences cannot
change policy results between Windows and Linux.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

REQUIRED_PATHS = (
    "docs/spec",
    "docs/impl",
    "docs/validation",
    "docs/validation/benchmarks",
    "docs/validation/evidence",
    "docs/validation/gates",
    "docs/validation/release",
    "qa/ci",
    "qa/fixtures/interop",
    "qa/tests",
    "qa/tools/vector-gen",
    "qa/vectors/candidate",
    "qa/vectors/cross-version",
)

MAIN_REQUIRED = (
    "Main README",
    "How HYDRA messaging works",
    "Spec docs and repo structure",
    "Crates",
    "Examples",
    "Public developer API",
    "Benchmark notes",
)
MAIN_FORBIDDEN = (
    "Roadmap",
    "Spec document index",
    "Protocol spec",
    "Threat model",
    "Security proof sketch",
    "State machines",
    "Envelope serialization",
    "Chain-key evolution",
    "TreeKEM profile",
    "Group modes",
    "Group rekey",
    "Anonymous authorization",
)
SPEC_REQUIRED = (
    "Main README",
    "Spec document index",
    "Protocol spec",
    "Threat model",
    "Security proof sketch",
    "State machines",
    "Envelope serialization",
    "Chain-key evolution",
    "TreeKEM profile",
    "Group modes",
    "Group rekey",
    "Anonymous authorization",
)
SPEC_FORBIDDEN = (
    "How HYDRA messaging works",
    "Spec docs and repo structure",
    "Crates",
    "Examples",
    "Public developer API",
    "Benchmark notes",
    "Carrier examples",
    "Production QA gate",
    "Roadmap",
)
VALIDATION_REQUIRED = (
    "Main README",
    "Validation index",
    "Spec document index",
    "Threat model",
)
VALIDATION_FORBIDDEN = (
    "How HYDRA messaging works",
    "Spec docs and repo structure",
    "Crates",
    "Examples",
    "Public developer API",
    "Benchmark notes",
    "Roadmap",
)

EXCLUDED_PARTS = {".git", "target", "node_modules", "test-results", "playwright-report"}


def fail(message: str) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def rel(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def is_excluded(path: Path) -> bool:
    relative = path.relative_to(REPO)
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return True
    parts = relative.parts
    if len(parts) >= 4 and parts[0] == "examples" and "web" in parts and "pkg" in parts:
        return True
    return False


def read_text(path: Path) -> str:
    # newline=None is the default and normalizes CRLF/CR/LF to \n.
    return path.read_text(encoding="utf-8", errors="strict")


def navigation_block(path: Path) -> str:
    lines = read_text(path).splitlines()
    try:
        start = lines.index("## Navigation")
    except ValueError:
        fail(f"Markdown doc missing Navigation section: {rel(path)}")
    out = [lines[start]]
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        out.append(line)
    return "\n".join(out)


def require_labels(path: Path, nav: str, labels: tuple[str, ...]) -> None:
    for label in labels:
        if f"[{label}]" not in nav:
            fail(f"navigation missing {label}: {rel(path)}")


def forbid_labels(path: Path, nav: str, labels: tuple[str, ...]) -> None:
    for label in labels:
        if f"[{label}]" in nav:
            fail(f"navigation has wrong nav-family entry {label}: {rel(path)}")


def is_main_nav_doc(relative: str) -> bool:
    if relative.startswith("crates/") or relative.startswith("examples/"):
        return True
    return relative in {
        "docs/impl/message-flow/README.md",
        "docs/impl/carrier-examples.md",
        "docs/impl/hydra-msg-cli.md",
        "docs/impl/wasm-javascript-bindings.md",
        "docs/spec/public-developer-api.md",
        "docs/validation/benchmarks/benchmark-results.md",
    }


def validate_navigation() -> None:
    root_readme = REPO / "README.md"
    root_nav = navigation_block(root_readme)
    # Root README is public/project navigation and intentionally omits "Main README".
    require_labels(root_readme, root_nav, MAIN_REQUIRED[1:])
    forbid_labels(root_readme, root_nav, MAIN_FORBIDDEN)

    for readme in REPO.rglob("README.md"):
        if readme == root_readme or is_excluded(readme):
            continue
        if "Main README" not in read_text(readme):
            fail(f"README missing Main README navigation: {rel(readme)}")

    docs: list[Path] = []
    for root in ("crates", "examples", "docs/spec", "docs/impl", "docs/validation"):
        for path in (REPO / root).rglob("*.md"):
            if path.is_file() and not is_excluded(path):
                docs.append(path)

    for path in sorted(docs, key=rel):
        nav = navigation_block(path)
        relative = rel(path)
        if is_main_nav_doc(relative):
            require_labels(path, nav, MAIN_REQUIRED)
            forbid_labels(path, nav, MAIN_FORBIDDEN)
        elif relative.startswith("docs/validation/"):
            require_labels(path, nav, VALIDATION_REQUIRED)
            forbid_labels(path, nav, VALIDATION_FORBIDDEN)
        else:
            require_labels(path, nav, SPEC_REQUIRED)
            forbid_labels(path, nav, SPEC_FORBIDDEN)


def iter_text_files(roots: tuple[str, ...]):
    seen: set[Path] = set()
    for root in roots:
        base = REPO / root
        candidates = [base] if base.is_file() else base.rglob("*") if base.exists() else []
        for path in candidates:
            if not path.is_file() or is_excluded(path) or path in seen:
                continue
            seen.add(path)
            try:
                raw = path.read_bytes()
                if b"\x00" in raw:
                    continue
                text = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            yield path, text


def assert_no_pattern(description: str, roots: tuple[str, ...], pattern: str, *, flags: int = 0) -> None:
    regex = re.compile(pattern, flags)
    hits: list[str] = []
    for path, text in iter_text_files(roots):
        for line_no, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                hits.append(f"{rel(path)}:{line_no}:{line}")
    if hits:
        print("\n".join(hits), file=sys.stderr)
        fail(description)


def validate_paths_and_stale_terms() -> None:
    for relative in REQUIRED_PATHS:
        if not (REPO / relative).exists():
            fail(f"required path missing: {relative}")

    for path in (REPO / "docs").iterdir():
        if path.is_file():
            fail(f"unexpected top-level docs file: {rel(path)}")

    project = REPO / "docs/project"
    if project.is_dir() and any(p.is_file() for p in project.rglob("*")):
        fail("persistent file found under docs/project; move release evidence to docs/validation/evidence")

    if (REPO / "qa/evidence").exists():
        fail("qa/evidence must not exist; move long-lived documentation to docs/validation/evidence")

    assert_no_pattern(
        "blocked simple-API wording found",
        ("README.md", "crates", "examples", "docs", "Cargo.toml"),
        r"stupid[- ]simple",
        flags=re.IGNORECASE,
    )
    assert_no_pattern("docs/planning reference found", ("docs", "crates", "README.md", "Cargo.toml"), r"docs/planning", flags=re.IGNORECASE)
    assert_no_pattern(
        "long-lived product or validation reference points into docs/project",
        ("docs", "crates", "examples", "README.md", "Cargo.toml"),
        r"docs/project/",
        flags=re.IGNORECASE,
    )
    assert_no_pattern("crate name reference found", ("docs", "crates", "README.md", "Cargo.toml"), r"hydra-types|hydra-wire", flags=re.IGNORECASE)
    assert_no_pattern(
        "primitive terminology found",
        ("docs/spec", "docs/impl", "docs/validation", "crates"),
        r"Kyber|Dilithium|XChaCha20",
    )
    assert_no_pattern("source TODO/unimplemented marker found", ("crates",), r"todo!|unimplemented!|TODO|FIXME")

    for path in (REPO / "qa/ci").rglob("*"):
        if path.is_file() and path.suffix in {".sh", ".ps1"} and path.stat().st_size == 0:
            fail(f"empty QA script found: {rel(path)}")


def main() -> None:
    validate_paths_and_stale_terms()
    validate_navigation()
    print("shared docs/path/stale-term checks passed")


if __name__ == "__main__":
    main()
